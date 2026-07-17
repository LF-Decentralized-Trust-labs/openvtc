//! `verify-trust`: verify a git commit range against the VTC Trust Registry.
//!
//! For every commit in a range this module answers two questions, in order:
//!
//! 1. **Who signed it, cryptographically?** The commit's `gpgsig` header is
//!    parsed as a PROTOCOL.sshsig blob; the Ed25519 public key embedded in it
//!    is matched against the keys published in the DID documents of the
//!    repository's declared signers, and the signature is verified over the
//!    exact bytes git signed.
//! 2. **Is that DID trusted, right now?** The signer DID is checked against
//!    the Trust Registry with a TRQP authorization query
//!    (`{entity: signer, authority, action, resource}`) via `trql-client`.
//!
//! The signer set comes from a committed index file (default `.did-signers`,
//! one DID per line) that lists *identities, not keys* — keys are resolved
//! from each DID document at verification time, so key rotation never
//! requires touching the repository, and revoking a signer is a registry
//! operation that takes effect on the next run.
//!
//! Failure is closed at every layer: an unsigned commit, a signature by an
//! unpublished key, a cryptographically invalid signature, an unauthorized
//! DID, and an unreachable registry all fail the check — each with its own
//! status so an operator can tell which remediation applies.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use ssh_key::{SshSig, public::KeyData};
use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqlError, TrqpQuery};

use crate::pgp_exempt::ExemptKeyring;

/// The sshsig namespace git uses for commit and tag signatures.
pub const GIT_SSHSIG_NAMESPACE: &str = "git";

/// Multicodec prefix for an Ed25519 public key in `publicKeyMultibase`.
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xED, 0x01];

/// Everything `verify-trust` needs for one run.
#[derive(Debug, Clone)]
pub struct VerifyTrustArgs {
    /// Repository to verify (a working tree with `git` available).
    pub repo_dir: PathBuf,
    /// Commit range in `git rev-list` syntax, e.g. `origin/main..HEAD`.
    pub range: String,
    /// Signer index file; relative paths resolve against `repo_dir`.
    pub signers_file: PathBuf,
    /// Base URL of the Trust Registry (`POST <url>/trust-tasks`).
    pub registry_url: String,
    /// DID of the registry (the `recipient` on every query document).
    pub registry_did: String,
    /// DID of the authority the tuple is evaluated under.
    pub authority_did: String,
    /// TRQP action, e.g. `git.commit.sign`.
    pub action: String,
    /// TRQP resource, e.g. the `org/repo` slug.
    pub resource: String,
    /// Broader resource to try when the primary one does not authorize
    /// (e.g. the org for an org-wide grant). Grant semantics are
    /// `resource OR fallback`: the registry's wire contract cannot
    /// distinguish "no record" from an explicit `authorized: false`, so a
    /// repo-level record cannot veto an org-level grant.
    pub fallback_resource: Option<String>,
    /// Optional armored PGP keyring of exempt platform keys (e.g. GitHub's
    /// web-flow key); relative paths resolve against `repo_dir`. Absent means
    /// no exemptions: every PGP-signed commit fails.
    pub exempt_keyring: Option<PathBuf>,
    /// Emit machine-readable JSON on stdout instead of human lines.
    pub json: bool,
}

/// Outcome for one commit. Ordered worst-first so a report can sort on it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "detail")]
pub enum CommitStatus {
    /// No `gpgsig` header on the commit.
    Unsigned,
    /// The signature did not parse as an Ed25519 sshsig.
    Malformed(String),
    /// The embedded key is published by none of the declared signers.
    UnknownKey { fingerprint: String },
    /// The key maps to a signer, but the signature does not verify.
    BadSignature { signer_did: String },
    /// Valid signature, but the registry did not authorize the signer.
    Unauthorized { signer_did: String },
    /// Valid signature, but the registry could not be consulted. Fails the
    /// run (closed), distinctly from a denial.
    RegistryUnavailable { signer_did: String, error: String },
    /// PGP-signed (a platform commit), but the signature verifies against no
    /// key in the exempt keyring — or no keyring is configured.
    PgpRejected { detail: String },
    /// PGP-signed by a key in the committed exempt keyring (e.g. a GitHub
    /// web-UI merge commit). Passes, reported distinctly from `Trusted`.
    Exempt { fingerprint: String },
    /// Valid signature by a registry-authorized signer. `resource` is the
    /// tuple resource the grant was found under (the primary one or the
    /// fallback).
    Trusted {
        signer_did: String,
        resource: String,
    },
}

impl CommitStatus {
    /// Signed by a registry-authorized DID.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted { .. })
    }

    /// Whether the commit passes the check: DID-trusted or keyring-exempt.
    pub fn passes(&self) -> bool {
        matches!(self, Self::Trusted { .. } | Self::Exempt { .. })
    }
}

/// One commit's verdict, as reported.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitVerdict {
    pub sha: String,
    #[serde(flatten)]
    pub status: CommitStatus,
}

/// The full report for a range.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustReport {
    pub ok: bool,
    pub commits: Vec<CommitVerdict>,
    /// Signer DIDs whose resolution failed (their commits show as
    /// `unknownKey`); surfaced so the cause is visible.
    pub unresolved_signers: BTreeMap<String, String>,
}

/// Run the check end to end: resolve the declared signers' keys, then verify
/// the range. Returns the process exit code (0 = every commit trusted).
pub async fn handle_verify_trust(args: VerifyTrustArgs) -> Result<i32> {
    let signer_dids = load_signers(&args.repo_dir, &args.signers_file)?;
    let exempt = load_exempt_keyring(&args)?;
    let (keys, unresolved) = resolve_signer_keys(&signer_dids).await?;
    let report = verify_with_keys(&args, &keys, exempt.as_ref(), unresolved).await?;
    print_report(&args, &report)?;
    Ok(if report.ok { 0 } else { 1 })
}

/// Verify the range against an already-resolved key→DID map. Split from
/// [`handle_verify_trust`] so tests can supply keys without a live resolver.
pub async fn verify_with_keys(
    args: &VerifyTrustArgs,
    signer_keys: &HashMap<[u8; 32], String>,
    exempt: Option<&ExemptKeyring>,
    unresolved_signers: BTreeMap<String, String>,
) -> Result<TrustReport> {
    let shas = list_commits(&args.repo_dir, &args.range)?;

    // Pass 1: cryptographic verification, collecting the DIDs that signed.
    let mut checked = Vec::with_capacity(shas.len());
    let mut signer_dids = BTreeSet::new();
    for sha in shas {
        let raw = read_commit_raw(&args.repo_dir, &sha)?;
        let signature = check_commit_signature(&raw, signer_keys, exempt);
        if let SignatureCheck::Valid { signer_did } = &signature {
            signer_dids.insert(signer_did.clone());
        }
        checked.push((sha, signature));
    }

    // Pass 2: one registry query per distinct signer DID.
    let decisions = query_registry(args, &signer_dids).await?;

    let commits: Vec<CommitVerdict> = checked
        .into_iter()
        .map(|(sha, signature)| CommitVerdict {
            sha,
            status: status_of(signature, &decisions),
        })
        .collect();

    // An empty range passes vacuously (nothing new to verify).
    let ok = commits.iter().all(|c| c.status.passes());
    Ok(TrustReport {
        ok,
        commits,
        unresolved_signers,
    })
}

// --- signature layer ---------------------------------------------------------

/// Result of the cryptographic check for one commit.
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureCheck {
    Unsigned,
    Malformed(String),
    UnknownKey { fingerprint: String },
    BadSignature { signer_did: String },
    PgpRejected { detail: String },
    Exempt { fingerprint: String },
    Valid { signer_did: String },
}

/// Verify one raw commit object against the signer key map.
pub fn check_commit_signature(
    raw: &[u8],
    signer_keys: &HashMap<[u8; 32], String>,
    exempt: Option<&ExemptKeyring>,
) -> SignatureCheck {
    let (payload, pem) = match split_signed_commit(raw) {
        Ok(Some(parts)) => parts,
        Ok(None) => return SignatureCheck::Unsigned,
        Err(e) => return SignatureCheck::Malformed(e.to_string()),
    };
    // Platform commits (GitHub web-UI merges, Dependabot) are PGP-signed;
    // they pass only via the explicitly committed exempt keyring.
    if pem.starts_with("-----BEGIN PGP SIGNATURE-----") {
        let Some(keyring) = exempt else {
            return SignatureCheck::PgpRejected {
                detail: "PGP-signed commit, but no exempt keyring is configured".to_string(),
            };
        };
        return match keyring.verify(&pem, &payload) {
            Ok(fingerprint) => SignatureCheck::Exempt { fingerprint },
            Err(detail) => SignatureCheck::PgpRejected { detail },
        };
    }
    let sig = match SshSig::from_pem(normalize_sshsig_armor(&pem).as_bytes()) {
        Ok(sig) => sig,
        Err(e) => return SignatureCheck::Malformed(format!("sshsig did not parse: {e}")),
    };
    let KeyData::Ed25519(embedded) = sig.public_key() else {
        return SignatureCheck::Malformed(format!(
            "unsupported signature algorithm: {}",
            sig.algorithm()
        ));
    };
    let key_bytes: [u8; 32] = embedded.0;
    let Some(signer_did) = signer_keys.get(&key_bytes) else {
        return SignatureCheck::UnknownKey {
            fingerprint: hex::encode(key_bytes),
        };
    };
    let public_key = ssh_key::PublicKey::from(sig.public_key().clone());
    match public_key.verify(GIT_SSHSIG_NAMESPACE, &payload, &sig) {
        Ok(()) => SignatureCheck::Valid {
            signer_did: signer_did.clone(),
        },
        Err(_) => SignatureCheck::BadSignature {
            signer_did: signer_did.clone(),
        },
    }
}

/// Re-wrap an sshsig armor's base64 body at 70 columns.
///
/// OpenSSH's own base64 reader accepts any line width, but the strict PEM
/// parser underneath [`SshSig::from_pem`] requires exactly the 70-column
/// wrapping ssh-keygen emits. Signatures created by did-git-sign before it
/// matched ssh-keygen's width (76 columns) live on in git history, so the
/// armor is normalized rather than trusted to be canonical.
pub fn normalize_sshsig_armor(pem: &str) -> String {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let mut normalized = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in body.as_bytes().chunks(70) {
        // Chunks of an ASCII base64 string are always valid UTF-8.
        normalized.push_str(&String::from_utf8_lossy(chunk));
        normalized.push('\n');
    }
    normalized.push_str("-----END SSH SIGNATURE-----\n");
    normalized
}

/// Split a raw commit object into (payload-as-signed, armored signature).
///
/// Git signs the commit object with the `gpgsig` header removed; the header's
/// value spans continuation lines (each prefixed with one space). Returns
/// `Ok(None)` for an unsigned commit.
pub fn split_signed_commit(raw: &[u8]) -> Result<Option<(Vec<u8>, String)>> {
    let text = std::str::from_utf8(raw).context("commit object is not UTF-8")?;
    let Some((headers, body)) = text.split_once("\n\n") else {
        bail!("malformed commit object: no header/body separator");
    };

    let mut kept_headers: Vec<&str> = Vec::new();
    let mut signature_lines: Vec<&str> = Vec::new();
    let mut in_gpgsig = false;
    for line in headers.split('\n') {
        if let Some(first) = line.strip_prefix("gpgsig ") {
            in_gpgsig = true;
            signature_lines.push(first);
        } else if in_gpgsig && let Some(continuation) = line.strip_prefix(' ') {
            signature_lines.push(continuation);
        } else {
            in_gpgsig = false;
            kept_headers.push(line);
        }
    }

    if signature_lines.is_empty() {
        return Ok(None);
    }

    let mut payload = kept_headers.join("\n").into_bytes();
    payload.extend_from_slice(b"\n\n");
    payload.extend_from_slice(body.as_bytes());

    let mut pem = signature_lines.join("\n");
    pem.push('\n');
    Ok(Some((payload, pem)))
}

/// Load the exempt keyring named by the args, resolving relative to the repo.
fn load_exempt_keyring(args: &VerifyTrustArgs) -> Result<Option<ExemptKeyring>> {
    let Some(path) = &args.exempt_keyring else {
        return Ok(None);
    };
    let path = if path.is_absolute() {
        path.clone()
    } else {
        args.repo_dir.join(path)
    };
    Ok(Some(ExemptKeyring::load(&path)?))
}

// --- signer index & DID resolution -------------------------------------------

/// Read and parse the signer index: one DID per line, `#` comments allowed.
/// A missing or malformed file is a hard error — with no declared signers
/// there is nothing to verify against, and the check must not silently pass.
pub fn load_signers(repo_dir: &Path, signers_file: &Path) -> Result<Vec<String>> {
    let path = if signers_file.is_absolute() {
        signers_file.to_path_buf()
    } else {
        repo_dir.join(signers_file)
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read signer index {}", path.display()))?;
    let dids = parse_signers(&text)?;
    if dids.is_empty() {
        bail!("signer index {} declares no DIDs", path.display());
    }
    Ok(dids)
}

/// Parse signer-index text. Rejects non-DID entries outright rather than
/// skipping them: a typo must fail loudly, not silently drop a signer.
pub fn parse_signers(text: &str) -> Result<Vec<String>> {
    let mut dids = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        if !entry.starts_with("did:") {
            bail!("signer index line {}: not a DID: {entry}", number + 1);
        }
        dids.push(entry.to_string());
    }
    Ok(dids)
}

/// Resolve every declared signer DID and collect the Ed25519 keys their DID
/// documents publish. A DID that fails to resolve is recorded (its commits
/// will fail as `unknownKey`) without blocking the other signers.
pub async fn resolve_signer_keys(
    dids: &[String],
) -> Result<(HashMap<[u8; 32], String>, BTreeMap<String, String>)> {
    use affinidi_tdk::TDK;
    use affinidi_tdk::common::config::TDKConfig;

    let tdk = TDK::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .context("TDK config")?,
        None,
    )
    .await
    .context("TDK init")?;

    let mut keys = HashMap::new();
    let mut unresolved = BTreeMap::new();
    for did in dids {
        match tdk.did_resolver().resolve(did).await {
            Ok(response) => {
                let doc = serde_json::to_value(&response.doc)
                    .with_context(|| format!("DID document for {did} did not serialize"))?;
                let published = ed25519_keys_from_doc(&doc);
                if published.is_empty() {
                    unresolved.insert(
                        did.clone(),
                        "DID document publishes no Ed25519 verification keys".to_string(),
                    );
                }
                for key in published {
                    keys.insert(key, did.clone());
                }
            }
            Err(e) => {
                unresolved.insert(did.clone(), format!("resolution failed: {e}"));
            }
        }
    }
    Ok((keys, unresolved))
}

/// Extract every Ed25519 public key from a DID document's verification
/// methods (`publicKeyMultibase`, multicodec `0xED01`).
pub fn ed25519_keys_from_doc(doc: &serde_json::Value) -> Vec<[u8; 32]> {
    let Some(methods) = doc.get("verificationMethod").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    methods
        .iter()
        .filter_map(|method| method.get("publicKeyMultibase")?.as_str())
        .filter_map(|encoded| multibase::decode(encoded).ok())
        .filter_map(|(_base, bytes)| {
            let raw = bytes.strip_prefix(&ED25519_MULTICODEC_PREFIX)?;
            <[u8; 32]>::try_from(raw).ok()
        })
        .collect()
}

// --- registry layer -----------------------------------------------------------

/// Per-DID registry decision: `Ok(Some(resource))` = authorized under that
/// tuple resource, `Ok(None)` = denied everywhere queried, `Err` =
/// registry unavailable.
type RegistryDecisions = BTreeMap<String, Result<Option<String>, String>>;

/// One TRQP authorization query per distinct signer DID.
async fn query_registry(
    args: &VerifyTrustArgs,
    signer_dids: &BTreeSet<String>,
) -> Result<RegistryDecisions> {
    let mut decisions = RegistryDecisions::new();
    if signer_dids.is_empty() {
        return Ok(decisions);
    }
    let transport = HttpsTransport::new(HttpsTransportConfig::new(&args.registry_url))?;
    let client = TrqlClient::new(Arc::new(transport), &args.registry_did);
    // The primary resource, then the broader fallback if it did not grant.
    let mut resources = vec![args.resource.clone()];
    if let Some(fallback) = &args.fallback_resource
        && fallback != &args.resource
    {
        resources.push(fallback.clone());
    }
    for did in signer_dids {
        let mut decision: Result<Option<String>, String> = Ok(None);
        for resource in &resources {
            let query = TrqpQuery::new(did, &args.authority_did, &args.action, resource);
            match client.authorization(query).await {
                Ok(response) if response.authorized => {
                    decision = Ok(Some(resource.clone()));
                    break;
                }
                Ok(_) => {}
                Err(e @ TrqlError::Rejected { .. }) => {
                    // The registry answered and said no (e.g. unknown tuple
                    // rejected rather than answered false) — a denial, not
                    // an availability problem; the fallback may still grant.
                    tracing::debug!("registry rejected the query for {did}: {e}");
                }
                Err(e) => {
                    // Fail closed: with any scope undeterminable, "denied"
                    // cannot be distinguished from "unreachable".
                    decision = Err(e.to_string());
                    break;
                }
            }
        }
        decisions.insert(did.clone(), decision);
    }
    Ok(decisions)
}

/// Combine the signature check with the registry decision.
fn status_of(signature: SignatureCheck, decisions: &RegistryDecisions) -> CommitStatus {
    match signature {
        SignatureCheck::Unsigned => CommitStatus::Unsigned,
        SignatureCheck::Malformed(detail) => CommitStatus::Malformed(detail),
        SignatureCheck::UnknownKey { fingerprint } => CommitStatus::UnknownKey { fingerprint },
        SignatureCheck::BadSignature { signer_did } => CommitStatus::BadSignature { signer_did },
        SignatureCheck::PgpRejected { detail } => CommitStatus::PgpRejected { detail },
        SignatureCheck::Exempt { fingerprint } => CommitStatus::Exempt { fingerprint },
        SignatureCheck::Valid { signer_did } => match decisions.get(&signer_did) {
            Some(Ok(Some(resource))) => CommitStatus::Trusted {
                signer_did,
                resource: resource.clone(),
            },
            Some(Ok(None)) => CommitStatus::Unauthorized { signer_did },
            Some(Err(error)) => CommitStatus::RegistryUnavailable {
                signer_did,
                error: error.clone(),
            },
            None => CommitStatus::RegistryUnavailable {
                signer_did,
                error: "no registry decision recorded".to_string(),
            },
        },
    }
}

// --- git plumbing --------------------------------------------------------------

/// List the commits in `range`, oldest first.
pub fn list_commits(repo_dir: &Path, range: &str) -> Result<Vec<String>> {
    let output = git(repo_dir, &["rev-list", "--reverse", range])?;
    Ok(output.lines().map(str::to_string).collect())
}

/// Read one raw commit object.
pub fn read_commit_raw(repo_dir: &Path, sha: &str) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["cat-file", "commit", sha])
        .output()
        .context("running git cat-file")?;
    if !output.status.success() {
        bail!(
            "git cat-file commit {sha} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn git(repo_dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim_end().to_string())
}

// --- reporting ------------------------------------------------------------------

fn print_report(args: &VerifyTrustArgs, report: &TrustReport) -> Result<()> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    for commit in &report.commits {
        let short = &commit.sha[..commit.sha.len().min(12)];
        match &commit.status {
            CommitStatus::Trusted {
                signer_did,
                resource,
            } => {
                println!("TRUSTED      {short}  {signer_did} (via {resource})");
            }
            CommitStatus::Exempt { fingerprint } => {
                println!("EXEMPT       {short}  PGP-signed by exempt platform key {fingerprint}");
            }
            CommitStatus::PgpRejected { detail } => {
                println!("PGP-REJECTED {short}  {detail}");
            }
            CommitStatus::Unauthorized { signer_did } => {
                println!("UNAUTHORIZED {short}  {signer_did} is not authorized by the registry");
            }
            CommitStatus::RegistryUnavailable { signer_did, error } => {
                println!(
                    "UNAVAILABLE  {short}  signed by {signer_did}; registry check failed: {error}"
                );
            }
            CommitStatus::BadSignature { signer_did } => {
                println!("BAD-SIG      {short}  signature by {signer_did} does not verify");
            }
            CommitStatus::UnknownKey { fingerprint } => {
                println!(
                    "UNKNOWN-KEY  {short}  key {fingerprint} is published by no declared signer"
                );
            }
            CommitStatus::Malformed(detail) => {
                println!("MALFORMED    {short}  {detail}");
            }
            CommitStatus::Unsigned => {
                println!("UNSIGNED     {short}  commit carries no signature");
            }
        }
    }
    for (did, reason) in &report.unresolved_signers {
        println!("WARNING      declared signer {did}: {reason}");
    }
    let passing = report.commits.iter().filter(|c| c.status.passes()).count();
    println!(
        "{}: {passing}/{} commits pass",
        if report.ok { "PASS" } else { "FAIL" },
        report.commits.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sign::create_ssh_signature;
    use ed25519_dalek::SigningKey;

    fn test_key() -> (SigningKey, [u8; 32]) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    fn unsigned_commit() -> String {
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
         author A U Thor <a@example.com> 1700000000 +0000\n\
         committer A U Thor <a@example.com> 1700000000 +0000\n\
         \n\
         a message\n"
            .to_string()
    }

    /// Insert a gpgsig header before the blank line, continuation-indented,
    /// exactly as git stores it.
    fn signed_commit(payload: &str, armored: &str) -> String {
        let (headers, body) = payload.split_once("\n\n").unwrap();
        let mut sig_header = String::from("gpgsig ");
        let mut lines = armored.trim_end().split('\n');
        sig_header.push_str(lines.next().unwrap());
        for line in lines {
            sig_header.push('\n');
            sig_header.push(' ');
            sig_header.push_str(line);
        }
        format!("{headers}\n{sig_header}\n\n{body}")
    }

    fn sign_commit(payload: &str, key: &SigningKey) -> String {
        let armored = create_ssh_signature(
            key,
            &key.verifying_key(),
            GIT_SSHSIG_NAMESPACE,
            payload.as_bytes(),
        )
        .unwrap();
        signed_commit(payload, &armored)
    }

    #[test]
    fn split_returns_none_for_unsigned_commit() {
        assert!(
            split_signed_commit(unsigned_commit().as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn split_recovers_exact_payload_and_signature() {
        let payload = unsigned_commit();
        let (key, _) = test_key();
        let commit = sign_commit(&payload, &key);

        let (recovered_payload, pem) = split_signed_commit(commit.as_bytes()).unwrap().unwrap();
        assert_eq!(recovered_payload, payload.as_bytes());
        assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(pem.trim_end().ends_with("-----END SSH SIGNATURE-----"));
    }

    #[test]
    fn our_encoder_and_the_decoder_agree() {
        // Cross-check: a signature produced by sign.rs verifies through the
        // ssh-key crate's independent implementation.
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key);
        let keys = HashMap::from([(public, "did:example:signer".to_string())]);

        let check = check_commit_signature(commit.as_bytes(), &keys, None);
        assert_eq!(
            check,
            SignatureCheck::Valid {
                signer_did: "did:example:signer".to_string()
            }
        );
    }

    #[test]
    fn legacy_76_column_armor_still_verifies() {
        // Signatures created before sign.rs matched ssh-keygen's 70-column
        // wrapping are permanent in git history and must keep verifying.
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let armored = create_ssh_signature(
            &key,
            &key.verifying_key(),
            GIT_SSHSIG_NAMESPACE,
            payload.as_bytes(),
        )
        .unwrap();
        let body: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let mut legacy = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for chunk in body.as_bytes().chunks(76) {
            legacy.push_str(std::str::from_utf8(chunk).unwrap());
            legacy.push('\n');
        }
        legacy.push_str("-----END SSH SIGNATURE-----\n");

        let commit = signed_commit(&payload, &legacy);
        let keys = HashMap::from([(public, "did:example:signer".to_string())]);
        assert_eq!(
            check_commit_signature(commit.as_bytes(), &keys, None),
            SignatureCheck::Valid {
                signer_did: "did:example:signer".to_string()
            }
        );
    }

    #[test]
    fn unknown_key_is_reported_with_fingerprint() {
        let payload = unsigned_commit();
        let (key, _) = test_key();
        let commit = sign_commit(&payload, &key);

        let check = check_commit_signature(commit.as_bytes(), &HashMap::new(), None);
        assert!(matches!(check, SignatureCheck::UnknownKey { .. }));
    }

    #[test]
    fn tampered_payload_is_a_bad_signature() {
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key).replace("a message", "b message");
        let keys = HashMap::from([(public, "did:example:signer".to_string())]);

        let check = check_commit_signature(commit.as_bytes(), &keys, None);
        assert_eq!(
            check,
            SignatureCheck::BadSignature {
                signer_did: "did:example:signer".to_string()
            }
        );
    }

    #[test]
    fn unsigned_commit_is_unsigned() {
        let check = check_commit_signature(unsigned_commit().as_bytes(), &HashMap::new(), None);
        assert_eq!(check, SignatureCheck::Unsigned);
    }

    #[test]
    fn signers_index_parses_and_rejects_non_dids() {
        let parsed =
            parse_signers("# team\n did:webvh:abc:example.com \n\ndid:webvh:def:example.com\n")
                .unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parse_signers("not-a-did\n").is_err());
    }

    #[test]
    fn ed25519_keys_are_extracted_from_a_did_document() {
        let (_, public) = test_key();
        let mut multicodec = ED25519_MULTICODEC_PREFIX.to_vec();
        multicodec.extend_from_slice(&public);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &multicodec);

        let doc = serde_json::json!({
            "id": "did:example:signer",
            "verificationMethod": [
                { "id": "did:example:signer#key-0", "publicKeyMultibase": encoded },
                { "id": "did:example:signer#key-x", "publicKeyMultibase": "zInvalid!" },
                { "id": "did:example:signer#key-jwk" }
            ]
        });
        let keys = ed25519_keys_from_doc(&doc);
        assert_eq!(keys, vec![public]);
    }

    #[test]
    fn statuses_compose_signature_and_registry_decisions() {
        let did = "did:example:signer".to_string();
        let mut decisions = RegistryDecisions::new();
        decisions.insert(did.clone(), Ok(Some("example/repo".to_string())));
        assert!(
            status_of(
                SignatureCheck::Valid {
                    signer_did: did.clone()
                },
                &decisions
            )
            .is_trusted()
        );

        decisions.insert(did.clone(), Ok(None));
        assert_eq!(
            status_of(
                SignatureCheck::Valid {
                    signer_did: did.clone()
                },
                &decisions
            ),
            CommitStatus::Unauthorized {
                signer_did: did.clone()
            }
        );

        decisions.insert(did.clone(), Err("connect refused".to_string()));
        assert!(matches!(
            status_of(SignatureCheck::Valid { signer_did: did }, &decisions),
            CommitStatus::RegistryUnavailable { .. }
        ));
    }
}
