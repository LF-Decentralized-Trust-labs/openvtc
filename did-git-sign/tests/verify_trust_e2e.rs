//! End-to-end `verify-trust` test: a real git repository containing a real
//! sshsig-signed commit object, verified against a stub Trust Registry
//! speaking the `POST /trust-tasks` wire contract.
//!
//! Requires the `git` binary (present on all CI runners).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::{Command, Stdio};

use did_git_sign::sign::create_ssh_signature;
use did_git_sign::verify_trust::{
    CommitStatus, GIT_SSHSIG_NAMESPACE, VerifyTrustArgs, verify_with_keys,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// --- git helpers -------------------------------------------------------------

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "A U Thor")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .env("GIT_COMMITTER_NAME", "A U Thor")
        .env("GIT_COMMITTER_EMAIL", "author@example.com")
        // Hermetic: the host's config may enable commit signing (this very
        // tool!), which would corrupt the fixtures.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string()
}

/// Rewrite `sha` as an sshsig-signed commit object and return the new sha.
fn sign_head_commit(repo: &Path, sha: &str, key: &SigningKey) -> String {
    let payload = {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "commit", sha])
            .output()
            .expect("git cat-file runs");
        assert!(out.status.success());
        out.stdout
    };
    let armored =
        create_ssh_signature(key, &key.verifying_key(), GIT_SSHSIG_NAMESPACE, &payload).unwrap();

    // Insert the gpgsig header before the blank line, continuation-indented
    // exactly as git stores it.
    let text = String::from_utf8(payload).unwrap();
    let (headers, body) = text.split_once("\n\n").unwrap();
    let mut sig_header = String::from("gpgsig ");
    let mut lines = armored.trim_end().split('\n');
    sig_header.push_str(lines.next().unwrap());
    for line in lines {
        sig_header.push_str("\n ");
        sig_header.push_str(line);
    }
    let signed = format!("{headers}\n{sig_header}\n\n{body}");

    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("git hash-object spawns");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(signed.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// Create a repo with one unsigned base commit, then one signed commit.
/// Returns (base_sha, signed_sha).
fn repo_with_signed_commit(repo: &Path, key: &SigningKey) -> (String, String) {
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base = git(repo, &["rev-parse", "HEAD"]);

    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "change"]);
    let unsigned = git(repo, &["rev-parse", "HEAD"]);

    let signed = sign_head_commit(repo, &unsigned, key);
    git(repo, &["update-ref", "refs/heads/main", &signed]);
    (base, signed)
}

// --- stub registry ------------------------------------------------------------

/// Serve the `/trust-tasks` contract: `authorized: true` exactly for the
/// given `(entity, resource)` grants.
async fn stub_registry_with(grants: Vec<(String, String)>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let grants = grants.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read headers.
                let header_end = loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length: usize = headers
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + content_length {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let request: Value = serde_json::from_slice(&buf[header_end..]).unwrap();
                let entity = request["payload"]["entity_id"].as_str().unwrap_or_default();
                let resource = request["payload"]["resource"].as_str().unwrap_or_default();
                let granted = grants.iter().any(|(e, r)| e == entity && r == resource);
                let response = json!({
                    "id": "urn:uuid:stub-reply",
                    "threadId": request["id"],
                    "type": "https://trusttasks.org/spec/registry/authorization/0.1#response",
                    "payload": {
                        "entity_id": entity,
                        "authority_id": request["payload"]["authority_id"],
                        "action": request["payload"]["action"],
                        "resource": request["payload"]["resource"],
                        "authorized": granted,
                        "time_evaluated": "2026-07-16T00:00:00Z",
                    }
                });
                let body = response.to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

/// Convenience: one repo-scoped grant for `authorized_did`.
async fn stub_registry(authorized_did: String) -> String {
    stub_registry_with(vec![(authorized_did, "example/repo".to_string())]).await
}

fn args_for(repo: &Path, range: String, registry_url: String) -> VerifyTrustArgs {
    VerifyTrustArgs {
        repo_dir: repo.to_path_buf(),
        range,
        signers_file: ".did-signers".into(),
        exempt_keyring: None,
        registry_url,
        registry_did: "did:example:registry".into(),
        authority_did: "did:example:authority".into(),
        action: "git.commit.sign".into(),
        resource: "example/repo".into(),
        fallback_resource: None,
        json: false,
    }
}

const SIGNER: &str = "did:example:signer";

// --- tests ---------------------------------------------------------------------

#[tokio::test]
async fn signed_and_authorized_commit_passes() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry(SIGNER.to_string()).await;

    let keys = HashMap::from([(key.verifying_key().to_bytes(), SIGNER.to_string())]);
    let args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    let report = verify_with_keys(&args, &keys, None, BTreeMap::new())
        .await
        .unwrap();

    assert_eq!(report.commits.len(), 1);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "example/repo".to_string()
        }
    );
    assert!(report.ok);
}

#[tokio::test]
async fn signed_but_unauthorized_commit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    // The registry authorizes a different DID.
    let registry = stub_registry("did:example:someone-else".to_string()).await;

    let keys = HashMap::from([(key.verifying_key().to_bytes(), SIGNER.to_string())]);
    let args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    let report = verify_with_keys(&args, &keys, None, BTreeMap::new())
        .await
        .unwrap();

    assert!(!report.ok);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Unauthorized {
            signer_did: SIGNER.to_string()
        }
    );
}

#[tokio::test]
async fn unsigned_commit_fails_without_touching_the_registry() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base = git(repo, &["rev-parse", "HEAD"]);
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "unsigned change"]);
    let head = git(repo, &["rev-parse", "HEAD"]);

    // Deliberately unreachable registry: no signed commits means no queries.
    let args = args_for(repo, format!("{base}..{head}"), "http://127.0.0.1:1".into());
    let report = verify_with_keys(&args, &HashMap::new(), None, BTreeMap::new())
        .await
        .unwrap();

    assert!(!report.ok);
    assert_eq!(report.commits[0].status, CommitStatus::Unsigned);
}

#[tokio::test]
async fn unreachable_registry_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);

    let keys = HashMap::from([(key.verifying_key().to_bytes(), SIGNER.to_string())]);
    let args = args_for(
        dir.path(),
        format!("{base}..{signed}"),
        "http://127.0.0.1:1".into(),
    );
    let report = verify_with_keys(&args, &keys, None, BTreeMap::new())
        .await
        .unwrap();

    assert!(
        !report.ok,
        "a valid signature must not pass without a registry decision"
    );
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::RegistryUnavailable { .. }
    ));
}

// --- PGP platform-commit exemption ------------------------------------------

mod pgp_platform {
    use super::*;
    use did_git_sign::pgp_exempt::ExemptKeyring;
    use pgp::composed::{
        ArmorOptions, DetachedSignature, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
        SignedSecretKey,
    };
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::types::Password;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn platform_key() -> SignedSecretKey {
        let mut rng = StdRng::seed_from_u64(7);
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .primary_user_id("GitHub <noreply@github.com>".to_string())
            .build()
            .unwrap()
            .generate(&mut rng)
            .unwrap()
    }

    /// Rewrite `sha` as a PGP-signed commit (the shape GitHub's web-flow key
    /// produces for web-UI merge and Dependabot commits).
    fn pgp_sign_commit(repo: &Path, sha: &str, key: &SignedSecretKey) -> String {
        let payload = {
            let out = Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["cat-file", "commit", sha])
                .output()
                .unwrap();
            assert!(out.status.success());
            out.stdout
        };
        let mut rng = StdRng::seed_from_u64(11);
        let armored = DetachedSignature::sign_binary_data(
            &mut rng,
            &key.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &payload[..],
        )
        .unwrap()
        .to_armored_string(ArmorOptions::default())
        .unwrap();

        let text = String::from_utf8(payload).unwrap();
        let (headers, body) = text.split_once("\n\n").unwrap();
        let mut sig_header = String::from("gpgsig ");
        let mut lines = armored.trim_end().split('\n');
        sig_header.push_str(lines.next().unwrap());
        for line in lines {
            sig_header.push_str("\n ");
            sig_header.push_str(line);
        }
        let signed = format!("{headers}\n{sig_header}\n\n{body}");

        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(signed.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim_end().to_string()
    }

    #[tokio::test]
    async fn platform_signed_commit_is_exempt_with_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let did_key = SigningKey::from_bytes(&[9u8; 32]);
        let (base, did_signed) = repo_with_signed_commit(repo, &did_key);

        // A "web-UI merge" style commit on top, PGP-signed by the platform key.
        std::fs::write(repo.join("a.txt"), "three\n").unwrap();
        git(repo, &["add", "a.txt"]);
        git(repo, &["commit", "-q", "-m", "merge-style change"]);
        let unsigned = git(repo, &["rev-parse", "HEAD"]);
        let platform = platform_key();
        let pgp_signed = pgp_sign_commit(repo, &unsigned, &platform);
        git(repo, &["update-ref", "refs/heads/main", &pgp_signed]);

        let keyring_armor = SignedPublicKey::from(platform.clone())
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        let keyring = ExemptKeyring::from_armored(&keyring_armor).unwrap();

        let registry = stub_registry(SIGNER.to_string()).await;
        let keys = HashMap::from([(did_key.verifying_key().to_bytes(), SIGNER.to_string())]);
        let args = args_for(repo, format!("{base}..{pgp_signed}"), registry);
        let report = verify_with_keys(&args, &keys, Some(&keyring), BTreeMap::new())
            .await
            .unwrap();

        assert!(report.ok, "DID-signed + platform-exempt should both pass");
        assert_eq!(report.commits.len(), 2);
        assert!(report.commits[0].status.is_trusted(), "{did_signed}");
        assert!(matches!(
            report.commits[1].status,
            CommitStatus::Exempt { .. }
        ));
    }

    #[tokio::test]
    async fn platform_signed_commit_fails_without_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git(repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.txt"), "one\n").unwrap();
        git(repo, &["add", "a.txt"]);
        git(repo, &["commit", "-q", "-m", "base"]);
        let base = git(repo, &["rev-parse", "HEAD"]);
        std::fs::write(repo.join("a.txt"), "two\n").unwrap();
        git(repo, &["add", "a.txt"]);
        git(repo, &["commit", "-q", "-m", "change"]);
        let unsigned = git(repo, &["rev-parse", "HEAD"]);
        let pgp_signed = pgp_sign_commit(repo, &unsigned, &platform_key());
        git(repo, &["update-ref", "refs/heads/main", &pgp_signed]);

        // No registry needed: the commit never reaches the registry pass.
        let args = args_for(
            repo,
            format!("{base}..{pgp_signed}"),
            "http://127.0.0.1:1".into(),
        );
        let report = verify_with_keys(&args, &HashMap::new(), None, BTreeMap::new())
            .await
            .unwrap();

        assert!(!report.ok, "no keyring means no exemptions");
        assert!(matches!(
            report.commits[0].status,
            CommitStatus::PgpRejected { .. }
        ));
    }
}

// --- org-fallback grants -------------------------------------------------------

#[tokio::test]
async fn org_grant_authorizes_via_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    // Grant exists only at org scope.
    let registry = stub_registry_with(vec![(SIGNER.to_string(), "example".to_string())]).await;

    let keys = HashMap::from([(key.verifying_key().to_bytes(), SIGNER.to_string())]);
    let mut args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    args.fallback_resource = Some("example".to_string());
    let report = verify_with_keys(&args, &keys, None, BTreeMap::new())
        .await
        .unwrap();

    assert!(report.ok);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "example".to_string()
        }
    );
}

#[tokio::test]
async fn org_grant_is_ignored_without_fallback_configured() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry_with(vec![(SIGNER.to_string(), "example".to_string())]).await;

    let keys = HashMap::from([(key.verifying_key().to_bytes(), SIGNER.to_string())]);
    let args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    let report = verify_with_keys(&args, &keys, None, BTreeMap::new())
        .await
        .unwrap();

    assert!(
        !report.ok,
        "no fallback configured: org grant must not apply"
    );
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::Unauthorized { .. }
    ));
}

#[tokio::test]
async fn repo_grant_wins_before_fallback_is_queried() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry_with(vec![
        (SIGNER.to_string(), "example/repo".to_string()),
        (SIGNER.to_string(), "example".to_string()),
    ])
    .await;

    let keys = HashMap::from([(key.verifying_key().to_bytes(), SIGNER.to_string())]);
    let mut args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    args.fallback_resource = Some("example".to_string());
    let report = verify_with_keys(&args, &keys, None, BTreeMap::new())
        .await
        .unwrap();

    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "example/repo".to_string()
        },
        "the repo-scoped grant is reported, not the fallback"
    );
}

#[tokio::test]
async fn denied_at_both_scopes_is_unauthorized() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry_with(vec![]).await;

    let keys = HashMap::from([(key.verifying_key().to_bytes(), SIGNER.to_string())]);
    let mut args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    args.fallback_resource = Some("example".to_string());
    let report = verify_with_keys(&args, &keys, None, BTreeMap::new())
        .await
        .unwrap();

    assert!(!report.ok);
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::Unauthorized { .. }
    ));
}

// --- committed platform keyring --------------------------------------------------

#[test]
fn committed_web_flow_keyring_parses() {
    // Drift tripwire: the keyring committed for the dogfood workflow must
    // stay parseable by the exemption verifier.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../.github/trusted-platform-keys.asc"
    );
    let text = std::fs::read_to_string(path).expect("committed keyring readable");
    did_git_sign::pgp_exempt::ExemptKeyring::from_armored(&text).expect("keyring parses");
}
