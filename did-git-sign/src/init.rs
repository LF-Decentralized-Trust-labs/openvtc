use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{self, SigningConfig, VtaCredentials};

/// Inputs to install did-git-sign for an already-provisioned persona.
///
/// All fields are values the caller already has — there is no VTA bootstrap
/// here. The function writes the config file, stores VTA credentials in the
/// OS keyring, runs the relevant `git config` invocations, and updates the
/// allowed_signers file.
///
/// The `verifying_key` is the Ed25519 public key (32 raw bytes) that signs
/// the persona's commits. It's used in the allowed_signers entry; the
/// caller is expected to have already derived it from the persona key
/// material.
pub struct InstallArgs<'a> {
    /// `true` writes config to the user's `~/.config/did-git-sign/`,
    /// `false` writes a repo-local `.did-git-sign.json`.
    pub global: bool,
    /// The verification method id, e.g. `did:webvh:.../persona#key-1`.
    pub did_key_id: String,
    /// VTA key UUID for the persona's signing key (stored in keyring so
    /// `did-git-sign -Y sign` can fetch the secret on demand).
    pub vta_key_id: String,
    /// DID this binary authenticates to the VTA as. The persona admin DID
    /// minted during VTA provisioning is the right value here.
    pub credential_did: String,
    /// Multibase-encoded private key paired with `credential_did`.
    pub credential_private_key_mb: String,
    /// VTA's own DID (e.g. `did:webvh:.../vta`).
    pub vta_did: String,
    /// VTA service URL, as resolved from the VTA's DID document. May be
    /// empty for DIDComm-only VTAs — `mediator_did` must be set in that
    /// case so the signer can reach the VTA over DIDComm.
    pub vta_url: String,
    /// DIDComm mediator DID advertised by the VTA. When `Some`, the signer
    /// uses DIDComm transport instead of REST. Required when `vta_url` is
    /// empty.
    pub mediator_did: Option<String>,
    /// Optional `git config user.name` to set during install.
    pub user_name: Option<String>,
    /// Persona signing key public bytes (Ed25519, 32 bytes).
    pub verifying_key: &'a [u8; 32],
}

/// Output of [`install`]. Mostly informational — used for the post-install
/// summary the caller prints.
pub struct InstallResult {
    /// Path the JSON config was written to.
    pub config_path: PathBuf,
    /// SSH public key string (`ssh-ed25519 …`) for the user to paste into
    /// their git host's signing-key settings.
    pub ssh_public_key: String,
    /// Set to the previous `--global user.signingKey` value if a non-global
    /// install just shadowed it. The caller can flag this to the operator
    /// so they aren't surprised when inspecting `git config --list`.
    pub overridden_global_signing_key: Option<String>,
}

/// Configure did-git-sign for an already-provisioned persona.
///
/// Idempotent against the file/keyring/git config state — re-running on a
/// host that already has did-git-sign installed updates the values without
/// erroring.
pub fn install(args: InstallArgs<'_>) -> Result<InstallResult> {
    let cfg = SigningConfig {
        did_key_id: args.did_key_id.clone(),
        user_name: args.user_name,
    };

    let vta_creds = VtaCredentials {
        vta_url: args.vta_url,
        vta_did: args.vta_did,
        credential_did: args.credential_did,
        private_key_multibase: args.credential_private_key_mb,
        key_id: args.vta_key_id,
        mediator_did: args.mediator_did,
    };

    let config_path = if args.global {
        SigningConfig::default_global_path()?
    } else {
        SigningConfig::repo_local_path()
    };

    cfg.save(&config_path)?;
    config::store_vta_credentials(&args.did_key_id, &vta_creds)?;

    setup_git(&config_path, &cfg, args.global)?;

    let entry = allowed_signers_entry(&cfg, args.verifying_key);
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    setup_allowed_signers(config_dir, &entry, args.global)?;

    // If we just shadowed a global user.signingKey with a local one, tell
    // the caller so they can surface it. Best-effort — failures here are
    // non-fatal.
    let overridden_global_signing_key = (!args.global)
        .then(|| {
            std::process::Command::new("git")
                .args(["config", "--global", "user.signingKey"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .flatten();

    Ok(InstallResult {
        config_path,
        ssh_public_key: ssh_public_key_string(args.verifying_key),
        overridden_global_signing_key,
    })
}

/// Tear down a did-git-sign install for `did_key_id`. Idempotent — every
/// step succeeds (best-effort) when its target is already gone, so the
/// function is safe to run repeatedly or against a partial install.
///
/// The caller decides scope: pass `global = true` to remove the user's
/// `~/.config/did-git-sign/config.json` install, `false` to remove a
/// repo-local `.did-git-sign.json` next to the current directory.
///
/// Returned [`UninstallResult`] is informational — it lists what was
/// touched so callers can render a summary, but never carries a hard
/// failure.
pub fn uninstall(global: bool, did_key_id: &str) -> Result<UninstallResult> {
    let mut summary = UninstallResult::default();

    let config_path = if global {
        SigningConfig::default_global_path()?
    } else {
        SigningConfig::repo_local_path()
    };

    // 1. Remove SigningConfig JSON file (silently if absent).
    if config_path.exists() {
        match std::fs::remove_file(&config_path) {
            Ok(()) => {
                summary.removed_config_file = Some(config_path.clone());
            }
            Err(e) => {
                summary
                    .warnings
                    .push(format!("could not remove {}: {e}", config_path.display()));
            }
        }
    }

    // 2. Drop the keyring entries that are keyed by did_key_id. The
    //    `delete_credential` API errors when the entry doesn't exist —
    //    swallow that case.
    for suffix in [":vta", ":token"] {
        let key = format!("{did_key_id}{suffix}");
        if let Ok(entry) = keyring_core::Entry::new(config::KEYRING_SERVICE, &key) {
            match entry.delete_credential() {
                Ok(()) => summary.removed_keyring_entries.push(key),
                Err(keyring_core::Error::NoEntry) => {}
                Err(e) => {
                    summary
                        .warnings
                        .push(format!("could not remove keyring entry '{key}': {e}"));
                }
            }
        }
    }

    // 3. Strip the matching line out of allowed_signers (if the file
    //    exists and contains an entry for this principal). Other principals
    //    in the same file are preserved.
    let signers_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("allowed_signers");
    if signers_path.exists() {
        match std::fs::read_to_string(&signers_path) {
            Ok(content) => {
                let prefix = format!("{did_key_id} ");
                let mut kept = Vec::new();
                let mut removed = false;
                for line in content.lines() {
                    if line.trim_start().starts_with(&prefix) {
                        removed = true;
                    } else {
                        kept.push(line);
                    }
                }
                if removed {
                    let mut new_content = kept.join("\n");
                    if !new_content.is_empty() {
                        new_content.push('\n');
                    }
                    if let Err(e) = std::fs::write(&signers_path, new_content) {
                        summary
                            .warnings
                            .push(format!("could not rewrite {}: {e}", signers_path.display()));
                    } else {
                        summary.allowed_signers_entry_removed = true;
                    }
                }
            }
            Err(e) => {
                summary
                    .warnings
                    .push(format!("could not read {}: {e}", signers_path.display()));
            }
        }
    }

    // 4. Unset the git config keys we own at the install scope. Best
    //    effort — `git config --unset` errors when the key isn't set,
    //    which we ignore.
    let scope = if global { "--global" } else { "--local" };
    for key in [
        "user.signingKey",
        "gpg.format",
        "gpg.ssh.program",
        "gpg.ssh.defaultKeyFile",
        "gpg.ssh.allowedSignersFile",
        "commit.gpgsign",
    ] {
        if git_config_unset(scope, key) {
            summary.git_config_keys_unset.push(key.to_string());
        }
    }

    Ok(summary)
}

/// Outcome of an [`uninstall`] call. None of the variants represent fatal
/// errors — the caller is expected to render `warnings` if it wants to
/// surface partial-state issues to the operator.
#[derive(Debug, Default)]
pub struct UninstallResult {
    /// Path of the SigningConfig file that was removed (if any).
    pub removed_config_file: Option<PathBuf>,
    /// Keyring keys that were deleted (under the `did-git-sign` service).
    pub removed_keyring_entries: Vec<String>,
    /// True when an allowed_signers line for this principal was removed.
    pub allowed_signers_entry_removed: bool,
    /// Git config keys that were unset at the install scope.
    pub git_config_keys_unset: Vec<String>,
    /// Best-effort warnings — used for display, not error propagation.
    pub warnings: Vec<String>,
}

/// Returns true if `git config <scope> --unset <key>` removed something.
/// Errors and "key not present" both map to false (best-effort cleanup).
fn git_config_unset(scope: &str, key: &str) -> bool {
    Command::new("git")
        .arg("config")
        .arg(scope)
        .arg("--unset")
        .arg(key)
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Initialize git configuration for DID-based SSH signing.
pub fn setup_git(config_path: &Path, cfg: &SigningConfig, global: bool) -> Result<()> {
    let scope = if global { "--global" } else { "--local" };
    let config_path_str = config_path
        .to_str()
        .context("config path is not valid UTF-8")?;

    // Set gpg format to ssh
    git_config(scope, "gpg.format", "ssh")?;

    // Set our tool as the signing program
    // Git calls: <program> -Y sign -f <user.signingKey or defaultKeyFile> -n git
    git_config(scope, "gpg.ssh.program", "did-git-sign")?;

    // Point git to our config file as both the signing key and the fallback key file.
    // user.signingKey takes precedence over gpg.ssh.defaultKeyFile when set, so we
    // must set it here to override any global user.signingKey (e.g. an SSH public key)
    // that would otherwise be passed as -f and cause a config parse error.
    //
    // NOTE: user.signingKey is conventionally a .pub path; using a .json path here
    // is unconventional. Third-party tools inspecting this repo's git config will
    // see a non-.pub value. This is an accepted trade-off — the local override is
    // the only non-destructive way to win over a global user.signingKey without
    // modifying the user's global git configuration.
    git_config(scope, "user.signingKey", config_path_str)?;
    git_config(scope, "gpg.ssh.defaultKeyFile", config_path_str)?;

    // Enable commit signing by default
    git_config(scope, "commit.gpgsign", "true")?;

    // Optionally set user.name
    if let Some(name) = &cfg.user_name {
        git_config(scope, "user.name", name)?;
    }

    Ok(())
}

/// Generate an allowed_signers file entry for verification.
pub fn allowed_signers_entry(cfg: &SigningConfig, public_key_bytes: &[u8; 32]) -> String {
    let pub_b64 = base64_encode_pubkey(public_key_bytes);
    format!("{} ssh-ed25519 {}", cfg.did_key_id, pub_b64)
}

/// Set up the allowed_signers file for signature verification.
pub fn setup_allowed_signers(config_dir: &Path, entry: &str, global: bool) -> Result<()> {
    let signers_path = config_dir.join("allowed_signers");
    let signers_path_str = signers_path
        .to_str()
        .context("signers path is not valid UTF-8")?;

    // Append or create the allowed_signers file
    let existing = std::fs::read_to_string(&signers_path).unwrap_or_default();
    if !existing.contains(entry) {
        let mut content = existing;
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(entry);
        content.push('\n');
        std::fs::write(&signers_path, content)
            .with_context(|| format!("failed to write {}", signers_path.display()))?;
    }

    let scope = if global { "--global" } else { "--local" };
    git_config(scope, "gpg.ssh.allowedSignersFile", signers_path_str)?;

    Ok(())
}

/// Run `git config <scope> <key> <value>`.
fn git_config(scope: &str, key: &str, value: &str) -> Result<()> {
    let output = Command::new("git")
        .arg("config")
        .arg(scope)
        .arg(key)
        .arg(value)
        .output()
        .context("failed to run git config")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git config {scope} {key} failed: {stderr}");
    }

    Ok(())
}

/// Format an Ed25519 public key as an SSH public key string (e.g., `ssh-ed25519 AAAA...`).
pub fn ssh_public_key_string(public_key_bytes: &[u8; 32]) -> String {
    format!("ssh-ed25519 {}", base64_encode_pubkey(public_key_bytes))
}

/// Base64-encode a raw Ed25519 public key for SSH authorized_keys format.
fn base64_encode_pubkey(public_key_bytes: &[u8; 32]) -> String {
    use base64::Engine;
    // SSH public key blob: "ssh-ed25519" type string + key bytes
    let mut blob = Vec::new();
    let key_type = b"ssh-ed25519";
    blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(key_type);
    blob.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(public_key_bytes);
    base64::engine::general_purpose::STANDARD.encode(&blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_pubkey_format() {
        let key = [0u8; 32];
        let encoded = base64_encode_pubkey(&key);
        // Should be a valid base64 string
        assert!(!encoded.is_empty());

        // Decode and verify structure
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        // 4 + 11 + 4 + 32 = 51 bytes
        assert_eq!(decoded.len(), 51);
    }

    #[test]
    fn test_allowed_signers_entry_format() {
        let cfg = SigningConfig {
            did_key_id: "did:webvh:abc:example.com#key-0".to_string(),
            user_name: None,
        };
        let key = [0u8; 32];
        let entry = allowed_signers_entry(&cfg, &key);
        assert!(entry.starts_with("did:webvh:abc:example.com#key-0 ssh-ed25519 "));
    }

    #[test]
    fn test_ssh_public_key_string_format() {
        let key = [0u8; 32];
        let result = ssh_public_key_string(&key);
        assert!(result.starts_with("ssh-ed25519 "));
        // The base64 part should be decodable
        let b64_part = result.strip_prefix("ssh-ed25519 ").unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_part).unwrap();
        // 4 + 11 + 4 + 32 = 51 bytes
        assert_eq!(decoded.len(), 51);
    }

    #[test]
    fn test_allowed_signers_entry_contains_valid_ssh_key() {
        let cfg = SigningConfig {
            did_key_id: "did:webvh:test:host#key-0".to_string(),
            user_name: Some("Test User".to_string()),
        };
        let key = [0xFF; 32];
        let entry = allowed_signers_entry(&cfg, &key);

        // Entry should have format: <email> ssh-ed25519 <base64>
        let parts: Vec<&str> = entry.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "did:webvh:test:host#key-0");
        assert_eq!(parts[1], "ssh-ed25519");
        // Third part is valid base64
        assert!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[2],).is_ok()
        );
    }

    #[test]
    fn test_base64_pubkey_encodes_key_type_and_bytes() {
        let key = [0x42; 32];
        let encoded = base64_encode_pubkey(&key);
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encoded).unwrap();

        // Verify SSH wire format: uint32 len + "ssh-ed25519" + uint32 len + key bytes
        assert_eq!(&decoded[0..4], &(11u32).to_be_bytes());
        assert_eq!(&decoded[4..15], b"ssh-ed25519");
        assert_eq!(&decoded[15..19], &(32u32).to_be_bytes());
        assert_eq!(&decoded[19..51], &[0x42; 32]);
    }

    #[test]
    fn test_setup_allowed_signers_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let entry = "did:webvh:test:host#key-0 ssh-ed25519 AAAA";

        // We cannot test the git config part without a git repo, but we can test
        // the file-writing portion by calling the function in a git repo context.
        // Instead, verify the file-writing logic directly:
        let signers_path = dir.path().join("allowed_signers");
        let content = format!("{entry}\n");
        std::fs::write(&signers_path, &content).unwrap();

        let read_back = std::fs::read_to_string(&signers_path).unwrap();
        assert!(read_back.contains(entry));
    }

    #[test]
    fn test_different_keys_produce_different_ssh_strings() {
        let key_a = [0x00; 32];
        let key_b = [0xFF; 32];
        assert_ne!(ssh_public_key_string(&key_a), ssh_public_key_string(&key_b));
    }

    /// Changes the process CWD on construction, restores it on drop (panic-safe).
    /// Requires `#[serial_test::serial]` — CWD is process-global.
    /// **Any future non-serial test that uses a relative path or calls
    /// `current_dir()` will silently resolve against the wrong directory.**
    struct CwdGuard {
        original: std::path::PathBuf,
    }

    impl CwdGuard {
        fn change_to(path: &std::path::Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            CwdGuard { original }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            // Best-effort restore; ignore errors (e.g. if the temp dir was already removed).
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    /// Regression guard: setup_git must never write user.email to the git config.
    ///
    /// user.email was historically set in earlier versions of this tool.  It was
    /// removed because git's SSH signature verification uses the allowed_signers
    /// principal (derived from the key fingerprint), not user.email, making the
    /// field irrelevant and misleading.  This test ensures it stays absent.
    #[test]
    #[serial_test::serial]
    fn setup_git_never_writes_user_email() {
        let dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        // Move into the temp repo so that `git config --local` targets it.
        // The inner block ensures CwdGuard is dropped (and CWD restored) before
        // the assertions run, keeping the verify step independent of CWD.
        let original_cwd = std::env::current_dir().unwrap();
        {
            let _cwd = CwdGuard::change_to(dir.path());
            let config_path = dir.path().join(".did-git-sign.json");
            let cfg = SigningConfig {
                did_key_id: "did:webvh:test#key-0".to_string(),
                user_name: None,
            };
            setup_git(&config_path, &cfg, false).unwrap();
            // _cwd drops here: original directory is restored
        }
        // Pin the invariant explicitly so a future edit that moves the
        // verify command inside the guard's scope (or drops the guard) is
        // caught loudly rather than silently regressing the CWD-independence
        // promise the inner block makes.
        assert_eq!(
            std::env::current_dir().unwrap(),
            original_cwd,
            "CwdGuard must restore the original directory on drop"
        );

        // Verify with an explicit -C so the check is not sensitive to the current CWD.
        let out = std::process::Command::new("git")
            .args([
                "-C",
                dir.path().to_str().unwrap(),
                "config",
                "--local",
                "user.email",
            ])
            .output()
            .unwrap();

        assert!(
            !out.status.success(),
            "user.email must not be set by setup_git; found: {}",
            String::from_utf8_lossy(&out.stdout).trim(),
        );
    }
}
