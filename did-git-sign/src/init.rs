use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use crate::config::SigningConfig;

/// Initialize git configuration for DID-based SSH signing.
pub fn setup_git(config_path: &Path, cfg: &SigningConfig, global: bool) -> Result<()> {
    let scope = if global { "--global" } else { "--local" };
    let config_path_str = config_path
        .to_str()
        .context("config path is not valid UTF-8")?;

    // Set gpg format to ssh
    git_config(scope, "gpg.format", "ssh")?;

    // Set our tool as the signing program
    // Git calls: <program> -Y sign -f <defaultKeyFile> -n git
    git_config(scope, "gpg.ssh.program", "did-git-sign")?;

    // Point git to our config file as the "key file"
    git_config(scope, "gpg.ssh.defaultKeyFile", config_path_str)?;

    // Enable commit signing by default
    git_config(scope, "commit.gpgsign", "true")?;

    // Set user.email to the DID#key-id
    git_config(scope, "user.email", &cfg.did_key_id)?;

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
pub fn setup_allowed_signers(
    config_dir: &Path,
    entry: &str,
    global: bool,
) -> Result<()> {
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
        let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
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
}
