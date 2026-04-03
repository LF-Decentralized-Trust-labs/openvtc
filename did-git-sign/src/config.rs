use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEYRING_SERVICE: &str = "did-git-sign";

/// Configuration stored in .did-git-sign.json
///
/// Contains only the DID identity and optional git user name.
/// All VTA credentials and key identifiers are stored in the OS keyring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    /// The DID#key-id to use as git user.email (e.g., did:webvh:abc:example.com#key-0)
    pub did_key_id: String,
    /// Git user.name to set during init
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

/// VTA credentials and key configuration stored securely in the OS keyring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtaCredentials {
    /// VTA service URL
    pub vta_url: String,
    /// VTA DID
    pub vta_did: String,
    /// Credential DID (for VTA authentication)
    pub credential_did: String,
    /// Credential private key (multibase-encoded)
    pub private_key_multibase: String,
    /// VTA key ID for the Ed25519 signing key
    pub key_id: String,
}

impl SigningConfig {
    /// Load config from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;
        serde_json::from_str(&data)
            .with_context(|| format!("failed to parse config: {}", path.display()))
    }

    /// Save config to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory: {}", parent.display())
            })?;
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)
            .with_context(|| format!("failed to write config: {}", path.display()))
    }

    /// Default global config path: ~/.config/did-git-sign/config.json
    pub fn default_global_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().context("could not determine config directory")?;
        Ok(config_dir.join("did-git-sign").join("config.json"))
    }

    /// Repo-local config path: .did-git-sign.json in the git repo root.
    pub fn repo_local_path() -> PathBuf {
        PathBuf::from(".did-git-sign.json")
    }
}

/// Store VTA credentials in the OS keyring, keyed by the DID#key-id.
pub fn store_vta_credentials(did_key_id: &str, creds: &VtaCredentials) -> Result<()> {
    let key = format!("{did_key_id}:vta");
    let value = serde_json::to_string(creds)?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &key)
        .context("failed to create keyring entry for VTA credentials")?;
    entry
        .set_password(&value)
        .context("failed to store VTA credentials in keyring")?;
    Ok(())
}

/// Retrieve VTA credentials from the OS keyring.
pub fn load_vta_credentials(did_key_id: &str) -> Result<VtaCredentials> {
    let key = format!("{did_key_id}:vta");
    let entry =
        keyring::Entry::new(KEYRING_SERVICE, &key).context("failed to create keyring entry")?;
    let data = entry
        .get_password()
        .context("VTA credentials not found in keyring — run `did-git-sign init` first")?;
    serde_json::from_str(&data).context("failed to parse VTA credentials from keyring")
}

/// Store a cached VTA access token in the keyring.
pub fn cache_token(did_key_id: &str, token: &str, expires_at: u64) -> Result<()> {
    let key = format!("{did_key_id}:token");
    let value = serde_json::json!({
        "access_token": token,
        "access_expires_at": expires_at,
    });
    let entry =
        keyring::Entry::new(KEYRING_SERVICE, &key).context("failed to create token cache entry")?;
    entry
        .set_password(&value.to_string())
        .context("failed to cache token in keyring")?;
    Ok(())
}

/// Load a cached VTA access token if it is still valid.
pub fn load_cached_token(did_key_id: &str) -> Option<String> {
    let key = format!("{did_key_id}:token");
    let entry = keyring::Entry::new(KEYRING_SERVICE, &key).ok()?;
    let data = entry.get_password().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&data).ok()?;

    let expires_at = parsed["access_expires_at"].as_u64()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    // Use token if it has at least 30 seconds remaining
    if now + 30 < expires_at {
        parsed["access_token"].as_str().map(|s| s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_signing_config_roundtrip_serde() {
        let cfg = SigningConfig {
            did_key_id: "did:webvh:abc:example.com#key-0".to_string(),
            user_name: Some("Alice".to_string()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: SigningConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.did_key_id, cfg.did_key_id);
        assert_eq!(parsed.user_name, cfg.user_name);
    }

    #[test]
    fn test_signing_config_user_name_none_omitted_in_json() {
        let cfg = SigningConfig {
            did_key_id: "did:webvh:abc:example.com#key-0".to_string(),
            user_name: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("user_name"));
    }

    #[test]
    fn test_signing_config_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let cfg = SigningConfig {
            did_key_id: "did:webvh:abc:example.com#key-0".to_string(),
            user_name: Some("Bob".to_string()),
        };
        cfg.save(&path).unwrap();

        let loaded = SigningConfig::load(&path).unwrap();
        assert_eq!(loaded.did_key_id, cfg.did_key_id);
        assert_eq!(loaded.user_name, cfg.user_name);
    }

    #[test]
    fn test_signing_config_load_missing_file() {
        let result = SigningConfig::load(Path::new("/nonexistent/config.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_config_load_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"not json").unwrap();

        let result = SigningConfig::load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_repo_local_path() {
        let path = SigningConfig::repo_local_path();
        assert_eq!(path, PathBuf::from(".did-git-sign.json"));
    }

    #[test]
    fn test_default_global_path_ends_with_expected_suffix() {
        // This may fail in unusual environments without a home dir, but should work in CI/dev
        if let Ok(path) = SigningConfig::default_global_path() {
            assert!(path.ends_with("did-git-sign/config.json"));
        }
    }

    #[test]
    fn test_vta_credentials_roundtrip_serde() {
        let creds = VtaCredentials {
            vta_url: "https://vta.example.com".to_string(),
            vta_did: "did:example:vta".to_string(),
            credential_did: "did:key:z6Mk123".to_string(),
            private_key_multibase: "z1234".to_string(),
            key_id: "key-1".to_string(),
        };
        let json = serde_json::to_string(&creds).unwrap();
        let parsed: VtaCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.vta_url, creds.vta_url);
        assert_eq!(parsed.key_id, creds.key_id);
        assert_eq!(parsed.credential_did, creds.credential_did);
    }

    #[test]
    fn test_signing_config_save_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("config.json");

        let cfg = SigningConfig {
            did_key_id: "did:webvh:abc:example.com#key-0".to_string(),
            user_name: None,
        };
        cfg.save(&path).unwrap();
        assert!(path.exists());
    }
}
