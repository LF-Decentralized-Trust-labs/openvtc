/*!
*  Public [crate::config::Config] information that is stored in plaintext on disk
*/

use crate::{
    config::{Config, ConfigProtectionType, protected_config::ProtectedConfig},
    errors::OpenVTCError,
    logs::Logs,
};
use secrecy::SecretVec;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{env, fs, path::PathBuf, sync::Arc};
use tracing::warn;

/// Primary structure used for storing [crate::config::Config] data that is not sensitive
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct PublicConfig {
    /// How is the configuration protected?
    pub protection: ConfigProtectionType,

    /// Persona DID
    pub persona_did: Arc<String>,

    /// Mediator DID
    pub mediator_did: String,

    /// Human friendly name to use when referring to ourself
    pub friendly_name: String,

    /// Linux Organisation DID
    pub lk_did: String,

    #[serde(default)]
    pub logs: Logs,

    #[serde(default)]
    pub private: Option<String>,
}

impl From<&Config> for PublicConfig {
    /// Extracts public information from the full Config
    fn from(cfg: &Config) -> Self {
        cfg.public.clone()
    }
}

/// Validates that a profile name contains only safe characters.
pub fn validate_profile_name(profile: &str) -> Result<(), OpenVTCError> {
    if profile != "default"
        && !profile
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(OpenVTCError::Config(format!(
            "Invalid profile name '{profile}'. Only alphanumeric characters, hyphens, and underscores are allowed."
        )));
    }
    if profile.is_empty() {
        return Err(OpenVTCError::Config(
            "Profile name cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// Private helper to determine where the config file is located
fn get_config_path(profile: &str) -> Result<PathBuf, OpenVTCError> {
    validate_profile_name(profile)?;

    let mut path = if let Ok(config_path) = env::var("OPENVTC_CONFIG_PATH") {
        PathBuf::from(config_path)
    } else {
        #[cfg(windows)]
        {
            dirs::config_dir()
                .map(|p| p.join("openvtc"))
                .ok_or_else(|| {
                    OpenVTCError::Config("Couldn't determine configuration directory".to_string())
                })?
        }
        #[cfg(not(windows))]
        {
            dirs::home_dir()
                .map(|p| p.join(".config").join("openvtc"))
                .ok_or_else(|| {
                    OpenVTCError::Config("Couldn't determine home directory".to_string())
                })?
        }
    };

    if profile == "default" {
        path.push("config.json");
    } else {
        path.push(format!("config-{profile}.json"));
    }

    Ok(path)
}

impl PublicConfig {
    /// Saves to disk the public configuration information
    /// Uses the default CONFIG_PATH const or ENV Variable OPENVTC_CONFIG_PATH
    pub fn save(
        &self,
        profile: &str,
        private: &ProtectedConfig,
        private_seed: &SecretVec<u8>,
    ) -> Result<(), OpenVTCError> {
        let path = get_config_path(profile)?;

        // Check that directory structure exists
        if let Some(parent_path) = path.parent()
            && !parent_path.exists()
        {
            // Create parent directories
            fs::create_dir_all(parent_path).map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't create parent directory ({}): {e}",
                    parent_path.to_string_lossy()
                ))
            })?;
        }

        let public = PublicConfig {
            private: Some(private.save(private_seed)?),
            ..self.clone()
        };
        // Write config to disk
        fs::write(&path, serde_json::to_string_pretty(&public)?).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't write public config to file ({}): {e}",
                path.to_string_lossy()
            ))
        })?;

        // Restrict file permissions to owner-only on Unix systems
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't set permissions on config file ({}): {e}",
                path.to_string_lossy()
            ))
        })?;

        Ok(())
    }

    /// Loads from disk the public information for OpenVTC to unlock it's secrets from the OS Secure
    /// Store
    pub fn load(profile: &str) -> Result<Self, OpenVTCError> {
        let path = get_config_path(profile)?;

        let file = fs::File::open(&path).map_err(|e| {
            OpenVTCError::ConfigNotFound(path.to_string_lossy().into_owned(), e)
        })?;

        match serde_json::from_reader(file) {
            Ok(s) => Ok(s),
            Err(e) => {
                warn!("Couldn't Deserialize PublicConfig. Reason: {e}");
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guards tests that mutate the OPENVTC_CONFIG_PATH env var so they
    /// don't race against each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_get_config_path_default_profile() {
        let _guard = ENV_LOCK.lock().unwrap();
        let base = if cfg!(windows) { "C:\\tmp\\openvtc-test" } else { "/tmp/openvtc-test" };
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base) };
        let path = get_config_path("default").expect("Should return path");
        
        let mut expected = PathBuf::from(base);
        expected.push("config.json");
        assert_eq!(path, expected);
        
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_named_profile() {
        let _guard = ENV_LOCK.lock().unwrap();
        let base = if cfg!(windows) { "C:\\tmp\\openvtc-test" } else { "/tmp/openvtc-test" };
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base) };
        let path = get_config_path("work").expect("Should return path");
        
        let mut expected = PathBuf::from(base);
        expected.push("config-work.json");
        assert_eq!(path, expected);
        
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_trailing_slash_normalization() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (base_with, base_without) = if cfg!(windows) {
            ("C:\\tmp\\cfg\\", "C:\\tmp\\cfg")
        } else {
            ("/tmp/cfg/", "/tmp/cfg")
        };

        // Assert that both versions produce the exact same PathBuf
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base_with) };
        let path_with = get_config_path("default").unwrap();

        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base_without) };
        let path_without = get_config_path("default").unwrap();

        assert_eq!(path_with, path_without, "Paths with and without trailing slashes must be identical");
        
        // Verify the actual content
        let mut expected = PathBuf::from(base_without);
        expected.push("config.json");
        assert_eq!(path_with, expected);

        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };

        let path = get_config_path("default").expect("Should return path");

        // Verify it ends with openvtc/config.json (cross-platform check)
        let mut expected_suffix = PathBuf::new();
        expected_suffix.push("openvtc");
        expected_suffix.push("config.json");

        assert!(path.ends_with(expected_suffix));
    }

    #[test]
    fn test_public_config_default() {
        let pc = PublicConfig::default();
        assert!(pc.persona_did.is_empty());
        assert!(pc.mediator_did.is_empty());
        assert!(pc.friendly_name.is_empty());
        assert!(pc.private.is_none());
    }
}
