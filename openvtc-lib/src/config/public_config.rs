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
use std::{env, fs, path::Path, sync::Arc};
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

/// Private helper to determine where the config file is located
fn get_config_path(profile: &str) -> Result<String, OpenVTCError> {
    let path = if let Ok(config_path) = env::var("OPENVTC_CONFIG_PATH") {
        if config_path.ends_with('/') {
            config_path
        } else {
            [&config_path, "/"].concat()
        }
    } else if let Some(home) = dirs::home_dir()
        && let Some(home_str) = home.to_str()
    {
        [home_str, "/.config/openvtc/"].concat()
    } else {
        return Err(OpenVTCError::Config(
            "Couldn't determine Home directory".to_string(),
        ));
    };

    if profile == "default" {
        Ok([&path, "config.json"].concat())
    } else {
        Ok([&path, "config-", profile, ".json"].concat())
    }
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
        let cfg_path = get_config_path(profile)?;
        let path = Path::new(&cfg_path);

        // Check that directory structure exists
        if let Some(parent_path) = path.parent()
            && !parent_path.exists()
        {
            // Create parent directories
            fs::create_dir_all(parent_path).map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't create parent directory ({}): {}",
                    parent_path.to_string_lossy(),
                    e
                ))
            })?;
        }

        let public = PublicConfig {
            private: Some(private.save(private_seed)?),
            ..self.clone()
        };
        // Write config to disk
        fs::write(path, serde_json::to_string_pretty(&public)?).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't write public config to file ({}): {}",
                path.to_string_lossy(),
                e
            ))
        })?;

        Ok(())
    }

    /// Loads from disk the public information for OpenVTC to unlock it's secrets from the OS Secure
    /// Store
    pub fn load(profile: &str) -> Result<Self, OpenVTCError> {
        let cfg_path = get_config_path(profile)?;
        let path = Path::new(&cfg_path);

        let file =
            fs::File::open(path).map_err(|e| OpenVTCError::ConfigNotFound(cfg_path.to_string(), e))?;

        match serde_json::from_reader(file) {
            Ok(s) => Ok(s),
            Err(e) => {
                warn!("Couldn't Deserialize PublicConfig. Reason: {e}");
                Err(e.into())
            }
        }
    }
}
