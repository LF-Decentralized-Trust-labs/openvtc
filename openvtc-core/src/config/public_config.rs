/*!
*  Public [crate::config::Config] information that is stored in plaintext on disk
*/

use crate::{
    config::{Config, ConfigProtectionType, protected_config::ProtectedConfig},
    errors::OpenVTCError,
    logs::Logs,
};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{env, fs, path::PathBuf, sync::Arc};
use tracing::warn;

/// Current config format version. Increment when the format changes.
pub const CONFIG_VERSION: u32 = 1;

/// Result of [`PublicConfig::delete_profile`]. Mostly informational —
/// callers render `warnings` when surfacing partial-state issues. None of
/// the fields represent fatal errors.
#[derive(Debug, Default)]
pub struct DeleteProfileSummary {
    /// Path of the JSON config that was deleted (if any).
    pub removed_config_file: Option<String>,
    /// True when the openvtc keyring entry was deleted.
    pub removed_keyring_entry: bool,
    /// Best-effort warnings — used for display, not error propagation.
    pub warnings: Vec<String>,
}

/// Primary structure used for storing [crate::config::Config] data that is not sensitive
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct PublicConfig {
    /// Config format version for migration support.
    /// Absent in pre-0.2.0 configs (treated as version 0).
    #[serde(default)]
    pub config_version: u32,

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
///
/// Trims leading/trailing whitespace before validating so that
/// `" default "` is treated as `"default"`. Rejects whitespace-only
/// inputs explicitly with a clear error rather than letting them fall
/// through the alphanumeric check (which would emit a confusing
/// "Invalid profile name '   '" message). The empty/whitespace check
/// runs first so an empty string can't reach the character check.
pub fn validate_profile_name(profile: &str) -> Result<(), OpenVTCError> {
    let trimmed = profile.trim();

    if trimmed.is_empty() {
        return Err(OpenVTCError::Config(
            "Profile name cannot be empty or contain only whitespace".to_string(),
        ));
    }

    if trimmed != "default"
        && !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(OpenVTCError::Config(format!(
            "Invalid profile name '{trimmed}'. Only alphanumeric characters, hyphens, and underscores are allowed."
        )));
    }
    Ok(())
}

/// Resolve the directory that holds OpenVTC profile data — config files,
/// the did.jsonl log, etc. Honours `OPENVTC_CONFIG_PATH`. Falls back to
/// `~/.config/openvtc/` on Unix/macOS, and to the platform's AppData
/// location (`%APPDATA%\openvtc`, via `dirs::config_dir()`) on Windows.
/// Validates the profile name as a side effect.
pub fn profile_dir(profile: &str) -> Result<PathBuf, OpenVTCError> {
    validate_profile_name(profile)?;
    if let Ok(config_path) = env::var("OPENVTC_CONFIG_PATH") {
        return Ok(PathBuf::from(config_path));
    }
    #[cfg(windows)]
    {
        dirs::config_dir()
            .map(|p| p.join("openvtc"))
            .ok_or_else(|| {
                OpenVTCError::Config("Couldn't determine configuration directory".to_string())
            })
    }
    #[cfg(not(windows))]
    {
        dirs::home_dir()
            .map(|p| p.join(".config").join("openvtc"))
            .ok_or_else(|| OpenVTCError::Config("Couldn't determine Home directory".to_string()))
    }
}

/// Private helper to determine where the config file is located.
/// Returns a `PathBuf` so callers don't have to round-trip through a
/// (potentially non-UTF-8) string.
fn get_config_path(profile: &str) -> Result<PathBuf, OpenVTCError> {
    let mut path = profile_dir(profile)?;
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
        private_seed: &SecretBox<Vec<u8>>,
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
            config_version: CONFIG_VERSION,
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

    ///
    /// Removes the public config JSON file under the resolved config path
    /// and (best-effort) deletes the matching `SecuredConfig` keyring
    /// entry. Each step is idempotent — both succeed when the artifact is
    /// already gone, so the function is safe to run against a partial /
    /// already-clean install.
    ///
    /// Caller is expected to coordinate other cleanup (e.g.
    /// `did_git_sign::init::uninstall`) themselves; this function only
    /// owns openvtc's own state.
    /// Tear down the on-disk + OS-keyring footprint of a profile.
    ///
    /// Removes the public config JSON file under the resolved config path
    /// and (best-effort) deletes the matching `SecuredConfig` keyring
    /// entry. Each step is idempotent — both succeed when the artifact is
    /// already gone, so the function is safe to run against a partial /
    /// already-clean install.
    ///
    /// Caller is expected to coordinate other cleanup (e.g.
    /// `did_git_sign::init::uninstall`) themselves; this function only
    /// owns openvtc's own state.
    pub fn delete_profile(profile: &str) -> Result<DeleteProfileSummary, OpenVTCError> {
        validate_profile_name(profile)?;
        let mut summary = DeleteProfileSummary::default();

        let path = get_config_path(profile)?;
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't remove public config file ({}): {e}",
                    path.to_string_lossy()
                ))
            })?;
            summary.removed_config_file = Some(path.to_string_lossy().into_owned());
        }

        // Drop the SecuredConfig keyring entry if present. `delete_credential`
        // returns `NoEntry` when nothing is stored — swallow that case.
        match keyring_core::Entry::new(crate::config::secured_config::service_name(), profile) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) => summary.removed_keyring_entry = true,
                Err(keyring_core::Error::NoEntry) => {}
                Err(e) => {
                    summary
                        .warnings
                        .push(format!("could not remove keyring entry: {e}"));
                }
            },
            Err(e) => {
                summary
                    .warnings
                    .push(format!("could not access keyring entry: {e}"));
            }
        }

        Ok(summary)
    }

    /// Loads from disk the public information for OpenVTC to unlock it's secrets from the OS Secure
    /// Store
    pub fn load(profile: &str) -> Result<Self, OpenVTCError> {
        let path = get_config_path(profile)?;

        let file = fs::File::open(&path)
            .map_err(|e| OpenVTCError::ConfigNotFound(path.to_string_lossy().into_owned(), e))?;

        let mut config: Self = match serde_json::from_reader(file) {
            Ok(s) => s,
            Err(e) => {
                warn!("Couldn't Deserialize PublicConfig. Reason: {e}");
                return Err(e.into());
            }
        };

        // Run migrations if config is from an older version
        if config.config_version < CONFIG_VERSION {
            tracing::info!(
                from = config.config_version,
                to = CONFIG_VERSION,
                "migrating config format"
            );
            migrate_config(&mut config)?;
        }

        Ok(config)
    }
}

/// Run config migrations from `config.config_version` up to [`CONFIG_VERSION`].
///
/// Each migration step handles one version increment. New migrations are added
/// as new match arms. The version field is updated after all migrations complete.
fn migrate_config(config: &mut PublicConfig) -> Result<(), OpenVTCError> {
    let mut version = config.config_version;

    while version < CONFIG_VERSION {
        match version {
            // Version 0 → 1: no structural changes, just adding the version field.
            // Pre-0.2.0 configs lack `config_version` and deserialize as 0.
            0 => {
                tracing::debug!("migration 0→1: adding config_version field");
            }
            v => {
                return Err(OpenVTCError::Config(format!(
                    "Unknown config version {v} — cannot migrate. \
                     Expected version <= {CONFIG_VERSION}."
                )));
            }
        }
        version += 1;
    }

    config.config_version = CONFIG_VERSION;
    Ok(())
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
        let base = if cfg!(windows) {
            "C:\\tmp\\openvtc-test"
        } else {
            "/tmp/openvtc-test"
        };
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base) };
        let path = get_config_path("default").unwrap();
        let mut expected = PathBuf::from(base);
        expected.push("config.json");
        assert_eq!(path, expected);
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_named_profile() {
        let _guard = ENV_LOCK.lock().unwrap();
        let base = if cfg!(windows) {
            "C:\\tmp\\openvtc-test"
        } else {
            "/tmp/openvtc-test"
        };
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base) };
        let path = get_config_path("work").unwrap();
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
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base_with) };
        let path_with = get_config_path("default").unwrap();
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base_without) };
        let path_without = get_config_path("default").unwrap();
        assert_eq!(
            path_with, path_without,
            "trailing slash should not affect the resolved path"
        );
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
        let path = get_config_path("default").unwrap();
        let mut expected_suffix = PathBuf::new();
        expected_suffix.push("openvtc");
        expected_suffix.push("config.json");
        assert!(
            path.ends_with(&expected_suffix),
            "fallback path should end with openvtc/config.json: {}",
            path.display()
        );
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
