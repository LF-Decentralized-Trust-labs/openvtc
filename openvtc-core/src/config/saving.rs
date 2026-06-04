//! Configuration saving and export logic.

use crate::{
    config::{
        Config, ConfigProtectionType, ExportedConfig,
        public_config::PublicConfig,
        secured_config::{SecuredConfig, passphrase_encrypt_v2},
    },
    errors::OpenVTCError,
    logs::LogFamily,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, sync::Arc};
use tracing::warn;

impl Config {
    /// Persists the full configuration (public, protected, and secured) to disk.
    ///
    /// - `profile`: Configuration profile name (determines file paths).
    ///
    /// # Errors
    ///
    /// Returns an error if the encryption seed cannot be derived, or if any
    /// config file fails to write.
    pub fn save(
        &self,
        profile: &str,
        #[cfg(feature = "openpgp-card")] touch_prompt: &(dyn Fn() + Send + Sync),
    ) -> Result<(), OpenVTCError> {
        let encryption_seed = self.get_encryption_seed()?;
        // The v2 `account` is the encrypted source of truth — mirror the live
        // in-memory account into the protected tier so it round-trips to disk.
        let mut private = self.private.clone();
        private.account = self.account.clone();
        self.public.save(profile, &private, &encryption_seed)?;

        let sc = SecuredConfig::from(self);
        sc.save(
            profile,
            if let ConfigProtectionType::Token(token) = &self.public.protection {
                Some(token)
            } else {
                None
            },
            self.unlock_code.as_ref().map(|s| s.expose_secret()),
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        Ok(())
    }

    /// Exports the full configuration (public + secured) to an encrypted file.
    ///
    /// - `passphrase`: Passphrase used to derive the export key. The caller
    ///   is responsible for collecting it; this function is non-interactive
    ///   so it can be used from any binary (TUI, daemon, tests) without
    ///   pulling in a CLI prompt library.
    /// - `file`: Destination file path for the base64url-encoded ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if passphrase derivation fails, serialization fails,
    /// encryption fails, or the file cannot be written.
    pub fn export(&self, passphrase: SecretString, file: &str) -> Result<(), OpenVTCError> {
        let pc = PublicConfig::from(self);
        let sc = SecuredConfig::from(self);

        let serialized = serde_json::to_vec(&ExportedConfig { pc, sc })?;
        // v2: per-export random Argon2 salt, embedded in the magic-prefixed
        // blob so two operators with the same passphrase produce
        // independent ciphertexts (and the same operator exporting twice
        // does too). Decrypt path auto-detects v1/v2 for backward compat
        // with previously-exported files.
        let secured = passphrase_encrypt_v2(
            passphrase.expose_secret().as_bytes(),
            b"openvtc-export-v1",
            &serialized,
        )?;

        fs::write(file, BASE64_URL_SAFE_NO_PAD.encode(&secured)).map_err(|e| {
            OpenVTCError::Config(format!("Couldn't write to file ({file}). Reason: {e}"))
        })?;

        // Restrict file permissions to owner-only on Unix systems
        #[cfg(unix)]
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't set permissions on export file ({file}): {e}"
            ))
        })?;

        warn!("Successfully exported settings to file({file})");
        Ok(())
    }

    /// Handles rejection of a VRC request by logging the event and removing the task.
    pub fn handle_vrc_reject(
        &mut self,
        task_id: &Arc<String>,
        reason: Option<&str>,
        from: &Arc<String>,
    ) -> Result<(), OpenVTCError> {
        let reason = if let Some(reason) = reason {
            reason.to_string()
        } else {
            "NO REASON PROVIDED".to_string()
        };

        self.public.logs.insert(
            LogFamily::Relationship,
            format!(
                "Removed VRC ({}) request as rejected by remote entity Reason: {}",
                task_id, reason
            ),
        );

        self.private.tasks.remove(task_id);

        self.public.logs.insert(
            LogFamily::Task,
            format!(
                "VRC request rejected by remote DID({}) Task ID({}) Reason({})",
                from, task_id, reason
            ),
        );

        Ok(())
    }
}
