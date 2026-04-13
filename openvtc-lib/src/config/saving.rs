//! Configuration saving and export logic.

use crate::{
    config::{
        Config, ConfigProtectionType, ExportedConfig, derive_passphrase_key,
        public_config::PublicConfig,
        secured_config::{SecuredConfig, unlock_code_encrypt},
    },
    errors::OpenVTCError,
    logs::LogFamily,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use dialoguer::{Password, theme::ColorfulTheme};
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
        self.public.save(profile, &self.private, &encryption_seed)?;

        let sc = SecuredConfig::from(self);
        sc.save(
            profile,
            if let ConfigProtectionType::Token(token) = &self.public.protection {
                Some(token)
            } else {
                None
            },
            self.unlock_code.as_ref(),
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        Ok(())
    }

    /// Exports the full configuration (public + secured) to an encrypted file.
    ///
    /// - `passphrase`: Optional passphrase; if `None`, the user is prompted interactively.
    /// - `file`: Destination file path for the base64url-encoded ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if passphrase derivation fails, serialization fails,
    /// encryption fails, or the file cannot be written.
    pub fn export(&self, passphrase: Option<SecretString>, file: &str) -> Result<(), OpenVTCError> {
        let pc = PublicConfig::from(self);
        let sc = SecuredConfig::from(self);

        let seed_bytes = if let Some(passphrase) = passphrase {
            derive_passphrase_key(passphrase.expose_secret().as_bytes(), b"openvtc-export-v1")?
        } else {
            let input = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter passphrase to encrypt exported configuration")
                .with_confirmation("Confirm passphrase", "Passphrases do not match")
                .interact()
                .map_err(|e| OpenVTCError::Config(format!("Failed to read passphrase: {e}")))?;
            derive_passphrase_key(input.as_bytes(), b"openvtc-export-v1")?
        };

        let serialized = serde_json::to_vec(&ExportedConfig { pc, sc })?;
        let secured = unlock_code_encrypt(&seed_bytes, &serialized)?;

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
