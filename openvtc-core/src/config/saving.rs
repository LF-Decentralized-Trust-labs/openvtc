//! Configuration saving and export logic.

use crate::{
    config::{
        Config, ConfigProtectionType, ExportedConfig, KeyBackend,
        public_config::PublicConfig,
        secured_config::{SecuredConfig, passphrase_encrypt_v2_blocking},
    },
    errors::OpenVTCError,
    logs::LogFamily,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek_bip32::ExtendedSigningKey;
use secrecy::{ExposeSecret, SecretBox, SecretString};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeMap, fs, sync::Arc};
use tracing::warn;

/// Deep-clone a [`KeyBackend`] for a save snapshot.
///
/// Re-wraps the non-`Clone` `SecretBox<Vec<u8>>` encryption seed by value, and
/// rebuilds the non-`Clone` BIP32 `ExtendedSigningKey` root from the stored
/// base64url seed exactly as the load path does
/// ([`crate::config::Config::load_step2`]). Used by [`Config::clone_for_save`]
/// to build an owned, `Send`-able save snapshot.
///
/// # Errors
///
/// Returns [`OpenVTCError::BIP32`] if the stored seed cannot be decoded or the
/// root cannot be re-derived from it.
fn clone_key_backend(backend: &KeyBackend) -> Result<KeyBackend, OpenVTCError> {
    Ok(match backend {
        KeyBackend::Bip32 { seed, .. } => {
            // The `ExtendedSigningKey` root is not `Clone` (ed25519-dalek-bip32
            // 0.3), so reconstruct it from the persisted seed, mirroring the load
            // path. The seed is the source of truth and the root is a pure
            // function of it, so the snapshot's root is identical to the live one.
            let root = ExtendedSigningKey::from_seed(
                BASE64_URL_SAFE_NO_PAD
                    .decode(seed.expose_secret())
                    .map_err(|e| {
                        OpenVTCError::BIP32(format!("Couldn't decode BIP32 seed for save: {e}"))
                    })?
                    .as_slice(),
            )
            .map_err(|e| {
                OpenVTCError::BIP32(format!("Couldn't rebuild BIP32 root for save: {e}"))
            })?;
            KeyBackend::Bip32 {
                root,
                seed: seed.clone(),
            }
        }
        KeyBackend::Vta {
            credential_bundle,
            credential_did,
            credential_private_key,
            vta_did,
            vta_url,
            mediator_did,
            encryption_seed,
        } => KeyBackend::Vta {
            credential_bundle: credential_bundle.clone(),
            credential_did: credential_did.clone(),
            credential_private_key: credential_private_key.clone(),
            vta_did: vta_did.clone(),
            vta_url: vta_url.clone(),
            mediator_did: mediator_did.clone(),
            encryption_seed: SecretBox::new(Box::new(encryption_seed.expose_secret().clone())),
        },
    })
}

impl Config {
    /// Produce an owned, `Send + 'static` snapshot of everything [`Config::save`]
    /// reads, so the (blocking) serialize + encrypt + file/keyring/card I/O can be
    /// moved off the async runtime onto a `spawn_blocking` thread (R11).
    ///
    /// `Config` is deliberately not `Clone` (it holds non-`Clone`
    /// `SecretBox<Vec<u8>>` secrets and runtime-only `identities`), so this
    /// deep-clones the persisted tiers and re-wraps the secret material by value.
    /// The `identities` map is *not* persisted — it is rebuilt at load — so it is
    /// dropped from the snapshot (replaced with an empty map) rather than cloned.
    ///
    /// The snapshot is taken on the loop thread (the single mutator) and then
    /// owned by the blocking closure: the live `Config` is never borrowed across
    /// an `.await`, preserving the single-mutator / unidirectional-data-flow
    /// invariant.
    ///
    /// Note: the per-record `Arc<Mutex<Relationship>>` / `Arc<Mutex<Task>>` inside
    /// the protected tier are clone-of-`Arc` (the snapshot *shares* those Mutexes
    /// with the live config), not deep copies. This is intentional and safe: each
    /// record's `Mutex` gives per-record exclusion, so a concurrent loop-thread
    /// mutation can never tear a single record mid-serialize; and any post-snapshot
    /// mutation re-runs `mark_dirty()`, so cross-record skew self-heals via the next
    /// coalesced save (and the shutdown force-flush captures the final state). The
    /// loop never holds a record lock across the `.await` where a save is spawned,
    /// so there is no deadlock between the save thread and the loop.
    ///
    /// # Errors
    ///
    /// Returns [`OpenVTCError::BIP32`] if a BIP32 backend's root cannot be
    /// rebuilt from its seed (the same failure the load path would surface).
    pub fn clone_for_save(&self) -> Result<Config, OpenVTCError> {
        Ok(Config {
            public: self.public.clone(),
            private: self.private.clone(),
            key_backend: clone_key_backend(&self.key_backend)?,
            key_info: self.key_info.clone(),
            protection_method: self.protection_method.clone(),
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: self.token_admin_pin.clone(),
            #[cfg(feature = "openpgp-card")]
            token_user_pin: self.token_user_pin.clone(),
            unlock_code: self
                .unlock_code
                .as_ref()
                .map(|s| SecretBox::new(Box::new(s.expose_secret().clone()))),
            account: self.account.clone(),
            // Runtime-only; rebuilt at load and unused by `save`.
            identities: BTreeMap::new(),
        })
    }

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
    ///
    /// R12: the Argon2id key derivation inside `passphrase_encrypt_v2` (~0.5–1 s
    /// of pure CPU) runs on a `spawn_blocking` thread via
    /// [`passphrase_encrypt_v2_blocking`] so the export does not peg the async
    /// event-loop / render task while the key is derived. The per-export random
    /// salt and the resulting blob are unchanged from the sync path.
    pub async fn export(&self, passphrase: SecretString, file: &str) -> Result<(), OpenVTCError> {
        let pc = PublicConfig::from(self);
        let sc = SecuredConfig::from(self);

        let serialized = serde_json::to_vec(&ExportedConfig { pc, sc })?;
        // v2: per-export random Argon2 salt, embedded in the magic-prefixed
        // blob so two operators with the same passphrase produce
        // independent ciphertexts (and the same operator exporting twice
        // does too). Decrypt path auto-detects v1/v2 for backward compat
        // with previously-exported files.
        //
        // Own the exposed passphrase bytes so they move into the blocking
        // closure (and zeroize there); `serialized` is also moved in. Neither
        // is logged or surfaced in an error.
        let secured = passphrase_encrypt_v2_blocking(
            passphrase.expose_secret().as_bytes().to_vec(),
            b"openvtc-export-v1".to_vec(),
            serialized,
        )
        .await?;

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
