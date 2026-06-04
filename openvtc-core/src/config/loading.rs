//! Configuration loading logic (step 1 and step 2).

use crate::{
    config::{
        Config, ConfigProtectionType, KeyBackend, UnlockCode, protected_config::ProtectedConfig,
        public_config::PublicConfig, secured_config::SecuredConfig,
    },
    errors::OpenVTCError,
};
use affinidi_tdk::{TDK, messaging::profiles::ATMProfile};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek_bip32::ExtendedSigningKey;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::collections::HashMap;
use tracing::{info, warn};
use vta_sdk::credentials::CredentialBundle;

#[cfg(feature = "openpgp-card")]
use super::TokenInteractions;

impl Config {
    /// Step 1 of loading the configuration: reads the public config from disk.
    ///
    /// Use this to inspect [`PublicConfig::protection`] and determine what additional
    /// credentials (passphrase, OpenPGP card PIN, etc.) are needed for step 2.
    ///
    /// # Errors
    ///
    /// Returns an error if the public config file cannot be read or deserialized.
    pub fn load_step1(profile: &str) -> Result<PublicConfig, OpenVTCError> {
        PublicConfig::load(profile)
    }

    /// Step 2 of loading the configuration: decrypts secrets, resolves the DID,
    /// regenerates keys, and builds the full [`Config`].
    ///
    /// Requires the [`PublicConfig`] from [`Config::load_step1`] plus any unlock
    /// credentials determined by the protection type.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails, the BIP32 seed or VTA credential
    /// bundle is invalid, DID resolution fails, key regeneration fails, or
    /// ATM profile creation fails.
    pub async fn load_step2(
        tdk: &mut TDK,
        profile: &str,
        public_config: PublicConfig,
        unlock_passphrase: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] token_user_pin: &SecretString,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
        on_progress: Option<&(dyn Fn(&str) + Send + Sync)>,
    ) -> Result<Self, OpenVTCError> {
        use tracing::debug;

        fn report_progress(on_progress: &Option<&(dyn Fn(&str) + Send + Sync)>, msg: &str) {
            if let Some(f) = on_progress {
                f(msg);
            }
        }

        report_progress(&on_progress, "Decrypting secrets...");

        let sc = SecuredConfig::load(
            profile,
            #[cfg(feature = "openpgp-card")]
            token_user_pin,
            if let ConfigProtectionType::Token(token) = &public_config.protection {
                Some(token)
            } else {
                None
            },
            unlock_passphrase,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        debug!(
            "Secured Config loaded (key_info entries: {})",
            sc.key_info.len()
        );

        // Determine key backend from secured config
        let key_backend = if let Some(ref bip32_seed) = sc.bip32_seed {
            // Legacy BIP32 config — call .expose_secret() to get the inner &str.
            let bip32_root = ExtendedSigningKey::from_seed(
                BASE64_URL_SAFE_NO_PAD
                    .decode(bip32_seed.expose_secret())?
                    .as_slice(),
            )
            .map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Couldn't get bip32 root from the secret seed material: {}",
                    e
                ))
            })?;
            KeyBackend::Bip32 {
                root: bip32_root,
                seed: bip32_seed.clone(),
            }
        } else if let Some(ref credential_bundle) = sc.credential_bundle {
            // VTA-managed config — expose only at the point of decoding.
            let bundle: CredentialBundle = serde_json::from_str(credential_bundle.expose_secret())
                .map_err(|e| {
                    OpenVTCError::Config(format!("Couldn't decode VTA credential bundle: {e}"))
                })?;
            let encryption_seed =
                ProtectedConfig::get_seed_from_credential(&bundle.private_key_multibase)?;
            KeyBackend::Vta {
                credential_bundle: credential_bundle.clone(),
                credential_did: bundle.did.clone(),
                credential_private_key: SecretString::new(
                    bundle.private_key_multibase.clone().into(),
                ),
                vta_did: sc.vta_did.clone().unwrap_or_default(),
                vta_url: sc.vta_url.clone().unwrap_or_default(),
                mediator_did: sc.mediator_did.clone(),
                encryption_seed,
            }
        } else {
            return Err(OpenVTCError::Config(
                "SecuredConfig has neither bip32_seed nor credential_bundle".to_string(),
            ));
        };

        // Get the encryption seed for ProtectedConfig
        let encryption_seed = match &key_backend {
            KeyBackend::Bip32 { root, .. } => ProtectedConfig::get_seed(root, "m/0'/0'/0'")?,
            KeyBackend::Vta {
                encryption_seed, ..
            } => SecretBox::new(Box::new(encryption_seed.expose_secret().to_vec())),
        };

        // Unencrypt the private config data, with migration from legacy seed
        let (private_cfg, needs_migration) = if let Some(private_cfg_str) = &public_config.private {
            match ProtectedConfig::load(&encryption_seed, private_cfg_str) {
                Ok(cfg) => (cfg, false),
                Err(_) => {
                    // Try legacy seed (pre-0.1.4 used verifying key instead of signing key)
                    if let KeyBackend::Bip32 { root, .. } = &key_backend {
                        let legacy_seed = ProtectedConfig::get_seed_legacy(root, "m/0'/0'/0'")?;
                        match ProtectedConfig::load(&legacy_seed, private_cfg_str) {
                            Ok(cfg) => {
                                warn!(
                                    "Config was encrypted with legacy seed — will be \
                                         re-encrypted with the new seed on next save"
                                );
                                (cfg, true)
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        return Err(OpenVTCError::Decrypt(
                            "Failed to decrypt protected config".to_string(),
                        ));
                    }
                }
            }
        } else {
            (ProtectedConfig::default(), false)
        };

        // If migrating from legacy seed, flag for re-encryption on next save
        if needs_migration {
            info!("Config will be re-encrypted with the updated seed derivation on next save");
        }

        debug!("Private Config\n{:#?}", private_cfg);

        // The v2 `account` persisted in the protected tier is the source of
        // truth. v1 (singleton) configs are reset before reaching here
        // (D13/R-RST), so a loadable config always carries an account.
        let account = private_cfg.account.clone();

        // Build the VTA client once upfront (if VTA backend), reusing whichever
        // transport setup chose: DIDComm if a mediator was advertised, REST
        // otherwise. Needed for runtime VTA operations whether or not a persona
        // is present.
        let vta_client = if matches!(&key_backend, KeyBackend::Vta { .. }) {
            report_progress(&on_progress, "Authenticating...");
            Some(super::build_runtime_vta_client(&key_backend).await?)
        } else {
            None
        };

        // Resolve runtime identities from the account's personas.
        //
        // A State-A (account-bootstrap, R-A-5) account persists with NO persona:
        // the app loads to a "no active community" state and a persona is minted
        // later in a State-B join. Such an account has no DID to resolve and no
        // persona/relationship messaging profiles to register, so the whole
        // resolve/keygen/profile block is skipped and `identities` stays empty.
        // A State-B account currently carries a single persona, resolved here.
        let active_persona = account.personas.values().next().map(|p| {
            (
                p.persona_id,
                std::sync::Arc::new(p.did.clone()),
                p.mediator_did.clone().unwrap_or_default(),
            )
        });

        let mut identities = HashMap::new();
        if let Some((active_persona_id, active_persona_did, active_mediator_did)) = active_persona {
            // All config info has been loaded, load DID Document and regenerate keys
            report_progress(&on_progress, "Resolving DID...");
            let rr = tdk
                .did_resolver()
                .resolve(&active_persona_did)
                .await
                .map_err(|e| {
                    OpenVTCError::Resolver(format!(
                        "Couldn't resolve Persona DID ({active_persona_did}): {e}"
                    ))
                })?;

            // Create keys from DID Document
            report_progress(&on_progress, "Loading keys...");
            Config::regenerate_persona_keys(tdk, &sc, &key_backend, &rr.doc, vta_client.as_ref())
                .await?;

            // Create persona profile
            report_progress(&on_progress, "Creating messaging profiles...");
            let persona_profile = ATMProfile::new(
                tdk.atm.as_ref().ok_or_else(|| {
                    OpenVTCError::Config("TDK ATM service not initialized".to_string())
                })?,
                Some("Persona DID".to_string()),
                active_persona_did.to_string(),
                Some(active_mediator_did.clone()),
            )
            .await?;

            // Register the persona profile with the TDK ATM Service but do NOT
            // open a WebSocket connection. The DIDComm service manages its own
            // connections — connecting here would create a duplicate WebSocket for
            // the same DID, triggering the mediator's duplicate detection loop.
            let atm = tdk.atm.clone().ok_or_else(|| {
                OpenVTCError::Config("TDK ATM service not initialized".to_string())
            })?;
            let persona_profile = atm.profile_add(&persona_profile, false).await?;

            report_progress(&on_progress, "Loading relationships...");
            // Registers each relationship profile with the ATM service as a
            // side-effect; the returned map is no longer stored on `Config`.
            private_cfg
                .relationships
                .generate_profiles(
                    tdk,
                    &active_persona_did,
                    &active_mediator_did,
                    &key_backend,
                    &sc.key_info,
                    vta_client.as_ref(),
                )
                .await?;

            identities.insert(
                active_persona_id,
                crate::identity::IdentityContext {
                    persona_id: active_persona_id,
                    did: active_persona_did.to_string(),
                    document: rr.doc,
                    profile: persona_profile,
                    mediator_did: Some(active_mediator_did),
                },
            );
        }

        Ok(Config {
            account,
            identities,
            key_backend,
            public: public_config,
            private: private_cfg,
            key_info: sc.key_info.clone(),
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: None,
            #[cfg(feature = "openpgp-card")]
            token_user_pin: token_user_pin.clone(),
            protection_method: sc.protection_method.clone(),
            unlock_code: unlock_passphrase
                .map(|uc| SecretBox::new(Box::new(uc.0.expose_secret().to_owned()))),
        })
    }
}
