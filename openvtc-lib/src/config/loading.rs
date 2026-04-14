//! Configuration loading logic (step 1 and step 2).

use crate::{
    config::{
        Config, ConfigProtectionType, KeyBackend, PersonaDID, UnlockCode,
        protected_config::ProtectedConfig, public_config::PublicConfig,
        secured_config::SecuredConfig,
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
            // Legacy BIP32 config
            let bip32_root = ExtendedSigningKey::from_seed(
                BASE64_URL_SAFE_NO_PAD.decode(bip32_seed)?.as_slice(),
            )
            .map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Couldn't get bip32 root from the secret seed material: {}",
                    e
                ))
            })?;
            KeyBackend::Bip32 {
                root: bip32_root,
                seed: SecretString::new(bip32_seed.clone().into()),
            }
        } else if let Some(ref credential_bundle) = sc.credential_bundle {
            // VTA-managed config
            let bundle = CredentialBundle::decode(credential_bundle).map_err(|e| {
                OpenVTCError::Config(format!("Couldn't decode VTA credential bundle: {:?}", e))
            })?;
            let encryption_seed =
                ProtectedConfig::get_seed_from_credential(&bundle.private_key_multibase)?;
            KeyBackend::Vta {
                credential_bundle: SecretString::new(credential_bundle.clone().into()),
                credential_did: bundle.did.clone(),
                credential_private_key: SecretString::new(
                    bundle.private_key_multibase.clone().into(),
                ),
                vta_did: sc.vta_did.clone().unwrap_or_default(),
                vta_url: sc.vta_url.clone().unwrap_or_default(),
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

        // Authenticate with VTA once upfront (if VTA backend)
        let vta_client = if let KeyBackend::Vta {
            vta_url,
            credential_did,
            credential_private_key,
            vta_did,
            ..
        } = &key_backend
        {
            report_progress(&on_progress, "Authenticating...");
            let token_result = vta_sdk::session::challenge_response(
                vta_url,
                credential_did,
                credential_private_key.expose_secret(),
                vta_did,
            )
            .await
            .map_err(|e| OpenVTCError::Config(format!("VTA authentication failed: {e}")))?;

            let client = vta_sdk::client::VtaClient::new(vta_url);
            client.set_token(token_result.access_token);
            Some(client)
        } else {
            None
        };

        // All config info has been loaded, load DID Document and regenerate keys
        report_progress(&on_progress, "Resolving DID...");
        let rr = tdk
            .did_resolver()
            .resolve(&public_config.persona_did)
            .await
            .map_err(|e| {
                OpenVTCError::Resolver(format!(
                    "Couldn't resolve Persona DID ({}): {}",
                    public_config.persona_did, e
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
            public_config.persona_did.to_string(),
            Some(public_config.mediator_did.clone()),
        )
        .await?;

        // Add the persona profile to the TDK ATM Service
        // This allows it to send/receive messages directly to the Persona DID
        let atm = tdk
            .atm
            .clone()
            .ok_or_else(|| OpenVTCError::Config("TDK ATM service not initialized".to_string()))?;
        let persona_profile = atm.profile_add(&persona_profile, true).await?;

        report_progress(&on_progress, "Loading relationships...");
        let atm_profiles = private_cfg
            .relationships
            .generate_profiles(
                tdk,
                &public_config.persona_did,
                &public_config.mediator_did,
                &key_backend,
                &sc.key_info,
                vta_client.as_ref(),
            )
            .await?;

        // Add all VRC's to the top level list
        let mut vrcs = HashMap::new();
        for relationship in private_cfg.vrcs_issued.values() {
            for (vrc_id, vrc) in relationship.iter() {
                vrcs.insert(vrc_id.clone(), vrc.clone());
            }
        }
        for relationship in private_cfg.vrcs_received.values() {
            for (vrc_id, vrc) in relationship.iter() {
                vrcs.insert(vrc_id.clone(), vrc.clone());
            }
        }

        Ok(Config {
            key_backend,
            persona_did: PersonaDID {
                document: rr.doc,
                profile: persona_profile,
            },
            public: public_config,
            private: private_cfg,
            key_info: sc.key_info.clone(),
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: None,
            #[cfg(feature = "openpgp-card")]
            token_user_pin: token_user_pin.clone(),
            protection_method: sc.protection_method.clone(),
            unlock_code: unlock_passphrase.map(|uc| uc.0.expose_secret().to_owned()),
            atm_profiles,
            vrcs,
        })
    }
}
