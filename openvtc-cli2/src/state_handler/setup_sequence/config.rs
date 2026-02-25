/*! Contains specific Config extensions for the CLI Application. */

use affinidi_tdk::{TDK, messaging::profiles::ATMProfile};
use anyhow::{Result, bail};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek_bip32::ExtendedSigningKey;
use openvtc::{
    LF_ORG_DID, LF_PUBLIC_MEDIATOR_DID,
    config::{
        Config, ConfigProtectionType, ExportedConfig, KeyBackend, KeyTypes, PersonaDID,
        protected_config::ProtectedConfig,
        public_config::PublicConfig,
        secured_config::{KeyInfoConfig, ProtectionMethod, unlock_code_decrypt},
    },
    logs::{LogFamily, LogMessage, Logs},
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    sync::Arc,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    state_handler::{
        setup_sequence::{ConfigProtection, MessageType, SetupState},
        state::State,
    },
    ui::pages::setup_flow::SetupFlow,
};

pub trait ConfigExtension {
    /// Imports a backup of openvtc configuration settings from an encrypted file
    /// state: OpenVTC backend state
    /// state_tx: State update channel transmitter
    /// import_unlock_passphrase: Passphrase used to decrypt the imported configuration
    /// new_unlock_passphrase: New passphrase to protect the imported configuration
    /// file: Path to the file containing the exported configuration
    /// profile: Profile name to import the configuration into
    fn import(
        state: &mut State,
        state_tx: &UnboundedSender<State>,
        import_unlock_passphrase: &SecretString,
        new_unlock_passphrase: &SecretString,
        file: &str,
        profile: &str,
    ) -> Result<()>;

    /// Creates a new Config instance based on the setup state
    /// Saves this to disk and returns the created Config
    async fn create(
        state: &SetupState,
        setup_flow: &SetupFlow,
        tdk: &TDK,
        profile: &str,
    ) -> Result<Config>;
}

impl ConfigExtension for Config {
    /// Import previously exported configuration settings from an encrypted file
    fn import(
        state: &mut State,
        state_tx: &UnboundedSender<State>,
        import_unlock_passphrase: &SecretString,
        new_unlock_passphrase: &SecretString,
        file: &str,
        profile: &str,
    ) -> Result<()> {
        let content = match fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                state
                    .setup
                    .config_import
                    .messages
                    .push(MessageType::Error(format!(
                        "Couldn't read from file ({file}). Reason: {e}"
                    )));
                let _ = state_tx.send(state.clone());
                bail!("File read error");
            }
        };

        let decoded = match BASE64_URL_SAFE_NO_PAD.decode(content) {
            Ok(decoded) => decoded,
            Err(e) => {
                state
                    .setup
                    .config_import
                    .messages
                    .push(MessageType::Error(format!(
                        "Couldn't base64 decode file content. Reason: {e}"
                    )));
                let _ = state_tx.send(state.clone());
                bail!("base64 decoding error");
            }
        };

        let seed_bytes = Sha256::digest(import_unlock_passphrase.expose_secret())
            .first_chunk::<32>()
            .expect("Couldn't get 32 bytes for passphrase hash")
            .to_owned();

        let decoded = unlock_code_decrypt(&seed_bytes, &decoded)?;

        let config: ExportedConfig = match serde_json::from_slice(&decoded) {
            Ok(config) => config,
            Err(e) => {
                state
                    .setup
                    .config_import
                    .messages
                    .push(MessageType::Error(format!(
                        "Couldn't deserialize configuration settings. Reason: {e}"
                    )));
                let _ = state_tx.send(state.clone());
                bail!("deserialization error");
            }
        };

        let bip32_seed = config.sc.bip32_seed.as_ref()
            .expect("Imported config missing BIP32 seed");
        let bip32_root = ExtendedSigningKey::from_seed(
            BASE64_URL_SAFE_NO_PAD
                .decode(bip32_seed)
                .expect("Couldn't base64 decode BIP32 seed")
                .as_slice(),
        )?;
        let private_seed = ProtectedConfig::get_seed(&bip32_root, "m/0'/0'/0'")?;

        let private = if let Some(private) = &config.pc.private {
            ProtectedConfig::load(&private_seed, private)?
        } else {
            ProtectedConfig::default()
        };

        config
            .pc
            .save(profile, &private, &private_seed)
            .expect("Couldn't save Public Config");

        #[cfg(feature = "openpgp-card")]
        {
            let state_clone = state.clone();
            let state_tx_clone = state_tx.clone();
            config
                .sc
                .save(
                    profile,
                    if let ConfigProtectionType::Token(token) = &config.pc.protection {
                        Some(token)
                    } else {
                        None
                    },
                    Some(
                        &sha2::Sha256::digest(new_unlock_passphrase.expose_secret().as_bytes())
                            .to_vec(),
                    ),
                    &move || {
                        let mut state_mut = state_clone.clone();
                        state_mut
                            .setup
                            .config_import
                            .messages
                            .push(MessageType::Info(
                                "Please touch token hardware to unlock keys".to_string(),
                            ));
                        let _ = state_tx_clone.send(state_mut);
                    },
                )
                .expect("Couldn't save Secured Config");
        }

        #[cfg(not(feature = "openpgp-card"))]
        config
            .sc
            .save(
                profile,
                if let ConfigProtectionType::Token(token) = &config.pc.protection {
                    Some(token)
                } else {
                    None
                },
                Some(&new_unlock_passphrase.expose_secret().as_bytes().to_vec()),
            )
            .expect("Couldn't save Secured Config");

        Ok(())
    }

    async fn create(
        state: &SetupState,
        setup_flow: &SetupFlow,
        tdk: &TDK,
        profile: &str,
    ) -> Result<Config> {
        // Initial Configuration state

        let mut unlock_code = None;
        let protection = match &state.protection {
            ConfigProtection::PlainText => ConfigProtectionType::Plaintext,
            ConfigProtection::Token(token) => ConfigProtectionType::Token(token.to_string()),
            ConfigProtection::Passcode(unlock) => {
                unlock_code = Some(unlock.expose_secret().to_vec());
                ConfigProtectionType::Encrypted
            }
        };

        let mediator_did = if let Some(mediator) = &state.custom_mediator {
            mediator.to_string()
        } else {
            LF_PUBLIC_MEDIATOR_DID.to_string()
        };

        // Build key info from persona keys
        let mut key_info = HashMap::new();
        let persona_keys = state.did_keys.clone().unwrap();
        key_info.insert(
            persona_keys.signing.secret.id.clone(),
            KeyInfoConfig {
                path: persona_keys.signing.source.clone(),
                create_time: persona_keys.signing.created,
                purpose: KeyTypes::PersonaSigning,
            },
        );
        key_info.insert(
            persona_keys.authentication.secret.id.clone(),
            KeyInfoConfig {
                path: persona_keys.authentication.source.clone(),
                create_time: persona_keys.authentication.created,
                purpose: KeyTypes::PersonaAuthentication,
            },
        );
        key_info.insert(
            persona_keys.decryption.secret.id.clone(),
            KeyInfoConfig {
                path: persona_keys.decryption.source.clone(),
                create_time: persona_keys.decryption.created,
                purpose: KeyTypes::PersonaEncryption,
            },
        );

        // Build VTA key backend from setup state
        let credential_raw = state.vta.credential_bundle_raw.clone()
            .expect("VTA credential bundle not set");
        let bundle = crate::state_handler::setup_sequence::vta::decode_credential(&credential_raw)
            .expect("Failed to decode credential bundle");
        let encryption_seed = ProtectedConfig::get_seed_from_credential(&bundle.private_key_multibase)?;
        let key_backend = KeyBackend::Vta {
            credential_bundle: SecretString::new(credential_raw),
            credential_did: bundle.did.clone(),
            credential_private_key: SecretString::new(bundle.private_key_multibase.clone()),
            vta_did: bundle.vta_did.clone(),
            vta_url: bundle.vta_url.clone().unwrap_or_default(),
            encryption_seed,
        };

        let config = Config {
            key_backend,
            public: PublicConfig {
                protection,
                persona_did: Arc::new(state.webvh_address.did.clone()),
                mediator_did: mediator_did.clone(),
                private: None,
                logs: Logs {
                    messages: VecDeque::from([LogMessage {
                        created: Utc::now(),
                        type_: LogFamily::Config,
                        message: "Initial openvtc setup completed".to_string(),
                    }]),
                    ..Default::default()
                },
                friendly_name: setup_flow.username.username.value().to_string(),
                lk_did: LF_ORG_DID.to_string(),
            },
            private: ProtectedConfig::default(),
            persona_did: PersonaDID {
                document: state.webvh_address.document.clone(),
                profile: Arc::new(
                    ATMProfile::new(
                        tdk.atm.as_ref().unwrap(),
                        Some("Persona DID".to_string()),
                        state.webvh_address.did.to_string(),
                        Some(mediator_did.clone()),
                    )
                    .await?,
                ),
            },
            key_info,
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: None,
            #[cfg(feature = "openpgp-card")]
            token_user_pin: SecretString::new(String::new()),
            protection_method: ProtectionMethod::default(),
            unlock_code,
            atm_profiles: HashMap::new(),
            vrcs: HashMap::new(),
        };

        config.save(
            profile,
            #[cfg(feature = "openpgp-card")]
            &|| {
                eprintln!("Touch confirmation needed for decryption");
            },
        )?;

        Ok(config)
    }
}
