/*! Handles the setup of the openvtc CLI tool
*/

#[cfg(feature = "openpgp-card")]
use crate::setup::openpgp_card::setup_hardware_token;
use crate::{
    CLI_BLUE, CLI_GREEN, CLI_PURPLE,
    setup::{
        bip32_bip39::{generate_bip39_mnemonic, mnemonic_from_recovery_phrase},
        did::did_setup,
        pgp_export::ask_export_persona_did_keys,
        pgp_import::{PGPKeys, terminal_input_pgp_key},
    },
};
use affinidi_tdk::{TDK, common::config::TDKConfig, messaging::profiles::ATMProfile};
use anyhow::Result;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use bip39::Mnemonic;
use chrono::Utc;
use console::{Term, style};
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use openvtc::{
    KeyPurpose, LF_ORG_DID, LF_PUBLIC_MEDIATOR_DID,
    bip32::{Bip32Extension, get_bip32_root},
    config::{
        Config, ConfigProtectionType, KeyBackend, KeyInfo, KeyTypes, PersonaDID, PersonaDIDKeys,
        protected_config::ProtectedConfig,
        public_config::PublicConfig,
        secured_config::{KeyInfoConfig, KeySourceMaterial, ProtectionMethod},
    },
    logs::{LogFamily, LogMessage, Logs},
};
use secrecy::SecretString;
use sha2::Digest;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

pub mod bip32_bip39;
mod did;
#[cfg(feature = "openpgp-card")]
mod openpgp_card;
pub mod pgp_export;
mod pgp_import;

/// Sets up the CLI tool
pub async fn cli_setup(term: &Term, profile: &str) -> Result<()> {
    println!(
        "{}",
        style("Initial setup of the openvtc tool").color256(CLI_GREEN)
    );
    println!();

    let mut imported_bip32 = false;
    // Are we recovering from a Recovery Phrase?
    let mnemonic = if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Recover Secrets from 24 word recovery phrase?")
        .default(false)
        .interact()
        .unwrap()
    {
        // Using Recovery Phrase
        imported_bip32 = true;
        mnemonic_from_recovery_phrase()?
    } else {
        generate_bip39_mnemonic()
    };

    let imported_keys = if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Use (import) existing PGP keys?")
        .default(false)
        .interact()
        .unwrap()
    {
        // Import PGP Secret key material
        terminal_input_pgp_key()?
    } else {
        PGPKeys::default()
    };

    // Creating new Secrets for the Persona DID
    let mut p_did_keys = create_keys(&mnemonic, &imported_keys)?;

    // Export this as an armored PGP Keyfile?
    if imported_keys.is_empty() {
        ask_export_persona_did_keys(term, &p_did_keys, None, None, true);
    }

    // Use hardware token?
    #[cfg(feature = "openpgp-card")]
    let token_id = {
        use dialoguer::Password;

        let admin_pin = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Please enter Token Admin PIN <blank = default>")
            .allow_empty_password(true)
            .interact()
            .unwrap();
        let admin_pin = if admin_pin.is_empty() {
            SecretString::new("12345678".to_string())
        } else {
            SecretString::new(admin_pin)
        };
        setup_hardware_token(term, &admin_pin, &p_did_keys)?
    };
    #[cfg(not(feature = "openpgp-card"))]
    let token_id = None;

    // If hardware token is not being used, then ask for an unlock code
    let unlock_code = if token_id.is_none() {
        // Check if an unlock code is desired?
        create_unlock_code().map(|c| c.to_vec())
    } else {
        // No need for an unlock code when using hardware token
        None
    };

    // Use a different Mediator?
    let mediator_did = change_mediator();

    let lk_did = change_lf_did();

    // Create a DID - will also rename the P-DID Keys with the right key-IDS
    let p_did = did_setup(
        get_bip32_root(mnemonic.to_entropy().as_slice())?,
        &mut p_did_keys,
        &mediator_did,
        imported_bip32,
    )
    .await?;

    // Create Configuration
    let mut key_info = HashMap::new();
    key_info.insert(
        p_did_keys.signing.secret.id.clone(),
        KeyInfoConfig {
            path: p_did_keys.signing.source.clone(),
            create_time: p_did_keys.signing.created,
            purpose: KeyTypes::PersonaSigning,
        },
    );
    key_info.insert(
        p_did_keys.authentication.secret.id.clone(),
        KeyInfoConfig {
            path: p_did_keys.authentication.source.clone(),
            create_time: p_did_keys.authentication.created,
            purpose: KeyTypes::PersonaAuthentication,
        },
    );
    key_info.insert(
        p_did_keys.decryption.secret.id.clone(),
        KeyInfoConfig {
            path: p_did_keys.decryption.source.clone(),
            create_time: p_did_keys.decryption.created,
            purpose: KeyTypes::PersonaEncryption,
        },
    );

    println!("{}", style("Please enter a name for yourself, this is used to give a human readable name to your DID and Verifiable Relationship Credentials.").color256(CLI_BLUE));
    let friendly_name = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter a name for yourself")
        .interact_text()
        .unwrap();

    // Instantiate TDK
    let tdk = TDK::new(
        TDKConfig::builder().with_load_environment(false).build()?,
        None,
    )
    .await?;

    let protection = if let Some(token) = token_id {
        ConfigProtectionType::Token(token)
    } else if unlock_code.is_some() {
        ConfigProtectionType::Encrypted
    } else {
        ConfigProtectionType::Plaintext
    };

    // Initial Configuration state
    let config = Config {
        key_backend: KeyBackend::Bip32 {
            root: get_bip32_root(mnemonic.to_entropy().as_slice())?,
            seed: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(mnemonic.to_entropy())),
        },
        public: PublicConfig {
            protection,
            persona_did: p_did.did.clone(),
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
            friendly_name,
            lk_did,
        },
        private: ProtectedConfig::default(),
        persona_did: PersonaDID {
            document: p_did.document,
            profile: Arc::new(
                ATMProfile::new(
                    tdk.atm.as_ref().unwrap(),
                    Some("Persona DID".to_string()),
                    p_did.did.to_string(),
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

    println!("{}", style("Next Steps:").color256(CLI_BLUE));
    println!(
        "\t{}",
        style("1. Publish your DID and ensure it is publicly accessible").color256(CLI_BLUE)
    );
    println!(
        "\t{}{}{}",
        style("2. Run ").color256(CLI_BLUE),
        style("openvtc status").color256(CLI_GREEN),
        style(" to ensure everything is ok").color256(CLI_BLUE)
    );
    println!("\t{}", style("3. Get verified!").color256(CLI_BLUE));

    Ok(())
}

/// Creates the Secret Key Material required
/// Returns the created Secrets and their source material
fn create_keys(mnemonic: &Mnemonic, imported_keys: &PGPKeys) -> Result<PersonaDIDKeys> {
    let bip32_root = get_bip32_root(mnemonic.to_entropy().as_slice())?;

    println!(
        "{}",
        style(
            "BIP32 Master Key successfully loaded. All necessary keys will be derived from this Key"
        )
        .color256(CLI_BLUE)
    );

    // Signing key
    let signing = if let Some(signing) = &imported_keys.signing {
        // use imported key
        signing.clone()
    } else {
        let mut sign_secret = bip32_root.get_secret_from_path("m/1'/0'/0'", KeyPurpose::Signing)?;

        sign_secret.id = sign_secret.get_public_keymultibase()?;

        println!(
            "{} {}",
            style("Signing Key (Ed25519) created:").color256(CLI_BLUE),
            style(&sign_secret.id).color256(CLI_GREEN)
        );

        KeyInfo {
            secret: sign_secret,
            source: KeySourceMaterial::Derived {
                path: "m/1'/0'/0'".to_string(),
            },
            expiry: None,
            created: Utc::now(),
        }
    };

    // Authentication key
    let authentication = if let Some(authentication) = &imported_keys.authentication {
        // use imported key
        authentication.clone()
    } else {
        let mut auth_secret =
            bip32_root.get_secret_from_path("m/1'/0'/1'", KeyPurpose::Authentication)?;

        auth_secret.id = auth_secret.get_public_keymultibase()?;

        println!(
            "{} {}",
            style("Authentication Key (Ed25519) created:").color256(CLI_BLUE),
            style(&auth_secret.id).color256(CLI_GREEN)
        );

        KeyInfo {
            secret: auth_secret,
            source: KeySourceMaterial::Derived {
                path: "m/1'/0'/1'".to_string(),
            },
            expiry: None,
            created: Utc::now(),
        }
    };

    // Encryption key
    let encryption = if let Some(encryption) = &imported_keys.encryption {
        // use imported key
        encryption.clone()
    } else {
        let mut enc_secret =
            bip32_root.get_secret_from_path("m/1'/0'/2'", KeyPurpose::Encryption)?;

        enc_secret.id = enc_secret.get_public_keymultibase()?;

        println!(
            "{} {}",
            style("Encryption Key (X25519) created:").color256(CLI_BLUE),
            style(&enc_secret.id).color256(CLI_GREEN)
        );
        KeyInfo {
            secret: enc_secret,
            source: KeySourceMaterial::Derived {
                path: "m/1'/0'/2'".to_string(),
            },
            expiry: None,
            created: Utc::now(),
        }
    };

    Ok(PersonaDIDKeys {
        signing,
        authentication,
        decryption: encryption,
    })
}

/// Generates a sha256 hash of an unlock code if required
pub fn create_unlock_code() -> Option<[u8; 32]> {
    println!("{}", style("NOTE: You are not using any hardware token. While secret information will be stored in your OS secure store where possible, it is best practice to protect this data with an unlock code.").color256(CLI_BLUE));
    println!("  {}", style("This unlock code is asked on application start so it can unlock secret configuration data required.").color256(CLI_BLUE));

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Would you like to set an unlock code to protect your secrets?")
        .default(true)
        .interact()
        .unwrap()
    {
        // Get unlock code from terminal
        let unlock_code: String = dialoguer::Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter Unlock Code")
            .with_confirmation("Confirm Unlock Code", "Unlock Codes do not match")
            .interact()
            .unwrap();

        // Create SHA2-256 hash of the unlock code
        Some(sha2::Sha256::digest(unlock_code.as_bytes()).into())
    } else {
        None
    }
}

/// Do you want to use an alternative mediator?
fn change_mediator() -> String {
    println!();
    println!("{}", style("openvtc utilizes DIDComm protocol to communicate. openvtc requires the use of a DIDComm Mediator to store and forward messages between parties privately and securely").color256(CLI_BLUE));
    println!(
        "{} {}",
        style("Default Mediator:").color256(CLI_BLUE),
        style(LF_PUBLIC_MEDIATOR_DID).color256(CLI_PURPLE),
    );

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you want to use an alternative DIDComm Mediator?")
        .default(false)
        .interact()
        .unwrap()
    {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("DIDComm Mediator DID:")
            .interact()
            .unwrap()
    } else {
        LF_PUBLIC_MEDIATOR_DID.to_string()
    }
}

/// Do you want to use an alternative LF DID?
fn change_lf_did() -> String {
    println!();
    println!("{}", style("openvtc interacts with the Linux Foundation , Linux Foundation is represented by a well-known DID. Do not change the following unless you know what you are doing!").color256(CLI_BLUE));
    println!(
        "{} {}",
        style("Default Linux Foundation DID:").color256(CLI_BLUE),
        style(LF_ORG_DID).color256(CLI_PURPLE),
    );

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you want to use an alternative Linux Foundation DID?")
        .default(false)
        .interact()
        .unwrap()
    {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Linux Foundation DID:")
            .interact()
            .unwrap()
    } else {
        LF_ORG_DID.to_string()
    }
}
