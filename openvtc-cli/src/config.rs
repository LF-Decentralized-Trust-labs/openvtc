/*! Contains specific Config extensions for the CLI Application. */

use crate::{
    relationships::RelationshipsExtension, setup::create_unlock_code, CLI_BLUE, CLI_GREEN,
    CLI_ORANGE, CLI_PURPLE, CLI_RED,
};
use anyhow::{bail, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use console::style;
use dialoguer::{theme::ColorfulTheme, Password};
use ed25519_dalek_bip32::ExtendedSigningKey;
use openvtc::{
    config::{
        protected_config::ProtectedConfig, public_config::PublicConfig,
        secured_config::unlock_code_decrypt, Config, ConfigProtectionType, ExportedConfig,
    },
    LF_PUBLIC_MEDIATOR_DID,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::fs;

pub trait ConfigExtension {
    fn import(passphrase: Option<SecretString>, file: &str, profile: &str) -> Result<()>;
    fn status(&self);
}

impl ConfigExtension for Config {
    /// Import previously exported configuration settings from an encrypted file
    fn import(passphrase: Option<SecretString>, file: &str, profile: &str) -> Result<()> {
        let content = match fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                println!(
                    "{}{}{}{}",
                    style("ERROR: Couldn't read from file (").color256(CLI_RED),
                    style(file).color256(CLI_PURPLE),
                    style(". Reason: ").color256(CLI_RED),
                    style(e).color256(CLI_ORANGE)
                );
                bail!("File read error");
            }
        };

        let decoded = match BASE64_URL_SAFE_NO_PAD.decode(content) {
            Ok(decoded) => decoded,
            Err(e) => {
                println!(
                    "{}{}{}",
                    style("ERROR: Couldn't base64 decode file content. Reason: ").color256(CLI_RED),
                    style(e).color256(CLI_ORANGE),
                    style("")
                );
                bail!("base64 decoding error");
            }
        };

        let seed_bytes = if let Some(passphrase) = passphrase {
            Sha256::digest(passphrase.expose_secret())
                .first_chunk::<32>()
                .expect("Couldn't get 32 bytes for passphrase hash")
                .to_owned()
        } else {
            Sha256::digest(
                Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter passphrase to decrypt imported configuration")
                    .interact()
                    .expect("Failed to read passphrase"),
            )
            .first_chunk::<32>()
            .expect("Couldn't get 32 bytes for passphrase hash")
            .to_owned()
        };

        let decoded = unlock_code_decrypt(&seed_bytes, &decoded)?;

        let config: ExportedConfig = match serde_json::from_slice(&decoded) {
            Ok(config) => config,
            Err(e) => {
                println!(
                    "{}{}",
                    style("ERROR: Couldn't deserialize configuration settings. Reason: ")
                        .color256(CLI_RED),
                    style(e).color256(CLI_ORANGE)
                );
                bail!("deserialization error");
            }
        };

        let passphrase = if let ConfigProtectionType::Encrypted = config.pc.protection {
            create_unlock_code()
        } else {
            None
        };

        let bip32_seed = config
            .sc
            .bip32_seed
            .as_ref()
            .expect("Imported config does not contain a BIP32 seed (VTA configs cannot be imported via CLI)");
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
        config
            .sc
            .save(
                profile,
                if let ConfigProtectionType::Token(token) = &config.pc.protection {
                    Some(token)
                } else {
                    None
                },
                passphrase.map(|pp| pp.to_vec()).as_ref(),
                #[cfg(feature = "openpgp-card")]
                &|| {
                    eprintln!("Touch confirmation needed for decryption");
                },
            )
            .expect("Couldn't save Public Config");

        println!(
            "{}",
            style("Successfully imported openvtc configuration settings").color256(CLI_GREEN)
        );

        Ok(())
    }

    /// Prints information relating to the configuration to console
    fn status(&self) {
        println!("{}", style("Configured Keys:").color256(CLI_BLUE));
        for (k, v) in &self.key_info {
            println!(
                "  {} {}\n    {} {} {} {}",
                style("Key #id:").color256(CLI_BLUE),
                style(k).color256(CLI_PURPLE),
                style("Purpose:").color256(CLI_BLUE),
                style(&v.purpose).color256(CLI_GREEN),
                style("Created:").color256(CLI_BLUE),
                style(v.create_time).color256(CLI_GREEN)
            );
            println!();
        }

        self.private.relationships.status(
            &self.private.contacts,
            &self.public.persona_did,
            &self.private.vrcs_issued,
            &self.private.vrcs_received,
        );
    }
}

pub trait PublicConfigExtension {
    fn status(&self);
}

impl PublicConfigExtension for PublicConfig {
    /// Prints information relating to the Public configuration to console
    fn status(&self) {
        println!();
        println!("{}", style("Configuration information").color256(CLI_BLUE));
        println!("{}", style("=========================").color256(CLI_BLUE));
        print!("{} ", style("Protection:").color256(CLI_BLUE));
        match &self.protection {
            ConfigProtectionType::Plaintext => {
                println!("{}", style("Plaintext").color256(CLI_RED));
            }
            ConfigProtectionType::Encrypted => {
                println!(
                    "{}",
                    style("ENCRYPTED with unlock passphrase").color256(CLI_GREEN)
                );
            }
            ConfigProtectionType::Token(token_id) => {
                println!(
                    "{}",
                    style(format!("HARDWARE TOKEN ({})", token_id)).color256(CLI_GREEN)
                );
            }
        }

        println!(
            "{} {}",
            style("Persona DID:").color256(CLI_BLUE),
            style(&self.persona_did).color256(CLI_PURPLE)
        );
        print!("{} ", style("Mediator DID:").color256(CLI_BLUE));
        if self.mediator_did == LF_PUBLIC_MEDIATOR_DID {
            println!("{}", style(LF_PUBLIC_MEDIATOR_DID).color256(CLI_GREEN));
        } else {
            println!(
                "{} {}",
                style(&self.mediator_did).color256(CLI_ORANGE),
                style("Mediator is customised (not an issue if deliberate)").color256(CLI_BLUE)
            );
        }
    }
}
