/*! Contains specific Config extensions for the CLI Application. */

use crate::{
    CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED, relationships::RelationshipsExtension,
    setup::create_unlock_code,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use console::style;
use dialoguer::{Password, theme::ColorfulTheme};
use ed25519_dalek_bip32::ExtendedSigningKey;
use openvtc::{
    LF_PUBLIC_MEDIATOR_DID,
    config::{
        Config, ConfigProtectionType, ExportedConfig, derive_passphrase_key,
        protected_config::ProtectedConfig, public_config::PublicConfig,
        secured_config::unlock_code_decrypt,
    },
};
use secrecy::{ExposeSecret, SecretString};
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

        let passphrase_bytes = if let Some(passphrase) = passphrase {
            passphrase.expose_secret().as_bytes().to_vec()
        } else {
            let input = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter passphrase to decrypt imported configuration")
                .interact()
                .context("Failed to read passphrase")?;
            input.into_bytes()
        };

        let seed_bytes = derive_passphrase_key(&passphrase_bytes, b"openvtc-export-v1")?;
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
            create_unlock_code()?
        } else {
            None
        };

        let bip32_seed = config
            .sc
            .bip32_seed
            .as_ref()
            .context("Imported config does not contain a BIP32 seed (VTA configs cannot be imported via CLI)")?;
        let bip32_root = ExtendedSigningKey::from_seed(
            BASE64_URL_SAFE_NO_PAD
                .decode(bip32_seed.expose_secret())
                .context("Couldn't base64 decode BIP32 seed")?
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
            .context("Couldn't save Public Config")?;
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
            .context("Couldn't save Secured Config")?;

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

/// Saves the current configuration to disk for the given profile.
///
/// Wraps `Config::save` with the platform-appropriate touch-notification
/// callback so all call sites use a single consistent invocation.
///
/// # Errors
///
/// Returns an error if serialization or file I/O fails.
pub fn save_config(config: &mut openvtc::config::Config, profile: &str) -> anyhow::Result<()> {
    config.save(
        profile,
        #[cfg(feature = "openpgp-card")]
        &|| {
            eprintln!("Touch confirmation needed for decryption");
        },
    )?;
    Ok(())
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
