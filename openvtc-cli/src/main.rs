/* Open Source Trust Community Tool
*
*/

use crate::{
    cli::cli,
    config::{ConfigExtension, save_config},
    contacts::ContactsExtension,
    interactions::vrc::vrcs_entry,
    log::LogsExtension,
    maintainers::maintainers_entry,
    relationships::relationships_entry,
    setup::{cli_setup, pgp_export::ask_export_persona_did_keys},
    tasks::tasks_entry,
};
use affinidi_tdk::{TDK, common::config::TDKConfigBuilder};
use anyhow::{Context, Result, bail};
use console::{Term, style};
use dialoguer::{Password, theme::ColorfulTheme};
#[cfg(feature = "openpgp-card")]
use openvtc::config::TokenInteractions;
use openvtc::{
    colors::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED},
    config::{Config, ConfigProtectionType, UnlockCode},
    process_lock::{check_duplicate_instance, remove_lock_file},
};
use secrecy::SecretString;
use status::print_status;
use std::env;
use tracing_subscriber::EnvFilter;

mod cli;
mod config;
mod contacts;
mod interactions;
mod log;
mod maintainers;
mod messaging;
#[cfg(feature = "openpgp-card")]
mod openpgp_card;
mod relationships;
mod setup;
mod status;
mod tasks;

// Handles initial setup and configuration of the CLI tool
fn initialize(term: &Term) {
    // Setup logging/tracing
    // If no RUST_LOG ENV variable is set, defaults to MAX_LEVEL: ERROR
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    term.set_title("openvtc");
}

/// Loads openvtc with Trust Development Kit (TDK) and Config
/// This does not need to be called for setup!
async fn load(profile: &str) -> Result<(TDK, Config)> {
    // Instantiate the TDK
    let mut tdk = TDK::new(
        TDKConfigBuilder::new()
            .with_load_environment(false)
            .build()?,
        None,
    )
    .await?;

    #[cfg(feature = "openpgp-card")]
    let a = {
        struct A;
        impl TokenInteractions for A {
            fn touch_notify(&self) {
                eprintln!("Touch confirmation needed for decryption");
            }
            fn touch_completed(&self) {
                eprintln!("Decryption key unlocked");
            }
        }
        A
    };

    let public_config = Config::load_step1(profile)?;

    let (_user_pin, unlock_passphrase) = match &public_config.protection {
        ConfigProtectionType::Token { .. } => {
            let user_pin = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Please enter Token User PIN <blank = default>")
                .allow_empty_password(true)
                .interact()
                .context("Failed to read Token User PIN")?;
            let user_pin = if user_pin.is_empty() {
                SecretString::new("123456".to_string().into())
            } else {
                SecretString::new(user_pin.into())
            };

            (user_pin, None)
        }
        ConfigProtectionType::Encrypted => {
            let passphrase =
                if let Some(passphrase) = cli().get_matches().get_one::<String>("unlock-code") {
                    passphrase.to_string()
                } else {
                    Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Please enter unlock passphrase")
                        .allow_empty_password(false)
                        .interact()
                        .context("Failed to read unlock passphrase")?
                };
            (
                SecretString::new(String::new().into()),
                Some(UnlockCode::from_string(&passphrase)?),
            )
        }
        ConfigProtectionType::Plaintext => (SecretString::new(String::new().into()), None),
    };

    let config = match Config::load_step2(
        &mut tdk,
        profile,
        public_config,
        unlock_passphrase.as_ref(),
        #[cfg(feature = "openpgp-card")]
        &_user_pin,
        #[cfg(feature = "openpgp-card")]
        &a,
        None,
    )
    .await
    {
        Ok(cfg) => cfg,
        Err(e) => {
            println!(
                "{}{}",
                style("ERROR: ").color256(CLI_RED),
                style(&e).color256(CLI_ORANGE)
            );
            bail!("Failed to load configuration: {e}");
        }
    };

    Ok((tdk, config))
}

// ****************************************************************************
// MAIN FUNCTION
// ****************************************************************************
#[tokio::main]
async fn main() -> Result<()> {
    let term = Term::stdout();

    // Which configuration profile to use?
    let profile = if let Ok(env_profile) = env::var("OPENVTC_CONFIG_PROFILE") {
        // ENV Profile will override the CLI Argument
        let cli_profile = cli()
            .get_matches()
            .get_one::<String>("profile")
            .unwrap_or(&"default".to_string())
            .to_string();
        if cli_profile != "default" && cli_profile != env_profile {
            println!("{}", 
                style("WARNING: Using both ENV OPENVTC_CONFIG_PROFILE and CLI profile! These do not match!").color256(CLI_ORANGE)
            );
            println!(
                "{} {}",
                style("WARNING: Using CLI Profile:").color256(CLI_ORANGE),
                style(&cli_profile).color256(CLI_PURPLE)
            );
            cli_profile
        } else {
            println!(
                "{}{}{}",
                style("Using profile (").color256(CLI_BLUE),
                style(&env_profile).color256(CLI_PURPLE),
                style(") from OPENVTC_CONFIG_PROFILE ENV variable").color256(CLI_BLUE)
            );
            env_profile
        }
    } else {
        cli()
            .get_matches()
            .get_one::<String>("profile")
            .unwrap_or(&"default".to_string())
            .to_string()
    };

    // Check if profile is currently active elsewhere?
    let lock_file = check_duplicate_instance(&profile)?;

    initialize(&term);

    // openvtc routines
    let result = openvtc(&term, &profile).await;

    remove_lock_file(&lock_file);

    result
}

async fn openvtc(term: &Term, profile: &str) -> Result<()> {
    match cli().get_matches().subcommand() {
        Some(("logs", _)) => {
            let (_, config) = load(profile).await?;

            config.public.logs.show_all();
        }
        Some(("status", _)) => {
            let mut tdk = TDK::new(
                TDKConfigBuilder::new()
                    .with_load_environment(false)
                    .build()?,
                None,
            )
            .await?;
            print_status(term, &mut tdk, profile).await;
        }
        Some(("setup", args)) => {
            if let Some(args) = args.subcommand_matches("import") {
                let passphrase = args.get_one::<String>("passphrase");
                return Config::import(
                    passphrase.map(|s| SecretString::new(s.to_string().into())),
                    args.get_one::<String>("file")
                        .expect("No file specified!")
                        .as_ref(),
                    profile,
                );
            }
            match cli_setup(term, profile).await {
                Ok(_) => {
                    println!(
                        "\n{}",
                        style("Setup completed successfully.").color256(CLI_GREEN)
                    );
                }
                Err(e) => {
                    eprintln!("Setup failed: {e}");
                }
            }
        }
        Some(("export", args)) => {
            let (tdk, config) = load(profile).await?;

            match args.subcommand() {
                Some(("pgp-keys", sub_args)) => {
                    // Export PGP Keys
                    let user_id = sub_args.get_one::<String>("user-id");
                    let passphrase = sub_args.get_one::<String>("passphrase");

                    ask_export_persona_did_keys(
                        term,
                        &config.get_persona_keys(&tdk).await?,
                        user_id.map(|s| s.as_str()),
                        passphrase.map(|s| SecretString::new(s.to_string().into())),
                        false, // Not running in wizard mode
                    );
                }
                Some(("settings", sub_args)) => {
                    // Export settings
                    let passphrase = sub_args.get_one::<String>("passphrase");
                    if let Err(e) = config.export(
                        passphrase.map(|s| SecretString::new(s.to_string().into())),
                        sub_args
                            .get_one::<String>("file")
                            .expect("Code error - file should has a default!")
                            .as_str(),
                    ) {
                        eprintln!("ERROR: Export failed: {e}");
                    }
                }
                _ => {
                    println!(
                        "{} {}",
                        style("ERROR:").color256(CLI_RED),
                        style(
                            "No valid export subcommand was used. Use --help for more information."
                        )
                        .color256(CLI_ORANGE)
                    );
                    bail!("Bad CLI arguments");
                }
            }
        }
        Some(("contacts", args)) => {
            let (tdk, mut config) = load(profile).await?;

            if config
                .private
                .contacts
                .contacts_entry(
                    tdk,
                    args,
                    &config.private.relationships,
                    &mut config.public.logs,
                )
                .await?
            {
                // Need to save config
                save_config(&mut config, profile)?;
            }
        }
        Some(("relationships", args)) => {
            let (tdk, mut config) = load(profile).await?;

            relationships_entry(tdk, &mut config, profile, args).await?;
        }
        Some(("tasks", args)) => {
            let (tdk, mut config) = load(profile).await?;

            tasks_entry(tdk, &mut config, profile, args, term).await?;
        }
        Some(("vrcs", args)) => {
            let (tdk, mut config) = load(profile).await?;

            vrcs_entry(tdk, &mut config, profile, args).await?;
        }
        Some(("maintainers", args)) => {
            let (tdk, mut config) = load(profile).await?;

            maintainers_entry(tdk, &mut config, args).await?;
        }
        _ => {
            eprintln!("No valid subcommand was used. Use --help for more information.");
        }
    }

    Ok(())
}

/// Prompts user for their unlock code when not using a hardware token.
/// Derives a 32-byte key via Argon2id (same KDF as `UnlockCode::from_string`).
pub fn get_unlock_code() -> Result<[u8; 32]> {
    let unlock_code = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Please enter your openvtc unlock code")
        // An empty unlock code would produce a deterministic key, providing no security.
        .allow_empty_password(false)
        .interact()
        .map_err(|e| anyhow::anyhow!("Failed to read unlock code: {e}"))?;

    Ok(openvtc::config::derive_passphrase_key(
        unlock_code.as_bytes(),
        b"openvtc-unlock-code-v1",
    )?)
}
