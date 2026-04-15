#[cfg(feature = "openpgp-card")]
use crate::cli::get_user_pin;
use crate::{
    cli::cli,
    state_handler::{DeferredLoad, StartingMode, StateHandler},
    ui::UiManager,
};
use anyhow::{Result, bail};
use console::style;
use dialoguer::{Password, theme::ColorfulTheme};
use openvtc::{
    colors::{CLI_BLUE, CLI_ORANGE, CLI_PURPLE, CLI_RED},
    config::{Config, ConfigProtectionType, UnlockCode},
    errors::OpenVTCError,
    process_lock::{check_duplicate_instance, remove_lock_file},
};
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
use std::env;
#[cfg(unix)]
use tokio::signal::unix::signal;
use tokio::sync::broadcast;

mod cli;
mod state_handler;
mod ui;

// ****************************************************************************
// MAIN Function
// ****************************************************************************

#[tokio::main]
async fn main() -> Result<()> {
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

    let mut starting_mode = StartingMode::NotSet;

    // Is there a CLI command to force setup wizard?
    if let Some(("setup", _)) = cli().get_matches().subcommand() {
        starting_mode = StartingMode::SetupWizard;
    }

    if let StartingMode::NotSet = starting_mode {
        match load_fast(&profile) {
            Ok(deferred) => {
                starting_mode = StartingMode::MainPageDeferred(deferred);
            }
            Err(OpenVTCError::ConfigNotFound(_, _)) => {
                // Configuration not found, start in setup mode
                starting_mode = StartingMode::SetupWizard;
            }
            Err(e) => {
                eprintln!(
                    "{} {}",
                    style("ERROR: Couldn't load configuration! Reason:").color256(CLI_RED),
                    style(e).color256(CLI_ORANGE)
                );
                bail!("Configuration Error");
            }
        };
    }

    // OpenVTC must be in either setup or main state
    if let StartingMode::NotSet = starting_mode {
        bail!("Starting mode not set correctly!");
    }

    // Setup the initial state
    let (terminator, mut interrupt_rx) = create_termination();
    let (state, state_rx) = StateHandler::new(&profile, starting_mode);
    let (ui_manager, action_rx) = UiManager::new();

    tokio::try_join!(
        state.main_loop(terminator, action_rx, interrupt_rx.resubscribe()),
        ui_manager.main_loop(state_rx, interrupt_rx.resubscribe()),
    )?;

    match interrupt_rx.recv().await {
        Ok(reason) => match reason {
            Interrupted::UserInt => println!("exited per user request"),
            Interrupted::OsSigInt => println!("exited because of an os sig int"),
            Interrupted::SystemError(reason) => {
                println!("exited because of a system error: {reason}")
            }
        },
        _ => {
            println!("exited because of an unexpected error");
        }
    }

    remove_lock_file(&lock_file);
    Ok(())
}

// ****************************************************************************
// Termination Management
// ****************************************************************************

#[derive(Debug, Clone)]
pub enum Interrupted {
    OsSigInt,
    UserInt,
    SystemError(String),
}

#[derive(Debug, Clone)]
pub struct Terminator {
    interrupt_tx: broadcast::Sender<Interrupted>,
}

impl Terminator {
    pub fn new(interrupt_tx: broadcast::Sender<Interrupted>) -> Self {
        Self { interrupt_tx }
    }

    pub fn terminate(&mut self, interrupted: Interrupted) -> anyhow::Result<()> {
        self.interrupt_tx.send(interrupted)?;

        Ok(())
    }
}

#[cfg(unix)]
async fn terminate_by_unix_signal(mut terminator: Terminator) {
    let mut interrupt_signal = signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("failed to create interrupt signal stream");

    interrupt_signal.recv().await;

    terminator
        .terminate(Interrupted::OsSigInt)
        .expect("failed to send interrupt signal");
}

// create a broadcast channel for retrieving the application kill signal
pub fn create_termination() -> (Terminator, broadcast::Receiver<Interrupted>) {
    let (tx, rx) = broadcast::channel(1);
    let terminator = Terminator::new(tx);

    #[cfg(unix)]
    tokio::spawn(terminate_by_unix_signal(terminator.clone()));

    (terminator, rx)
}

/// Applies OPENVTC_* environment variable overrides to a loaded Config.
pub fn apply_env_overrides(config: &mut Config) {
    use openvtc::config::KeyBackend;

    if let Ok(val) = std::env::var("OPENVTC_MEDIATOR_DID") {
        config.public.mediator_did = val;
    }
    if let Ok(val) = std::env::var("OPENVTC_VTA_URL")
        && let KeyBackend::Vta {
            ref mut vta_url, ..
        } = config.key_backend
    {
        *vta_url = val;
    }
    if let Ok(val) = std::env::var("OPENVTC_VTA_DID")
        && let KeyBackend::Vta {
            ref mut vta_did, ..
        } = config.key_backend
    {
        *vta_did = val;
    }
    if let Ok(val) = std::env::var("OPENVTC_FRIENDLY_NAME") {
        config.public.friendly_name = val;
    }
}

/// Fast, synchronous load — only does local config read + terminal prompts.
/// Network-heavy work (TDK init, DID resolution, VTA auth) is deferred to the state handler.
fn load_fast(profile: &str) -> Result<DeferredLoad, OpenVTCError> {
    let public_config = Config::load_step1(profile)?;

    let unlock_passphrase = match &public_config.protection {
        ConfigProtectionType::Token { .. } => None,
        ConfigProtectionType::Encrypted => {
            if let Some(passphrase) = cli().get_matches().get_one::<String>("unlock-code") {
                Some(UnlockCode::from_string(passphrase)?)
            } else {
                Some(UnlockCode::from_string(
                    &Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Please enter unlock passphrase")
                        .allow_empty_password(false)
                        .interact()
                        .unwrap(),
                )?)
            }
        }
        ConfigProtectionType::Plaintext => None,
    };

    #[cfg(feature = "openpgp-card")]
    let user_pin = if matches!(&public_config.protection, ConfigProtectionType::Token(_)) {
        get_user_pin()
    } else {
        SecretString::new("123456".to_string().into())
    };

    Ok(DeferredLoad {
        profile: profile.to_string(),
        public_config,
        unlock_passphrase,
        #[cfg(feature = "openpgp-card")]
        user_pin,
    })
}
