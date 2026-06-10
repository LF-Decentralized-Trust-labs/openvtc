#[cfg(feature = "openpgp-card")]
use crate::cli::get_user_pin;
use crate::colors::{CLI_BLUE, CLI_ORANGE, CLI_PURPLE, CLI_RED};
use crate::{
    cli::cli,
    state_handler::{DeferredLoad, StartingMode, StateHandler},
    ui::UiManager,
};
use anyhow::{Result, bail};
use console::style;
use dialoguer::{Confirm, Password, theme::ColorfulTheme};
use openvtc_core::{
    config::{Config, ConfigProtectionType, UnlockCode, public_config::PublicConfig},
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
mod clipboard;
mod colors;
mod state_handler;
mod ui;

/// Register the platform-specific keyring-core credential store as the
/// process default. Must run before any `keyring_core::Entry::new` call.
fn init_default_keyring_store() -> Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()
        .map_err(|e| anyhow::anyhow!("init macOS keychain store: {e}"))?;
    #[cfg(target_os = "linux")]
    let store = linux_keyutils_keyring_store::Store::new()
        .map_err(|e| anyhow::anyhow!("init linux keyutils store: {e}"))?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()
        .map_err(|e| anyhow::anyhow!("init Windows credential manager store: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

/// Redact file system paths from error messages for user display.
fn redact_paths(msg: &str) -> String {
    let home = dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    if !home.is_empty() {
        msg.replace(&home, "~")
    } else {
        msg.to_string()
    }
}

// ****************************************************************************
// MAIN Function
// ****************************************************************************

#[tokio::main]
async fn main() -> Result<()> {
    // Optional file-based debug logging.
    // Set OPENVTC_DEBUG_LOG to a file path to enable, e.g.:
    //   OPENVTC_DEBUG_LOG=/tmp/openvtc.log cargo run -p openvtc
    // Log level defaults to "debug" but can be overridden with RUST_LOG.
    if let Ok(log_path) = env::var("OPENVTC_DEBUG_LOG") {
        match std::fs::File::create(&log_path) {
            Ok(log_file) => {
                let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"));
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(std::sync::Mutex::new(log_file))
                    .with_ansi(false)
                    .init();
                tracing::info!("Debug logging enabled → {log_path}");
            }
            Err(e) => {
                eprintln!(
                    "warning: OPENVTC_DEBUG_LOG={log_path} could not be opened ({e}); continuing without file logging"
                );
            }
        }
    }

    // Register the platform's keyring-core credential store. keyring-core 1.0
    // doesn't auto-pick a backend — every binary registers exactly one at
    // startup. On Linux we use the kernel keyutils backend so headless
    // sessions (no D-Bus, no GUI) work without extra setup.
    init_default_keyring_store()?;

    // Parse the command line exactly once; thread the parsed values down to
    // the call sites that need them (profile resolution, setup detection, and
    // the unlock-code passed into `load_fast`). Unknown subcommands and
    // `--help`/`--version` are handled here by clap (process exits).
    let matches = cli().get_matches();
    let cli_profile = matches
        .get_one::<String>("profile")
        .cloned()
        .unwrap_or_else(|| "default".to_string());
    let unlock_code_arg = matches.get_one::<String>("unlock-code").cloned();
    let setup_requested = matches!(matches.subcommand(), Some(("setup", _)));

    // Which configuration profile to use?
    let profile = if let Ok(env_profile) = env::var("OPENVTC_CONFIG_PROFILE") {
        // ENV Profile will override the CLI Argument
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
        cli_profile
    };

    // The profile name is interpolated into lock-file and config paths and
    // used as the OS keyring account identifier; reject path separators and
    // traversal sequences before it reaches the filesystem.
    if profile.is_empty()
        || !profile
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        || profile.contains("..")
    {
        eprintln!(
            "{} {}",
            style("ERROR: Invalid profile name:").color256(CLI_RED),
            style(&profile).color256(CLI_ORANGE)
        );
        bail!("Profile name may only contain [A-Za-z0-9._-] and must not contain '..'");
    }

    // Check if profile is currently active elsewhere?
    let lock_file = check_duplicate_instance(&profile)?;

    let mut starting_mode = StartingMode::NotSet;

    // Is there a CLI command to force setup wizard?
    if setup_requested {
        starting_mode = StartingMode::SetupWizard;
    }

    if let StartingMode::NotSet = starting_mode {
        match load_fast(&profile, unlock_code_arg.as_deref()) {
            Ok(deferred) => {
                starting_mode = StartingMode::MainPageDeferred(deferred);
            }
            Err(OpenVTCError::ConfigNotFound(_, _)) => {
                // Configuration not found, start in setup mode
                starting_mode = StartingMode::SetupWizard;
            }
            Err(OpenVTCError::ConfigVersionUnsupported { found, expected }) => {
                // Breaking reset (D13 / R-RST-2,3): the on-disk config predates
                // the v2 account model and cannot be migrated. Warn explicitly,
                // require confirmation, then delete it and run setup from scratch.
                eprintln!(
                    "{}",
                    style(format!(
                        "Your existing configuration (format v{found}) is incompatible with \
                         this version of OpenVTC (format v{expected}) and cannot be upgraded \
                         automatically."
                    ))
                    .color256(CLI_ORANGE)
                );
                eprintln!(
                    "{}",
                    style(
                        "Continuing will DELETE the existing configuration and its stored \
                         credentials, then start a fresh setup. This cannot be undone."
                    )
                    .color256(CLI_RED)
                );
                let confirmed = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Delete the incompatible configuration and reset?")
                    .default(false)
                    .interact()
                    .unwrap_or(false);
                if !confirmed {
                    bail!("Incompatible configuration; reset declined by user");
                }
                let summary = PublicConfig::delete_profile(&profile).map_err(|e| {
                    anyhow::anyhow!("Failed to delete incompatible configuration: {e}")
                })?;
                for warning in &summary.warnings {
                    eprintln!(
                        "{}",
                        style(format!("warning during reset: {warning}")).color256(CLI_ORANGE)
                    );
                }
                starting_mode = StartingMode::SetupWizard;
            }
            Err(e) => {
                eprintln!(
                    "{} {}",
                    style("ERROR: Couldn't load configuration! Reason:").color256(CLI_RED),
                    style(redact_paths(&e.to_string())).color256(CLI_ORANGE)
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
                println!(
                    "exited because of a system error: {}",
                    redact_paths(&reason)
                )
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
    let mut interrupt_signal = match signal(tokio::signal::unix::SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create interrupt signal stream: {e}");
            return;
        }
    };

    interrupt_signal.recv().await;

    if let Err(e) = terminator.terminate(Interrupted::OsSigInt) {
        tracing::error!("Failed to send interrupt signal: {e}");
    }
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
    use openvtc_core::config::KeyBackend;

    if let Ok(val) = std::env::var("OPENVTC_MEDIATOR_DID") {
        config.set_active_mediator_did(&val);
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

/// Maximum number of interactive unlock attempts before aborting.
const MAX_UNLOCK_ATTEMPTS: usize = 5;

/// Fast, synchronous load — only does local config read + terminal prompts.
/// Network-heavy work (TDK init, DID resolution, VTA auth) is deferred to the state handler.
fn load_fast(profile: &str, unlock_code_arg: Option<&str>) -> Result<DeferredLoad, OpenVTCError> {
    let public_config = Config::load_step1(profile)?;

    let unlock_passphrase = match &public_config.protection {
        ConfigProtectionType::Token { .. } => None,
        ConfigProtectionType::Encrypted => {
            if let Some(passphrase) = unlock_code_arg {
                eprintln!(
                    "{}",
                    style(
                        "WARNING: --unlock-code exposes the passphrase in the process list; \
                         prefer the interactive prompt on shared systems."
                    )
                    .color256(CLI_ORANGE)
                );
                Some(UnlockCode::from_string(passphrase)?)
            } else {
                let mut result = None;
                for attempt in 1..=MAX_UNLOCK_ATTEMPTS {
                    // After 3 failed attempts, add exponential backoff delay
                    if attempt > 3 {
                        let delay = std::time::Duration::from_secs(1 << (attempt - 3).min(3));
                        std::thread::sleep(delay);
                    }
                    let input = match Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Please enter unlock passphrase")
                        .allow_empty_password(false)
                        .interact()
                    {
                        Ok(input) => input,
                        Err(e) => {
                            eprintln!("Failed to read passphrase input: {e}");
                            return Err(OpenVTCError::Config(format!(
                                "Passphrase input failed: {e}"
                            )));
                        }
                    };
                    match UnlockCode::from_string(&input) {
                        Ok(code) => {
                            result = Some(code);
                            break;
                        }
                        Err(e) => {
                            let remaining = MAX_UNLOCK_ATTEMPTS - attempt;
                            if remaining == 0 {
                                eprintln!("Too many failed unlock attempts. Aborting.");
                                return Err(e);
                            }
                            eprintln!(
                                "WARNING: Failed unlock attempt. {} attempt{} remaining.",
                                remaining,
                                if remaining == 1 { "" } else { "s" }
                            );
                        }
                    }
                }
                result
            }
        }
        ConfigProtectionType::Plaintext => None,
    };

    #[cfg(feature = "openpgp-card")]
    let user_pin = if matches!(&public_config.protection, ConfigProtectionType::Token(_)) {
        get_user_pin().map_err(|e| OpenVTCError::Config(format!("Failed to get user PIN: {e}")))?
    } else {
        SecretString::new("123456".into())
    };

    Ok(DeferredLoad {
        profile: profile.to_string(),
        public_config,
        unlock_passphrase,
        #[cfg(feature = "openpgp-card")]
        user_pin,
    })
}
