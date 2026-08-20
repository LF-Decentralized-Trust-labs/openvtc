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
    secure_store::{Durability, StoreDescription},
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
mod health_cmd;
mod state_handler;
mod ui;

/// Load the full account for `openvtc health`, or `None` if it cannot be had.
///
/// Every failure here is soft. A profile that does not exist, will not decrypt,
/// or whose VTA is unreachable still leaves a useful report to run against the
/// `--vtc` DIDs — and "the account would not load" is itself a finding worth
/// printing rather than an error worth aborting on. The reason is surfaced on
/// stderr so it is not swallowed.
///
/// The admin VTA session `load_step2` hands back is shut down immediately: this
/// command reads DID documents, and holding a live mediator connection open for
/// that would add a second socket for the profile the running TUI may already
/// own.
async fn load_config_for_health(profile: &str, unlock_code_arg: Option<&str>) -> Option<Config> {
    let deferred = match load_fast(profile, unlock_code_arg) {
        Ok(deferred) => deferred,
        Err(OpenVTCError::ConfigNotFound(_, _)) => return None,
        Err(e) => {
            eprintln!(
                "{} {}",
                style("Account not loaded:").color256(CLI_ORANGE),
                redact_paths(&e.to_string()),
            );
            return None;
        }
    };

    let mut tdk = match affinidi_tdk::TDK::new(
        affinidi_tdk::common::config::TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .ok()?,
        None,
    )
    .await
    {
        Ok(tdk) => tdk,
        Err(e) => {
            eprintln!(
                "{} {e}",
                style("Account not loaded (TDK init failed):").color256(CLI_ORANGE)
            );
            return None;
        }
    };

    #[cfg(feature = "openpgp-card")]
    struct TouchPrompt;
    #[cfg(feature = "openpgp-card")]
    impl openvtc_core::config::TokenInteractions for TouchPrompt {
        fn touch_notify(&self) {
            eprintln!("Touch your security token to continue…");
        }
        fn touch_completed(&self) {}
    }

    match Config::load_step2(
        &mut tdk,
        profile,
        deferred.public_config,
        deferred.unlock_passphrase.as_ref(),
        #[cfg(feature = "openpgp-card")]
        &deferred.user_pin,
        #[cfg(feature = "openpgp-card")]
        &TouchPrompt,
        None,
    )
    .await
    {
        Ok((config, admin_session)) => {
            if let Some(session) = admin_session {
                session.shutdown().await;
            }
            Some(config)
        }
        Err(e) => {
            eprintln!(
                "{} {}",
                style("Account not loaded:").color256(CLI_ORANGE),
                redact_paths(&e.to_string()),
            );
            None
        }
    }
}

/// Environment variable that overrides automatic credential-store selection.
///
/// Values: `auto` (default), `secret-service`, `file`, `keyutils`. Anything else
/// is an error rather than a silent fall-through to `auto` — a typo here would
/// otherwise put a profile's keys somewhere the user did not intend.
const STORE_OVERRIDE_ENV: &str = "OPENVTC_SECURE_STORE";

/// Register the platform-specific keyring-core credential store as the
/// process default. Must run before any `keyring_core::Entry::new` call.
///
/// `profile` is needed because the durable file-backed store lives beside that
/// profile's config; this therefore runs *after* profile resolution, not before.
fn init_default_keyring_store(profile: &str) -> Result<()> {
    let requested = std::env::var(STORE_OVERRIDE_ENV).unwrap_or_else(|_| "auto".to_string());

    #[cfg(target_os = "macos")]
    let (store, description) = {
        if requested != "auto" {
            bail!(
                "{STORE_OVERRIDE_ENV}={requested} is not supported on macOS;                  the Keychain is the only backend"
            );
        }
        let store = apple_native_keyring_store::keychain::Store::new()
            .map_err(|e| anyhow::anyhow!("init macOS keychain store: {e}"))?;
        let description = StoreDescription {
            label: "macOS Keychain".to_string(),
            location: "login keychain (service \"openvtc\", account = profile name)".to_string(),
            durability: Durability::Durable,
            inspect_hint: Some(format!(
                "security find-generic-password -s openvtc -a {profile}"
            )),
        };
        (
            store as std::sync::Arc<keyring_core::api::CredentialStore>,
            description,
        )
    };

    #[cfg(target_os = "windows")]
    let (store, description) = {
        if requested != "auto" {
            bail!(
                "{STORE_OVERRIDE_ENV}={requested} is not supported on Windows;                  the Credential Manager is the only backend"
            );
        }
        let store = windows_native_keyring_store::Store::new()
            .map_err(|e| anyhow::anyhow!("init Windows credential manager store: {e}"))?;
        let description = StoreDescription {
            label: "Windows Credential Manager".to_string(),
            location: "generic credential \"openvtc\" for the current user".to_string(),
            durability: Durability::Durable,
            inspect_hint: Some("cmdkey /list | findstr openvtc".to_string()),
        };
        let _ = profile;
        (
            store as std::sync::Arc<keyring_core::api::CredentialStore>,
            description,
        )
    };

    #[cfg(target_os = "linux")]
    let (store, description) = linux_store(profile, &requested)?;

    keyring_core::set_default_store(store);
    openvtc_core::secure_store::record_active(description);
    Ok(())
}

/// Build the durable file-backed store for a profile, refusing to hold an
/// unencrypted `SecuredConfig`.
#[cfg(target_os = "linux")]
fn file_store(
    profile: &str,
) -> Result<(
    std::sync::Arc<openvtc_core::secure_store::file::Store>,
    std::path::PathBuf,
)> {
    let dir = openvtc_core::secure_store::secrets_dir(profile)
        .map_err(|e| anyhow::anyhow!("resolve secrets directory: {e}"))?;
    let store = openvtc_core::secure_store::file::Store::new(
        dir.clone(),
        Some(openvtc_core::config::secured_config::require_encrypted_blob),
    );
    Ok((store, dir))
}

/// Pick a Linux credential store.
///
/// The order matters and is the point of this change. Previously OpenVTC always
/// used the kernel keyring, whose own documentation calls it a cache that "will
/// not persist across reboots" — so a profile's only copy of its seed was in
/// RAM, and a reboot presented as a corrupt install. Now:
///
/// 1. **Secret Service** (gnome-keyring, KWallet, KeePassXC, oo7) when a daemon
///    answers — the durable, standard desktop answer, and what the README has
///    claimed all along.
/// 2. Otherwise a **composite**: the encrypted-file store over the kernel
///    keyring. A passphrase- or token-protected profile is written to disk and
///    survives; an unprotected one stays in the kernel keyring rather than
///    having its seed written out in the clear, and the user is told to set a
///    passphrase.
#[cfg(target_os = "linux")]
fn linux_store(
    profile: &str,
    requested: &str,
) -> Result<(
    std::sync::Arc<keyring_core::api::CredentialStore>,
    StoreDescription,
)> {
    use keyring_core::api::CredentialStore;
    use std::sync::Arc;

    let secret_service =
        |explicit: bool| -> Result<Option<(Arc<CredentialStore>, StoreDescription)>> {
            match dbus_secret_service_keyring_store::Store::new() {
                Ok(store) => Ok(Some((
                    store as Arc<CredentialStore>,
                    StoreDescription {
                        label: "Secret Service (GNOME Keyring / KWallet / KeePassXC)".to_string(),
                        location: "your login keyring, typically ~/.local/share/keyrings"
                            .to_string(),
                        durability: Durability::Durable,
                        inspect_hint: Some(format!(
                            "secret-tool search service openvtc username {profile}"
                        )),
                    },
                ))),
                Err(e) if explicit => Err(anyhow::anyhow!(
                    "{STORE_OVERRIDE_ENV}=secret-service was requested but no Secret Service \
                 is reachable: {e}. Check that a keyring daemon is running and that \
                 DBUS_SESSION_BUS_ADDRESS is set."
                )),
                Err(e) => {
                    // Not an error: headless boxes legitimately have no daemon.
                    // Say so, because the fallback has different properties.
                    tracing::info!(
                        "no Secret Service available ({e}); falling back to local storage"
                    );
                    Ok(None)
                }
            }
        };

    match requested {
        "secret-service" => Ok(secret_service(true)?.expect("explicit request returns or errors")),

        "file" => {
            let (store, dir) = file_store(profile)?;
            Ok((
                store as Arc<CredentialStore>,
                StoreDescription {
                    label: "Encrypted file".to_string(),
                    location: dir.display().to_string(),
                    durability: Durability::Durable,
                    inspect_hint: Some(format!("ls -l {}", dir.display())),
                },
            ))
        }

        "keyutils" => {
            let store = linux_keyutils_keyring_store::Store::new()
                .map_err(|e| anyhow::anyhow!("init linux keyutils store: {e}"))?;
            Ok((
                store as Arc<CredentialStore>,
                StoreDescription {
                    label: "Linux kernel keyring (keyutils)".to_string(),
                    location: "kernel memory — NOT written to disk".to_string(),
                    durability: Durability::UntilReboot,
                    inspect_hint: Some("keyctl show @us 2>/dev/null; keyctl show @s".to_string()),
                },
            ))
        }

        "auto" => {
            if let Some(found) = secret_service(false)? {
                return Ok(found);
            }
            let (durable, dir) = file_store(profile)?;

            // No kernel keyring either (some minimal containers): the file
            // store alone is still better than refusing to start. An
            // unprotected profile then cannot save at all — but it is told
            // exactly why, and setting a passphrase fixes it, which beats the
            // previous behaviour of failing here outright.
            let volatile = match linux_keyutils_keyring_store::Store::new() {
                Ok(store) => store,
                Err(e) => {
                    tracing::warn!(
                        "no kernel keyring available ({e}); \
                         this profile must have a passphrase or a token to be storable"
                    );
                    return Ok((
                        durable as Arc<CredentialStore>,
                        StoreDescription {
                            label: "Encrypted file (no kernel keyring available)".to_string(),
                            location: dir.display().to_string(),
                            durability: Durability::Durable,
                            inspect_hint: Some(format!("ls -l {}", dir.display())),
                        },
                    ));
                }
            };

            let store = openvtc_core::secure_store::composite::Store::new(
                durable as Arc<CredentialStore>,
                volatile as Arc<CredentialStore>,
            );
            Ok((
                store as Arc<CredentialStore>,
                StoreDescription {
                    label: "Encrypted file, falling back to the kernel keyring".to_string(),
                    location: format!(
                        "{} when the profile has a passphrase; kernel memory otherwise",
                        dir.display()
                    ),
                    // Per-credential, not store-wide: `secure_store::probe`
                    // reports which tier a given profile actually landed in.
                    durability: Durability::Unknown,
                    inspect_hint: Some(format!(
                        "ls -l {}; keyctl show @us 2>/dev/null",
                        dir.display()
                    )),
                },
            ))
        }

        other => bail!(
            "unknown {STORE_OVERRIDE_ENV}={other}; expected one of: \
             auto, secret-service, file, keyutils"
        ),
    }
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
        // Append, never truncate. `File::create` truncated on every launch, so
        // the evidence from a failed run was destroyed by the restart used to
        // reproduce it — the exact workflow this variable exists to serve.
        // Each run announces itself below, so runs stay separable in one file.
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(log_file) => {
                let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"));
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(std::sync::Mutex::new(log_file))
                    .with_ansi(false)
                    .init();
                // A run banner, because the file now spans runs: without a
                // marker, two appended runs read as one continuous session and
                // a restart becomes invisible in the middle of a trace.
                tracing::info!(
                    version = env!("CARGO_PKG_VERSION"),
                    "───── openvtc run started ─────  (appending to {log_path})"
                );
            }
            Err(e) => {
                eprintln!(
                    "warning: OPENVTC_DEBUG_LOG={log_path} could not be opened ({e}); continuing without file logging"
                );
            }
        }
    }

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

    // Optional invitation credential (VIC) to present when joining a community.
    // Loaded eagerly so a malformed path / JSON fails fast with a clear message
    // rather than silently dropping the invite mid-join.
    let invitation_credential: Option<serde_json::Value> = match matches
        .get_one::<String>("invitation")
    {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("failed to read invitation file `{path}`: {e}"))?;
            let vic: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("invitation file `{path}` is not valid JSON: {e}"))?;
            // Fail fast on a stripped/summary VIC rather than silently presenting
            // an unusable credential the VTC refers to a moderator.
            openvtc_core::join::validate_invitation_credential(&vic)
                .map_err(|e| anyhow::anyhow!("invitation file `{path}`: {e}"))?;
            Some(vic)
        }
        None => None,
    };

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

    // Register the platform's keyring-core credential store. keyring-core 1.0
    // doesn't auto-pick a backend — every binary registers exactly one at
    // startup. This runs *after* profile resolution because the durable
    // file-backed store used on Linux lives beside that profile's config.
    init_default_keyring_store(&profile)?;

    // `health` runs before the duplicate-instance check and never takes the
    // lock. The report is read-only, and the moment you most want it is while a
    // TUI is sitting on a join that never came back — refusing to run because
    // that TUI holds the profile would deny the diagnosis to the one situation
    // it exists for. Account details are best-effort for the same reason (see
    // `health_cmd::run`): a locked or undecryptable profile degrades the report
    // rather than aborting it.
    if let Some(("health", health_args)) = matches.subcommand() {
        let vtc_dids: Vec<String> = health_args
            .get_many::<String>("vtc")
            .map(|values| values.cloned().collect())
            .unwrap_or_default();
        let as_json = health_args.get_flag("json");
        let config = load_config_for_health(&profile, unlock_code_arg.as_deref()).await;
        return health_cmd::run(&profile, config.as_ref(), &vtc_dids, as_json).await;
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
            Err(e @ (OpenVTCError::Vta(_) | OpenVTCError::Auth(_))) => {
                // R18: a VTA connection/auth failure is a retryable runtime fault,
                // NOT config corruption. Surface "check VTA / re-auth" guidance and
                // reserve reset-style messaging for genuine `Config` errors below.
                let hint = if matches!(e, OpenVTCError::Auth(_)) {
                    "Check that your credentials are still valid and re-authenticate, then try again."
                } else {
                    "Check that your VTA is reachable and try again."
                };
                eprintln!(
                    "{} {}",
                    style("ERROR: Couldn't reach the VTA! Reason:").color256(CLI_RED),
                    style(redact_paths(&e.to_string())).color256(CLI_ORANGE)
                );
                eprintln!("{}", style(hint).color256(CLI_ORANGE));
                bail!("VTA Connection Error");
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
    let (mut state, state_rx) = StateHandler::new(&profile, starting_mode);
    state.set_invitation_credential(invitation_credential);
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
