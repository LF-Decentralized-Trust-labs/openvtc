//! Shared helpers for the post-action "save / sync / status / log" ritual that
//! every panel's action handlers perform after a state-mutating operation.
//!
//! Before this module existed, the same ~8-line success/error block was copied
//! inline across the inbox, relationship, credential, and settings handlers:
//!
//! 1. set the panel's `status_message`,
//! 2. persist the config (`save_config`, logging on failure),
//! 3. rebuild UI state from config (`sync_from_config`),
//! 4. push an activity-log entry (`log` or `log_detailed`).
//!
//! The helpers here generalize that block over the panel-specific status slot
//! (reached via an accessor closure, since each panel stores its
//! `status_message` in a different sub-struct) without changing any behavior.
//! Panel/mode transitions stay at the call site because they vary per panel.

use openvtc_core::config::Config;

use crate::state_handler::main_page::MainPageState;
use crate::state_handler::settings_actions;

/// Activity-log entry to write after an action completes.
pub(crate) enum SyncLog {
    /// A plain, single-line summary (`log`).
    Plain(String),
    /// A summary plus a detail pane (`log_detailed`).
    Detailed { summary: String, detail: String },
}

impl SyncLog {
    fn write(self, main_page: &mut MainPageState) {
        match self {
            SyncLog::Plain(summary) => main_page.log(summary),
            SyncLog::Detailed { summary, detail } => main_page.log_detailed(summary, detail),
        }
    }
}

/// How to persist + refresh UI after a successful action.
pub(crate) enum Persist {
    /// Save the config (logging on failure), then sync UI from config.
    SaveAndSync,
    /// The action already saved the config itself; only sync UI from config.
    SyncOnly,
    /// The action already saved the config and no UI sync is required.
    None,
}

impl Persist {
    fn apply(self, main_page: &mut MainPageState, config: &Config, profile: &str) {
        match self {
            Persist::SaveAndSync => {
                if let Err(e) = settings_actions::save_config(config, profile) {
                    main_page.log_error("Failed to save config", &e);
                }
                main_page.sync_from_config(config);
            }
            Persist::SyncOnly => main_page.sync_from_config(config),
            Persist::None => {}
        }
    }
}

/// Finish a successful action: persist/refresh per `persist`, set the panel's
/// `status_message` (reached via `status`), then write the activity log entry.
///
/// `status` returns a mutable reference to the panel's status slot, e.g.
/// `|mp| &mut mp.content_panel.inbox.status_message`.
pub(crate) fn save_and_sync(
    main_page: &mut MainPageState,
    config: &Config,
    profile: &str,
    persist: Persist,
    status: impl FnOnce(&mut MainPageState) -> &mut Option<String>,
    success_status: impl Into<String>,
    log: SyncLog,
) {
    *status(main_page) = Some(success_status.into());
    persist.apply(main_page, config, profile);
    log.write(main_page);
}

/// Record a failed action: set the panel's `status_message` to `Error: {err:#}`
/// (reached via `status`) and log the error with `context`.
pub(crate) fn record_error(
    main_page: &mut MainPageState,
    status: impl FnOnce(&mut MainPageState) -> &mut Option<String>,
    context: impl Into<String>,
    err: &anyhow::Error,
) {
    *status(main_page) = Some(format!("Error: {err:#}"));
    main_page.log_error(context, err);
}
