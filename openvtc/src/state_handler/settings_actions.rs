//! Settings action handlers for the TUI.

use anyhow::Result;
use openvtc_core::{config::Config, logs::LogFamily};
use secrecy::{SecretBox, SecretString};
use tracing::info;

/// Save the config to disk using the profile name.
pub fn save_config(config: &Config, profile: &str) -> Result<()> {
    config.save(
        profile,
        #[cfg(feature = "openpgp-card")]
        &|| {},
    )?;
    Ok(())
}

/// Update the friendly name and save.
pub fn update_friendly_name(config: &mut Config, profile: &str, name: &str) -> Result<()> {
    config.public.friendly_name = name.to_string();
    config.public.logs.insert(
        LogFamily::Config,
        format!("Friendly name changed to '{}'", name),
    );
    save_config(config, profile)?;
    info!(name = %name, "friendly name updated");
    Ok(())
}

/// Update the mediator DID and save.
pub fn update_mediator_did(config: &mut Config, profile: &str, did: &str) -> Result<()> {
    config.set_active_mediator_did(did);
    config.public.logs.insert(
        LogFamily::Config,
        format!("Mediator DID changed to '{}'", did),
    );
    save_config(config, profile)?;
    info!(did = %did, "mediator DID updated (reconnect needed)");
    Ok(())
}

/// Update the organization DID and save.
pub fn update_org_did(config: &mut Config, profile: &str, did: &str) -> Result<()> {
    config.account.org_did = did.to_string();
    config
        .public
        .logs
        .insert(LogFamily::Config, format!("Org DID changed to '{}'", did));
    save_config(config, profile)?;
    info!(did = %did, "org DID updated");
    Ok(())
}

/// Set a passphrase to encrypt the config in the keyring.
pub fn set_passphrase(config: &mut Config, profile: &str, passphrase: &str) -> Result<()> {
    use openvtc_core::config::{ConfigProtectionType, derive_passphrase_key, validate_passphrase};

    validate_passphrase(passphrase)?;
    let key = derive_passphrase_key(passphrase.as_bytes(), b"openvtc-unlock-code-v1")?;
    config.unlock_code = Some(SecretBox::new(Box::new(key.to_vec())));
    config.public.protection = ConfigProtectionType::Encrypted;
    config.public.logs.insert(
        LogFamily::Config,
        "Config protection changed to passphrase encrypted".to_string(),
    );
    save_config(config, profile)?;
    info!("config protection set to passphrase encrypted");
    Ok(())
}

/// Remove passphrase protection, reverting to keyring-only.
pub fn remove_passphrase(config: &mut Config, profile: &str) -> Result<()> {
    use openvtc_core::config::ConfigProtectionType;

    config.unlock_code = None;
    config.public.protection = ConfigProtectionType::Plaintext;
    config.public.logs.insert(
        LogFamily::Config,
        "Config protection changed to keyring only (no additional encryption)".to_string(),
    );
    save_config(config, profile)?;
    info!("config protection reverted to keyring only");
    Ok(())
}

/// Validate a file path for export/import operations.
fn validate_file_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        anyhow::bail!("File path cannot be empty");
    }
    if path.contains("..") {
        anyhow::bail!("Path traversal (..) is not allowed");
    }
    Ok(())
}

/// Export the config to a file, encrypted with the given passphrase.
pub fn export_config(config: &Config, path: &str, passphrase: &str) -> Result<()> {
    validate_file_path(path)?;
    let secret = SecretString::new(passphrase.to_string().into());
    config.export(secret, path)?;
    info!(path = %path, "config exported");
    Ok(())
}

/// Validate an import file, then direct the operator to the real restore flow.
///
/// Importing into a *running* profile would require swapping the live config
/// and reconnecting messaging, so it is intentionally not performed from the
/// Settings panel. The supported restore path lives in the setup wizard:
/// run `openvtc setup` and choose "Import" / "Restore Backup".
pub fn import_config(path: &str, _passphrase: &str) -> Result<String> {
    validate_file_path(path)?;
    // Validate the file exists
    if !std::path::Path::new(path).exists() {
        anyhow::bail!("File not found: {}", path);
    }
    Ok(format!(
        "Import from {} is not supported here — run `openvtc setup` and choose \
         Import / Restore Backup to restore an exported config.",
        path
    ))
}

/// Add a contact by DID with an optional alias (synchronous, no DID resolution).
pub fn add_contact(
    config: &mut Config,
    profile: &str,
    did: &str,
    alias: Option<&str>,
) -> Result<()> {
    use openvtc_core::config::protected_config::Contact;
    use std::sync::Arc;

    let contact_did = Arc::new(did.to_string());
    let alias_str = alias.map(|a| a.to_string());
    let contact = Arc::new(Contact {
        did: contact_did.clone(),
        alias: alias_str.clone(),
    });

    config
        .private
        .contacts
        .contacts
        .insert(contact_did, contact.clone());

    if let Some(a) = &alias_str {
        config.private.contacts.aliases.insert(a.clone(), contact);
    }

    config.public.logs.insert(
        LogFamily::Config,
        format!("Contact added: {} alias({})", did, alias.unwrap_or("N/A")),
    );
    save_config(config, profile)?;
    info!(did = %did, "contact added");
    Ok(())
}

/// Remove a contact by DID.
pub fn remove_contact(config: &mut Config, profile: &str, did: &str) -> Result<()> {
    config
        .private
        .contacts
        .remove_contact(&mut config.public.logs, did);
    save_config(config, profile)?;
    info!(did = %did, "contact removed");
    Ok(())
}

// ============================================================
// State-handler dispatch wrappers
// ============================================================

use crate::state_handler::{
    actions::{ContactAction, SettingsAction},
    didcomm::{self, ReconnectOutcome},
    main_page::content::SettingsMode,
    state::{self, State},
};
use affinidi_messaging_didcomm_service::DIDCommService;

fn handle_select(state: &mut State, index: usize) {
    #[cfg(feature = "openpgp-card")]
    if let SettingsMode::TokenManagement { selected_index } =
        &mut state.main_page.content_panel.settings.mode
    {
        *selected_index = index;
    } else {
        state.main_page.content_panel.settings.selected_index = index;
    }
    #[cfg(not(feature = "openpgp-card"))]
    {
        state.main_page.content_panel.settings.selected_index = index;
    }
}

fn handle_start_edit(state: &mut State) {
    let idx = state.main_page.content_panel.settings.selected_index;
    let s = &state.main_page.content_panel.settings;
    state.main_page.content_panel.settings.mode = match idx {
        0 => SettingsMode::EditFriendlyName {
            input: s.friendly_name.clone(),
        },
        1 => SettingsMode::EditMediatorDid {
            input: s.mediator_did.clone(),
        },
        2 => SettingsMode::EditOrgDid {
            input: s.org_did.clone(),
        },
        5 => SettingsMode::ExportConfig {
            path_input: "openvtc-export.enc".to_string(),
            passphrase_len: 0,
            active_field: 0,
        },
        6 => SettingsMode::ImportConfig {
            path_input: "openvtc-export.enc".to_string(),
            passphrase_len: 0,
            active_field: 0,
        },
        _ => SettingsMode::View,
    };
}

fn handle_field_update(state: &mut State, value: String) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::EditFriendlyName { input }
        | SettingsMode::EditMediatorDid { input }
        | SettingsMode::EditOrgDid { input } => {
            *input = value;
        }
        _ => {}
    }
}

fn handle_form_field_update(state: &mut State, field: usize, value: String) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { path_input, .. }
        | SettingsMode::ImportConfig { path_input, .. }
            if field == 0 =>
        {
            *path_input = value;
        }
        _ => {}
    }
}

fn handle_passphrase_len(state: &mut State, len: usize) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { passphrase_len, .. }
        | SettingsMode::ImportConfig { passphrase_len, .. } => {
            *passphrase_len = len;
        }
        _ => {}
    }
}

fn handle_form_tab_switch(state: &mut State) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { active_field, .. }
        | SettingsMode::ImportConfig { active_field, .. } => {
            *active_field = if *active_field == 0 { 1 } else { 0 };
        }
        _ => {}
    }
}

fn handle_protection_option_select(state: &mut State, option: usize) {
    if let SettingsMode::ChangeProtection {
        selected_option, ..
    } = &mut state.main_page.content_panel.settings.mode
    {
        *selected_option = option;
    }
}

fn handle_protection_start_input(state: &mut State) {
    if let SettingsMode::ChangeProtection { active_field, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *active_field = 1;
    }
}

fn handle_protection_passphrase_len(state: &mut State, len: usize) {
    if let SettingsMode::ChangeProtection { passphrase_len, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *passphrase_len = len;
    }
}

fn handle_protection_confirm_len(state: &mut State, len: usize) {
    if let SettingsMode::ChangeProtection { confirm_len, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *confirm_len = len;
    }
}

fn handle_protection_tab_switch(state: &mut State, next_field: usize) {
    if let SettingsMode::ChangeProtection { active_field, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *active_field = next_field;
    }
}

/// Returns `true` if the mediator DID was changed and a reconnect is needed.
fn handle_submit_edit(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    value: &str,
) -> bool {
    let idx = state.main_page.content_panel.settings.selected_index;
    let result = match idx {
        0 => update_friendly_name(config, profile, value),
        1 => update_mediator_did(config, profile, value),
        2 => update_org_did(config, profile, value),
        _ => Ok(()),
    };
    match result {
        Ok(()) => {
            let setting_name = match idx {
                0 => "Friendly name",
                1 => "Mediator DID",
                2 => "Organization DID",
                _ => "Setting",
            };
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message =
                Some("Setting saved".to_string());
            state.main_page.sync_from_config(config);
            state.main_page.log(format!("{} updated", setting_name));
            // Mediator DID is index 1 — caller should trigger reconnect
            idx == 1
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message = Some(format!("Error: {e:#}"));
            state.main_page.log_error("Failed to save setting", &e);
            false
        }
    }
}

fn handle_export_config_action(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    path: &str,
    passphrase: &str,
) {
    match export_config(config, path, passphrase) {
        Ok(()) => {
            config
                .public
                .logs
                .insert(LogFamily::Config, format!("Config exported to {}", path));
            if let Err(e) = save_config(config, profile) {
                state
                    .main_page
                    .log_error("Failed to persist export-log entry", &e);
            }
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message =
                Some(format!("Config exported to {}", path));
            state.main_page.log(format!("Config exported to {}", path));
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message =
                Some(format!("Export failed: {e:#}"));
            state.main_page.log_error("Config export failed", &e);
        }
    }
}

fn handle_import_config_action(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    path: &str,
    passphrase: &str,
) {
    match import_config(path, passphrase) {
        Ok(msg) => {
            config
                .public
                .logs
                .insert(LogFamily::Config, format!("Config imported from {}", path));
            if let Err(e) = save_config(config, profile) {
                state
                    .main_page
                    .log_error("Failed to persist import-log entry", &e);
            }
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message = Some(msg.clone());
            state.main_page.log(msg);
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message =
                Some(format!("Import failed: {e:#}"));
            state.main_page.log_error("Config import failed", &e);
        }
    }
}

fn handle_change_protection(state: &mut State) {
    state.main_page.content_panel.settings.mode = SettingsMode::ChangeProtection {
        selected_option: 0,
        passphrase_len: 0,
        confirm_len: 0,
        active_field: 0,
    };
}

fn handle_set_passphrase(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    passphrase: &str,
) {
    match set_passphrase(config, profile, passphrase) {
        Ok(()) => {
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message =
                Some("Passphrase protection enabled".to_string());
            state.main_page.sync_from_config(config);
            state.main_page.log("Passphrase protection enabled");
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message = Some(format!("Error: {e:#}"));
            state.main_page.log_error("Failed to set passphrase", &e);
        }
    }
}

fn handle_remove_passphrase(config: &mut Box<Config>, state: &mut State, profile: &str) {
    match remove_passphrase(config, profile) {
        Ok(()) => {
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message =
                Some("Protection reverted to keyring only".to_string());
            state.main_page.sync_from_config(config);
            state.main_page.log("Protection reverted to keyring only");
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message = Some(format!("Error: {e:#}"));
            state.main_page.log_error("Failed to remove passphrase", &e);
        }
    }
}

fn handle_wipe_start(state: &mut State) {
    state.main_page.content_panel.settings.mode = SettingsMode::WipeConfirm {
        confirm_input: String::new(),
    };
}

fn handle_wipe_input(state: &mut State, value: String) {
    if let SettingsMode::WipeConfirm { confirm_input } =
        &mut state.main_page.content_panel.settings.mode
    {
        *confirm_input = value;
    }
}

const WIPE_CONFIRM_TOKEN: &str = "WIPE";

fn handle_wipe_confirm(state: &mut State, profile: &str) -> bool {
    let typed = match &state.main_page.content_panel.settings.mode {
        SettingsMode::WipeConfirm { confirm_input } => confirm_input.trim().to_string(),
        _ => return false,
    };
    if !typed.eq_ignore_ascii_case(WIPE_CONFIRM_TOKEN) {
        state.main_page.content_panel.settings.status_message = Some(format!(
            "Type {WIPE_CONFIRM_TOKEN} (exactly) to confirm — wipe cancelled."
        ));
        state.main_page.content_panel.settings.mode = SettingsMode::View;
        return false;
    }

    if let Some(info) = state.main_page.content_panel.settings.did_git_sign.clone() {
        match did_git_sign::init::uninstall(true, &info.did_key_id) {
            Ok(summary) => {
                if let Some(path) = &summary.removed_config_file {
                    state
                        .main_page
                        .log(format!("Removed did-git-sign config: {}", path.display()));
                }
                if !summary.removed_keyring_entries.is_empty() {
                    state.main_page.log(format!(
                        "Removed did-git-sign keyring entries: {}",
                        summary.removed_keyring_entries.join(", ")
                    ));
                }
                if summary.allowed_signers_entry_removed {
                    state
                        .main_page
                        .log("Removed did-git-sign allowed_signers entry");
                }
                for w in &summary.warnings {
                    state.main_page.log(format!("did-git-sign uninstall: {w}"));
                }
            }
            Err(e) => {
                state
                    .main_page
                    .log_error("did-git-sign uninstall failed", &e);
            }
        }
    }

    match openvtc_core::config::public_config::PublicConfig::delete_profile(profile) {
        Ok(summary) => {
            if let Some(path) = &summary.removed_config_file {
                state
                    .main_page
                    .log(format!("Removed openvtc config: {path}"));
            }
            if summary.removed_keyring_entry {
                state.main_page.log("Removed openvtc keyring entry");
            }
            for w in &summary.warnings {
                state.main_page.log(format!("openvtc wipe: {w}"));
            }
        }
        Err(e) => {
            state
                .main_page
                .log_error("Failed to wipe openvtc profile", &e);
            state.main_page.content_panel.settings.status_message =
                Some(format!("Wipe failed: {e:#}"));
            return false;
        }
    }

    state.main_page.log("Profile wiped — exiting.");
    true
}

#[cfg(feature = "openpgp-card")]
fn handle_token_management(state: &mut State) {
    state.main_page.content_panel.settings.mode =
        SettingsMode::TokenManagement { selected_index: 0 };
    match openvtc_core::openpgp_card::get_cards() {
        Ok(cards) => {
            state.main_page.content_panel.settings.token.detected_count = cards.len();
            state
                .main_page
                .content_panel
                .settings
                .token
                .messages
                .clear();
        }
        Err(e) => {
            state.main_page.content_panel.settings.token.detected_count = 0;
            state.main_page.content_panel.settings.token.messages =
                vec![format!("Error detecting tokens: {e}")];
        }
    }
}

#[cfg(feature = "openpgp-card")]
fn handle_token_detect(state: &mut State) {
    match openvtc_core::openpgp_card::get_cards() {
        Ok(cards) => {
            state.main_page.content_panel.settings.token.detected_count = cards.len();
            state.main_page.content_panel.settings.token.messages =
                vec![format!("{} token(s) detected", cards.len())];
        }
        Err(e) => {
            state.main_page.content_panel.settings.token.detected_count = 0;
            state.main_page.content_panel.settings.token.messages = vec![format!("Error: {e}")];
        }
    }
}

#[cfg(feature = "openpgp-card")]
fn handle_token_factory_reset(state: &mut State) {
    match openvtc_core::openpgp_card::get_cards() {
        Ok(cards) if !cards.is_empty() => {
            match openvtc_core::openpgp_card::factory_reset(cards[0].clone()) {
                Ok(()) => {
                    state.main_page.content_panel.settings.token.messages =
                        vec!["Factory reset completed successfully.".to_string()];
                    state.main_page.content_panel.settings.token.reset_completed = true;
                }
                Err(e) => {
                    state.main_page.content_panel.settings.token.messages =
                        vec![format!("Factory reset failed: {e}")];
                }
            }
        }
        Ok(_) => {
            state.main_page.content_panel.settings.token.messages =
                vec!["No tokens detected. Insert a token first.".to_string()];
        }
        Err(e) => {
            state.main_page.content_panel.settings.token.messages = vec![format!("Error: {e}")];
        }
    }
}

#[cfg(feature = "openpgp-card")]
fn handle_token_back(state: &mut State) {
    state.main_page.content_panel.settings.mode = SettingsMode::View;
    state
        .main_page
        .content_panel
        .settings
        .token
        .messages
        .clear();
    state.main_page.content_panel.settings.token.reset_completed = false;
}

async fn run_persona_reconnect(
    service: &DIDCommService,
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    state: &mut State,
) {
    state.connection.status = state::MediatorStatus::Connecting;
    state.connection.messaging_active = false;
    state.main_page.log("Reconnecting to mediator...");
    match didcomm::reconnect_persona_listener(service, config, tdk).await {
        ReconnectOutcome::Connected => {
            state.connection.status = state::MediatorStatus::Connected;
            state.connection.messaging_active = true;
            state.main_page.log("Reconnected to mediator");
        }
        ReconnectOutcome::Failed(reason) => {
            state.connection.status = state::MediatorStatus::Failed(reason.clone());
            state.main_page.log(format!("Reconnect failed: {reason}"));
        }
    }
}

/// Outcome of dispatching a `SettingsAction`. The TUI loop ignores
/// `Continue` and breaks out with `UserInt` when the operator wipes
/// the profile (the binary can no longer authenticate after a wipe).
pub(crate) enum SettingsOutcome {
    Continue,
    ExitUserInt,
}

/// Dispatch a single `SettingsAction`. Returns `ExitUserInt` if the
/// operator confirmed a profile wipe — caller is responsible for
/// driving the terminator afterwards.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch(
    action: SettingsAction,
    config: &mut Box<Config>,
    tdk: &affinidi_tdk::TDK,
    service: &DIDCommService,
    state: &mut State,
    profile: &str,
) -> SettingsOutcome {
    match action {
        SettingsAction::Select(index) => handle_select(state, index),
        SettingsAction::StartEdit => handle_start_edit(state),
        SettingsAction::CancelEdit => {
            state.main_page.content_panel.settings.mode = SettingsMode::View;
        }
        SettingsAction::FieldUpdate(value) => handle_field_update(state, value),
        SettingsAction::FormFieldUpdate { field, value } => {
            handle_form_field_update(state, field, value)
        }
        SettingsAction::FormTabSwitch => handle_form_tab_switch(state),
        SettingsAction::ProtectionOptionSelect(option) => {
            handle_protection_option_select(state, option)
        }
        SettingsAction::ProtectionStartInput => handle_protection_start_input(state),
        SettingsAction::ProtectionPassphraseLen(len) => {
            handle_protection_passphrase_len(state, len)
        }
        SettingsAction::ProtectionConfirmLen(len) => handle_protection_confirm_len(state, len),
        SettingsAction::ProtectionTabSwitch(next_field) => {
            handle_protection_tab_switch(state, next_field)
        }
        SettingsAction::PassphraseLen(len) => handle_passphrase_len(state, len),
        SettingsAction::SubmitEdit { value } => {
            if handle_submit_edit(config, state, profile, &value) {
                run_persona_reconnect(service, config, tdk, state).await;
            }
        }
        SettingsAction::ExportConfig { path, passphrase } => {
            handle_export_config_action(config, state, profile, &path, &passphrase)
        }
        SettingsAction::ImportConfig { path, passphrase } => {
            handle_import_config_action(config, state, profile, &path, &passphrase)
        }
        SettingsAction::ChangeProtection => handle_change_protection(state),
        SettingsAction::SetPassphrase { passphrase } => {
            handle_set_passphrase(config, state, profile, &passphrase)
        }
        SettingsAction::RemovePassphrase => handle_remove_passphrase(config, state, profile),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenManagement => handle_token_management(state),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenDetect => handle_token_detect(state),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenFactoryReset => handle_token_factory_reset(state),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenBack => handle_token_back(state),
        SettingsAction::ClipboardCopied(msg) => {
            state.main_page.content_panel.settings.status_message = Some(msg.clone());
            state.main_page.log(msg);
        }
        SettingsAction::WipeProfileStart => handle_wipe_start(state),
        SettingsAction::WipeProfileInput(value) => handle_wipe_input(state, value),
        SettingsAction::WipeProfileConfirm => {
            if handle_wipe_confirm(state, profile) {
                return SettingsOutcome::ExitUserInt;
            }
        }
        SettingsAction::ReconnectMediator => {
            run_persona_reconnect(service, config, tdk, state).await;
        }
    }
    SettingsOutcome::Continue
}

/// Dispatch a single `ContactAction`. Trivial enough to live alongside the
/// other settings dispatch since contacts ride the same save_config path.
pub(crate) fn dispatch_contact(
    action: ContactAction,
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
) {
    match action {
        ContactAction::Add { did, alias } => {
            match add_contact(config, profile, &did, alias.as_deref()) {
                Ok(()) => {
                    state.main_page.sync_from_config(config);
                    state
                        .main_page
                        .log(format!("Contact added: {}", super::log_did(&did)));
                }
                Err(e) => {
                    state.main_page.log_error("Failed to add contact", &e);
                }
            }
        }
        ContactAction::Remove { did } => match remove_contact(config, profile, &did) {
            Ok(()) => {
                state.main_page.sync_from_config(config);
                state
                    .main_page
                    .log(format!("Contact removed: {}", super::log_did(&did)));
            }
            Err(e) => {
                state.main_page.log_error("Failed to remove contact", &e);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_file_path_rejects_empty() {
        assert!(validate_file_path("").is_err());
        assert!(validate_file_path("   ").is_err());
    }

    #[test]
    fn test_validate_file_path_rejects_traversal() {
        assert!(validate_file_path("../../etc/passwd").is_err());
        assert!(validate_file_path("foo/../bar").is_err());
    }

    #[test]
    fn test_validate_file_path_accepts_normal() {
        assert!(validate_file_path("export.enc").is_ok());
        assert!(validate_file_path("/home/user/backup.enc").is_ok());
    }

    #[test]
    fn test_validate_file_path_accepts_dot_slash() {
        assert!(validate_file_path("./local-file.dat").is_ok());
    }

    #[test]
    fn test_validate_file_path_rejects_hidden_traversal() {
        assert!(validate_file_path("/tmp/safe/../../../etc/shadow").is_err());
    }
}
