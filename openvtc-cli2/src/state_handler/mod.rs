use std::borrow::Cow;
use std::sync::Arc;

use crate::{
    Interrupted, Terminator,
    state_handler::{
        actions::{
            Action, ContactAction, CredentialAction, InboxAction, RelationshipAction,
            SettingsAction,
        },
        main_page::MainPanel,
        state::{ActivePage, State},
    },
};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use anyhow::Result;
use openvtc::config::{Config, UnlockCode, public_config::PublicConfig};
use openvtc::logs::LogFamily;
use secrecy::SecretString;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver},
};
use tracing::debug;

/// Truncate a DID string for display in activity log messages.
#[must_use]
fn truncate_did(did: &str) -> Cow<'_, str> {
    if did.len() > 30 {
        Cow::Owned(format!("{}...", &did[..27]))
    } else {
        Cow::Borrowed(did)
    }
}

pub mod actions;
mod credential_actions;
pub mod didcomm;
mod inbox_actions;
pub mod main_page;
mod message_dispatch;
mod relationship_actions;
mod settings_actions;
mod setup_did_actions;
pub mod setup_sequence;
mod setup_token_actions;
mod setup_vta_actions;
mod setup_wizard;
pub mod state;

pub struct DeferredLoad {
    pub profile: String,
    pub public_config: PublicConfig,
    pub unlock_passphrase: Option<UnlockCode>,
    #[cfg(feature = "openpgp-card")]
    pub user_pin: SecretString,
}

#[allow(dead_code)]
pub enum StartingMode {
    NotSet,
    MainPage(Box<Config>, TDK),
    MainPageDeferred(DeferredLoad),
    SetupWizard,
}

pub struct StateHandler {
    state_tx: tokio::sync::watch::Sender<State>,
    profile: String,
    starting_mode: StartingMode,
}

pub(crate) enum SetupWizardExit {
    Interrupted(Interrupted),
    Config(Box<Config>),
}

impl StateHandler {
    pub fn new(
        profile: &str,
        starting_mode: StartingMode,
    ) -> (Self, tokio::sync::watch::Receiver<State>) {
        let (state_tx, state_rx) = tokio::sync::watch::channel(State::default());

        (
            StateHandler {
                state_tx,
                profile: profile.to_string(),
                starting_mode,
            },
            state_rx,
        )
    }

    pub async fn main_loop(
        mut self,
        mut terminator: Terminator,
        mut action_rx: UnboundedReceiver<Action>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> Result<Interrupted> {
        let mut state = State::default();

        let starting_mode = std::mem::replace(&mut self.starting_mode, StartingMode::NotSet);
        let (tdk, mut config) = match starting_mode {
            StartingMode::MainPage(config, tdk) => {
                state.active_page = ActivePage::Main;
                state.main_page.menu_panel.selected = true;
                state.main_page.config = (&config).into();
                state.main_page.log("Configuration loaded");

                (tdk.to_owned(), config)
            }
            StartingMode::SetupWizard => {
                // Instantiate TDK
                let tdk = TDK::new(
                    TDKConfig::builder().with_load_environment(false).build()?,
                    None,
                )
                .await?;

                match self
                    .setup_wizard(&mut action_rx, &mut interrupt_rx, &mut state, &tdk)
                    .await
                {
                    Ok(SetupWizardExit::Config(mut config)) => {
                        crate::apply_env_overrides(&mut config);

                        // Initialize main page state from the freshly created config
                        state.active_page = ActivePage::Main;
                        state.main_page.menu_panel.selected = true;
                        state.main_page.sync_from_config(&config);
                        state.main_page.log("Setup complete — configuration loaded");

                        (tdk, config)
                    }
                    Ok(SetupWizardExit::Interrupted(interrupted)) => {
                        if let Err(e) = terminator.terminate(interrupted.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        return Ok(interrupted);
                    }
                    Err(e) => {
                        let err = Interrupted::SystemError(format!("Setup Wizard failed: {e}"));
                        if let Err(e) = terminator.terminate(err.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        return Ok(err);
                    }
                }
            }
            StartingMode::MainPageDeferred(deferred) => {
                // Set minimal state from PublicConfig so UI can render immediately
                state.active_page = ActivePage::Main;
                state.main_page.menu_panel.selected = true;
                state.main_page.config = main_page::MainMenuConfigState {
                    name: deferred.public_config.friendly_name.clone(),
                    did: deferred.public_config.persona_did.clone(),
                };
                state.connection.status = state::MediatorStatus::Initializing("Starting...".into());
                let _ = self.state_tx.send(state.clone());

                // Spawn TDK init + config load as a background task with progress reporting
                let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<String>();

                // Prepare shared state for TokenNotifier so it can push UI updates
                #[cfg(feature = "openpgp-card")]
                let notifier_state_tx = self.state_tx.clone();
                #[cfg(feature = "openpgp-card")]
                let notifier_shared_state =
                    std::sync::Arc::new(std::sync::Mutex::new(state.clone()));

                let mut load_handle = tokio::spawn(async move {
                    let on_progress = |msg: &str| {
                        if let Err(e) = progress_tx.send(msg.to_string()) {
                            debug!("Failed to send progress event: {e}");
                        }
                    };

                    on_progress("Starting TDK...");
                    let mut tdk = TDK::new(
                        TDKConfig::builder()
                            .with_load_environment(false)
                            .build()
                            .map_err(|e| anyhow::anyhow!("TDK config failed: {e}"))?,
                        None,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("TDK init failed: {e}"))?;

                    // TokenInteractions impl for openpgp-card
                    #[cfg(feature = "openpgp-card")]
                    let token_notifier = {
                        use openvtc::config::TokenInteractions;

                        struct TokenNotifier {
                            shared_state: std::sync::Arc<
                                std::sync::Mutex<crate::state_handler::state::State>,
                            >,
                            state_tx:
                                tokio::sync::watch::Sender<crate::state_handler::state::State>,
                        }
                        impl TokenInteractions for TokenNotifier {
                            fn touch_notify(&self) {
                                if let Ok(mut s) = self.shared_state.lock() {
                                    s.token_touch_pending = true;
                                    let _ = self.state_tx.send(s.clone());
                                }
                            }
                            fn touch_completed(&self) {
                                if let Ok(mut s) = self.shared_state.lock() {
                                    s.token_touch_pending = false;
                                    let _ = self.state_tx.send(s.clone());
                                }
                            }
                        }
                        TokenNotifier {
                            shared_state: notifier_shared_state,
                            state_tx: notifier_state_tx,
                        }
                    };

                    let config = Config::load_step2(
                        &mut tdk,
                        &deferred.profile,
                        deferred.public_config,
                        deferred.unlock_passphrase.as_ref(),
                        #[cfg(feature = "openpgp-card")]
                        &deferred.user_pin,
                        #[cfg(feature = "openpgp-card")]
                        &token_notifier,
                        Some(&on_progress),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                    Ok::<_, anyhow::Error>((tdk, config))
                });

                // Listen for progress updates + handle user actions while loading
                let (tdk, config) = loop {
                    tokio::select! {
                        Some(msg) = progress_rx.recv() => {
                            state.connection.status =
                                state::MediatorStatus::Initializing(msg);
                            let _ = self.state_tx.send(state.clone());
                        }
                        result = &mut load_handle => {
                            match result {
                                Ok(Ok((tdk, config))) => break (tdk, config),
                                Ok(Err(e)) => {
                                    state.connection.status =
                                        state::MediatorStatus::Failed(format!("{e}"));
                                    let _ = self.state_tx.send(state.clone());
                                    return self
                                        .run_degraded_loop(
                                            &mut action_rx,
                                            &mut interrupt_rx,
                                            &mut terminator,
                                            &mut state,
                                        )
                                        .await;
                                }
                                Err(join_err) => {
                                    state.connection.status =
                                        state::MediatorStatus::Failed(
                                            format!("Internal error: {join_err}"),
                                        );
                                    let _ = self.state_tx.send(state.clone());
                                    return self
                                        .run_degraded_loop(
                                            &mut action_rx,
                                            &mut interrupt_rx,
                                            &mut terminator,
                                            &mut state,
                                        )
                                        .await;
                                }
                            }
                        }
                        Some(action) = action_rx.recv() => {
                            if matches!(action, Action::Exit) {
                                load_handle.abort();
                                if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                                    debug!("Failed to send terminate signal: {e}");
                                }
                                return Ok(Interrupted::UserInt);
                            }
                        }
                        Ok(interrupted) = interrupt_rx.recv() => {
                            load_handle.abort();
                            return Ok(interrupted);
                        }
                    }
                };

                let mut config = config;
                crate::apply_env_overrides(&mut config);

                let config = Box::new(config);
                // Sync all display state from the loaded config
                state.main_page.sync_from_config(&config);
                state.main_page.log("Configuration loaded");

                (tdk, config)
            }
            StartingMode::NotSet => {
                let err = Interrupted::SystemError("Starting Mode is Not Set!".to_string());
                if let Err(e) = terminator.terminate(err.clone()) {
                    debug!("Failed to send terminate signal: {e}");
                }
                return Ok(err);
            }
        };

        // Send initial state immediately so the UI renders without blocking
        state.connection.status = state::MediatorStatus::Connecting;
        let _ = self.state_tx.send(state.clone());

        // Start the DIDComm service (connection lifecycle, message dispatch, sending)
        let (didcomm_event_tx, mut didcomm_event_rx) = mpsc::unbounded_channel();
        let shutdown_token = tokio_util::sync::CancellationToken::new();

        let didcomm_service = match didcomm::start_service(
            &config,
            &tdk,
            didcomm_event_tx.clone(),
            shutdown_token.clone(),
        )
        .await
        {
            Ok(svc) => svc,
            Err(e) => {
                state.connection.status =
                    state::MediatorStatus::Failed(format!("DIDComm service: {e}"));
                state
                    .main_page
                    .log(format!("DIDComm service failed to start: {e}"));
                let _ = self.state_tx.send(state.clone());
                return self
                    .run_degraded_loop(
                        &mut action_rx,
                        &mut interrupt_rx,
                        &mut terminator,
                        &mut state,
                    )
                    .await;
            }
        };

        // Forward lifecycle events (connect/disconnect/restart) to the activity log
        let (lifecycle_log_tx, mut lifecycle_log_rx) = mpsc::unbounded_channel::<String>();
        let _lifecycle_handle = didcomm::spawn_lifecycle_logger(&didcomm_service, lifecycle_log_tx);

        // Wait for persona listener to connect (up to 15 s)
        match didcomm_service
            .wait_connected("persona", std::time::Duration::from_secs(30))
            .await
        {
            Ok(()) => {
                state.connection.status = state::MediatorStatus::Connected { latency_ms: 0 };
                state.connection.messaging_active = true;
                state.main_page.log("Connected to mediator");
            }
            Err(e) => {
                state.connection.status = state::MediatorStatus::Failed(format!("{e}"));
                state
                    .main_page
                    .log(format!("Mediator connection failed: {e}"));
            }
        }
        let _ = self.state_tx.send(state.clone());

        // Track when a trust-ping was sent to measure round-trip latency.
        // `true` = manual ping (log to activity), `false` = keepalive (silent).
        let mut ping_sent_at: Option<(std::time::Instant, bool)> = None;

        // Periodic keepalive ping to monitor mediator connectivity (every 60s)
        let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        keepalive_interval.tick().await; // consume the immediate first tick

        // Send initial ping to get first latency reading
        if state.connection.messaging_active
            && let Ok(ping_msg) =
                build_trust_ping(&config.public.persona_did, &config.public.mediator_did)
            && didcomm_service
                .send_message("persona", ping_msg, &config.public.mediator_did)
                .await
                .is_ok()
        {
            ping_sent_at = Some((std::time::Instant::now(), false));
        }

        let result = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => match action {
                    Action::Exit => {
                        if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                            debug!("Failed to send terminate signal: {e}");
                        }

                        break Interrupted::UserInt;
                    },
                    Action::UXError(interrupted) => {
                        // An error has occurred on the UX side
                        if let Err(e) = terminator.terminate(interrupted.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }

                        break interrupted;
                    },
                    Action::MainMenuSelected(menu_item) => {
                        // User has changed main menu selection
                        state.main_page.menu_panel.selected_menu = menu_item;
                    },
                    Action::MainPanelSwitch(panel) => {
                        match panel {
                            MainPanel::ContentPanel => {
                                // When switching to ContentPanel, reset any content-specific state if needed
                                state.main_page.menu_panel.selected = false;
                                state.main_page.content_panel.selected = true;
                            },
                            MainPanel::MainMenu => {
                                // When switching to MainMenu, reset any content-specific state if needed
                                state.main_page.menu_panel.selected = true;
                                state.main_page.content_panel.selected = false;
                            }
                        }
                    },
                    Action::Inbox(ia) => match ia {
                        InboxAction::SelectTask(index) => {
                            handle_inbox_select(&mut state, index);
                        },
                        InboxAction::OpenDetail(index) => {
                            handle_inbox_open_detail(&mut state, index);
                        },
                        InboxAction::Back => {
                            state.main_page.content_panel.inbox.active_task = None;
                        },
                        InboxAction::AcceptRelationship { task_id, generate_r_did } => {
                            handle_inbox_accept_relationship(&mut config, &tdk, &didcomm_service, &mut state, &self.profile, &task_id, generate_r_did).await;
                        },
                        InboxAction::RejectRelationship { task_id, reason } => {
                            handle_inbox_reject_relationship(&mut config, &tdk, &didcomm_service, &mut state, &self.profile, &task_id, reason.as_deref()).await;
                        },
                        InboxAction::AcceptVrc { task_id } => {
                            handle_inbox_accept_vrc(&mut config, &mut state, &self.profile, &task_id);
                        },
                        InboxAction::AcceptVrcRequest { task_id } => {
                            handle_inbox_accept_vrc_request(&mut config, &tdk, &didcomm_service, &mut state, &self.profile, &task_id).await;
                        },
                        InboxAction::RejectVrcRequest { task_id, reason } => {
                            handle_inbox_reject_vrc_request(&mut config, &tdk, &didcomm_service, &mut state, &self.profile, &task_id, reason.as_deref()).await;
                        },
                        InboxAction::DismissTask { task_id } => {
                            handle_inbox_dismiss_task(&mut config, &mut state, &self.profile, &task_id);
                        },
                        InboxAction::ClearAll => {
                            handle_inbox_clear_all(&mut config, &mut state, &self.profile);
                        },
                    },
                    Action::Relationship(ra) => match ra {
                        RelationshipAction::Select(index) => {
                            state.main_page.content_panel.relationships.selected_index = index;
                        },
                        RelationshipAction::OpenDetail(index) => {
                            handle_relationship_open_detail(&mut state, index);
                        },
                        RelationshipAction::StartNewRequest => {
                            handle_relationship_start_new_request(&mut state);
                        },
                        RelationshipAction::CancelNewRequest | RelationshipAction::Back => {
                            handle_relationship_cancel_or_back(&mut state);
                        },
                        RelationshipAction::InputUpdate { field, value } => {
                            handle_relationship_input_update(&mut state, field, value);
                        },
                        RelationshipAction::ToggleRDid => {
                            handle_relationship_toggle_r_did(&mut state);
                        },
                        RelationshipAction::FocusField(field) => {
                            use main_page::content::RelationshipsMode;
                            if let RelationshipsMode::NewRequest { active_field, .. } =
                                &mut state.main_page.content_panel.relationships.mode
                            {
                                *active_field = field;
                            }
                        },
                        RelationshipAction::SubmitRequest { did, alias, reason, generate_r_did } => {
                            handle_relationship_submit(&mut config, &tdk, &didcomm_service, &mut state, &self.state_tx, &self.profile, &did, &alias, reason.as_deref(), generate_r_did).await;
                        },
                        RelationshipAction::Ping { remote_p_did } => {
                            handle_relationship_ping(&mut config, &tdk, &didcomm_service, &mut state, &self.profile, &remote_p_did).await;
                            ping_sent_at = Some((std::time::Instant::now(), true));
                        },
                        RelationshipAction::Remove { remote_p_did } => {
                            handle_relationship_remove(&mut config, &mut state, &self.profile, &remote_p_did);
                        },
                        RelationshipAction::StartEditAlias { index, current_alias } => {
                            state.main_page.content_panel.relationships.mode =
                                main_page::content::RelationshipsMode::EditAlias { index, alias_input: current_alias };
                        },
                        RelationshipAction::EditAliasUpdate(value) => {
                            if let main_page::content::RelationshipsMode::EditAlias { ref mut alias_input, .. } =
                                state.main_page.content_panel.relationships.mode
                            {
                                *alias_input = value;
                            }
                        },
                        RelationshipAction::EditAlias { remote_p_did, alias } => {
                            handle_relationship_edit_alias(&mut config, &mut state, &self.profile, &remote_p_did, &alias);
                        },
                        RelationshipAction::CancelEditAlias { index } => {
                            state.main_page.content_panel.relationships.mode =
                                main_page::content::RelationshipsMode::Detail { index };
                        },
                    },
                    Action::Credential(ca) => match ca {
                        CredentialAction::SwitchTab => {
                            handle_credential_switch_tab(&mut state);
                        },
                        CredentialAction::Select(index) => {
                            state.main_page.content_panel.credentials.selected_index = index;
                        },
                        CredentialAction::OpenDetail(index) => {
                            handle_credential_open_detail(&mut state, index);
                        },
                        CredentialAction::Back | CredentialAction::CancelNewRequest => {
                            handle_credential_back(&mut state);
                        },
                        CredentialAction::StartNewRequest => {
                            handle_credential_start_new_request(&mut state);
                        },
                        CredentialAction::SelectRelationship(index) => {
                            handle_credential_select_relationship(&mut state, index);
                        },
                        CredentialAction::ReasonUpdate(value) => {
                            handle_credential_reason_update(&mut state, value);
                        },
                        CredentialAction::SubmitRequest { relationship_p_did, reason } => {
                            handle_credential_submit_request(&mut config, &tdk, &didcomm_service, &mut state, &self.profile, &relationship_p_did, reason.as_deref()).await;
                        },
                        CredentialAction::Remove { vrc_id } => {
                            handle_credential_remove(&mut config, &mut state, &self.profile, &vrc_id);
                        },
                    },
                    Action::Contact(ca) => match ca {
                        ContactAction::Add { did, alias } => {
                            handle_contact_add(&mut config, &mut state, &self.profile, &did, alias.as_deref());
                        },
                        ContactAction::Remove { did } => {
                            handle_contact_remove(&mut config, &mut state, &self.profile, &did);
                        },
                    },
                    Action::Settings(sa) => match sa {
                        SettingsAction::Select(index) => {
                            handle_settings_select(&mut state, index);
                        },
                        SettingsAction::StartEdit => {
                            handle_settings_start_edit(&mut state);
                        },
                        SettingsAction::CancelEdit => {
                            state.main_page.content_panel.settings.mode = main_page::content::SettingsMode::View;
                        },
                        SettingsAction::FieldUpdate(value) => {
                            handle_settings_field_update(&mut state, value);
                        },
                        SettingsAction::FormFieldUpdate { field, value } => {
                            handle_settings_form_field_update(&mut state, field, value);
                        },
                        SettingsAction::FormTabSwitch => {
                            handle_settings_form_tab_switch(&mut state);
                        },
                        SettingsAction::ProtectionOptionSelect(option) => {
                            handle_settings_protection_option_select(&mut state, option);
                        },
                        SettingsAction::ProtectionStartInput => {
                            handle_settings_protection_start_input(&mut state);
                        },
                        SettingsAction::ProtectionPassphraseLen(len) => {
                            handle_settings_protection_passphrase_len(&mut state, len);
                        },
                        SettingsAction::ProtectionConfirmLen(len) => {
                            handle_settings_protection_confirm_len(&mut state, len);
                        },
                        SettingsAction::ProtectionTabSwitch(next_field) => {
                            handle_settings_protection_tab_switch(&mut state, next_field);
                        },
                        SettingsAction::PassphraseLen(len) => {
                            handle_settings_passphrase_len(&mut state, len);
                        },
                        SettingsAction::SubmitEdit { value } => {
                            let needs_reconnect = handle_settings_submit_edit(&mut config, &mut state, &self.profile, &value);
                            if needs_reconnect {
                                state.connection.status = state::MediatorStatus::Connecting;
                                state.connection.messaging_active = false;
                                state.main_page.log("Reconnecting to mediator...");

                                // Replace the persona listener with the new mediator DID
                                let _ = didcomm_service.remove_listener("persona").await;
                                let new_config = didcomm::persona_listener_config(&config, &tdk).await;
                                if let Err(e) = didcomm_service.add_listener(new_config).await {
                                    state.connection.status =
                                        state::MediatorStatus::Failed(format!("{e}"));
                                    state.main_page.log(format!("Reconnect failed: {e}"));
                                } else {
                                    match didcomm_service
                                        .wait_connected("persona", std::time::Duration::from_secs(30))
                                        .await
                                    {
                                        Ok(()) => {
                                            state.connection.status =
                                                state::MediatorStatus::Connected { latency_ms: 0 };
                                            state.connection.messaging_active = true;
                                            state.main_page.log("Reconnected to mediator");
                                        }
                                        Err(e) => {
                                            state.connection.status =
                                                state::MediatorStatus::Failed(format!("{e}"));
                                            state.main_page.log(format!("Reconnect failed: {e}"));
                                        }
                                    }
                                }
                            }
                        },
                        SettingsAction::ExportConfig { path, passphrase } => {
                            handle_settings_export_config(&mut config, &mut state, &self.profile, &path, &passphrase);
                        },
                        SettingsAction::ImportConfig { path, passphrase } => {
                            handle_settings_import_config(&mut config, &mut state, &self.profile, &path, &passphrase);
                        },
                        SettingsAction::ChangeProtection => {
                            handle_settings_change_protection(&mut state);
                        },
                        SettingsAction::SetPassphrase { passphrase } => {
                            handle_settings_set_passphrase(&mut config, &mut state, &self.profile, &passphrase);
                        },
                        SettingsAction::RemovePassphrase => {
                            handle_settings_remove_passphrase(&mut config, &mut state, &self.profile);
                        },
                        #[cfg(feature = "openpgp-card")]
                        SettingsAction::TokenManagement => {
                            handle_settings_token_management(&mut state);
                        },
                        #[cfg(feature = "openpgp-card")]
                        SettingsAction::TokenDetect => {
                            handle_settings_token_detect(&mut state);
                        },
                        #[cfg(feature = "openpgp-card")]
                        SettingsAction::TokenFactoryReset => {
                            handle_settings_token_factory_reset(&mut state);
                        },
                        #[cfg(feature = "openpgp-card")]
                        SettingsAction::TokenBack => {
                            handle_settings_token_back(&mut state);
                        },
                        SettingsAction::ClipboardCopied(msg) => {
                            state.main_page.content_panel.settings.status_message = Some(msg.clone());
                            state.main_page.log(msg);
                        },
                        SettingsAction::ReconnectMediator => {
                            state.connection.status = state::MediatorStatus::Connecting;
                            state.connection.messaging_active = false;
                            state.main_page.log("Reconnecting to mediator...");

                            // Replace the persona listener
                            let _ = didcomm_service.remove_listener("persona").await;
                            let new_config = didcomm::persona_listener_config(&config, &tdk).await;
                            if let Err(e) = didcomm_service.add_listener(new_config).await {
                                state.connection.status =
                                    state::MediatorStatus::Failed(format!("{e}"));
                                state.main_page.log(format!("Reconnect failed: {e}"));
                            } else {
                                match didcomm_service
                                    .wait_connected("persona", std::time::Duration::from_secs(30))
                                    .await
                                {
                                    Ok(()) => {
                                        state.connection.status =
                                            state::MediatorStatus::Connected { latency_ms: 0 };
                                        state.connection.messaging_active = true;
                                        state.main_page.log("Reconnected to mediator");
                                    }
                                    Err(e) => {
                                        state.connection.status =
                                            state::MediatorStatus::Failed(format!("{e}"));
                                        state.main_page.log(format!("Reconnect failed: {e}"));
                                    }
                                }
                            }
                        },
                    },
                    _ => {}
                },
                // DIDComm inbound message events
                Some(event) = didcomm_event_rx.recv() => {
                    match event {
                        didcomm::DIDCommEvent::InboundMessage { message, .. } => {
                            match message_dispatch::process_inbound_message(
                                &mut config,
                                &tdk,
                                &didcomm_service,
                                &message,
                            )
                            .await
                            {
                                Ok(true) => {
                                    if let Err(e) = settings_actions::save_config(&config, &self.profile) {
                                        state.main_page.log(format!("Failed to save config: {e}"));
                                    }
                                    state.main_page.sync_from_config(&config);
                                    state.main_page.log("Inbound message processed");
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    state.main_page.log(format!("Message error: {e}"));
                                    debug!("message dispatch error: {e}");
                                }
                            }
                        }
                        didcomm::DIDCommEvent::TrustPingReceived { from, listener_id, message_id } => {
                            let sender = from.as_deref().unwrap_or("unknown");
                            let sender_arc = std::sync::Arc::new(sender.to_string());

                            // Only respond to pings from the mediator or established relationships
                            let is_mediator = sender == config.public.mediator_did;
                            let has_relationship = config
                                .private
                                .relationships
                                .find_by_remote_did(&sender_arc)
                                .map(|r| {
                                    r.lock()
                                        .map(|l| l.state == openvtc::relationships::RelationshipState::Established)
                                        .unwrap_or(false)
                                })
                                .unwrap_or(false);

                            if is_mediator || has_relationship {
                                // Send pong to verified sender
                                if let Some(ref from_did) = from
                                    && let Ok(pong_msg) =
                                        build_trust_pong(from_did, &message_id)
                                    && let Err(e) = didcomm_service
                                        .send_message(&listener_id, pong_msg, from_did)
                                        .await
                                {
                                    state
                                        .main_page
                                        .log(format!("Failed to send pong: {e}"));
                                }
                                state.main_page.log(format!(
                                    "Trust-ping from {} — pong sent",
                                    truncate_did(sender)
                                ));
                            } else {
                                state.main_page.log(format!(
                                    "Trust-ping from {} — ignored (no relationship)",
                                    truncate_did(sender)
                                ));
                            }
                        }
                        didcomm::DIDCommEvent::TrustPongReceived { from } => {
                            let sender = from.as_deref().unwrap_or("unknown");
                            let ping_info = ping_sent_at.take();
                            if let Some((sent_at, is_manual)) = ping_info {
                                let ms = sent_at.elapsed().as_millis();
                                // Update connection status with latest latency
                                state.connection.status =
                                    state::MediatorStatus::Connected { latency_ms: ms };
                                state.connection.last_ping_latency_ms = Some(ms);
                                // Only log manual pings (user-initiated), not keepalives
                                if is_manual {
                                    state.main_page.log(format!(
                                        "Trust-pong received from {} ✓ ({}ms)",
                                        truncate_did(sender),
                                        ms
                                    ));
                                }
                            } else {
                                state.main_page.log(format!(
                                    "Trust-pong received from {} ✓",
                                    truncate_did(sender)
                                ));
                            }
                        }
                    }
                },
                // Lifecycle log messages from the DIDCommService
                Some(log_msg) = lifecycle_log_rx.recv() => {
                    state.main_page.log(log_msg);
                },
                // Periodic keepalive ping for connectivity monitoring
                _ = keepalive_interval.tick() => {
                    if state.connection.messaging_active
                        && let Ok(ping_msg) = build_trust_ping(
                            &config.public.persona_did,
                            &config.public.mediator_did,
                        )
                    {
                        match didcomm_service
                            .send_message("persona", ping_msg, &config.public.mediator_did)
                            .await
                        {
                            Ok(()) => {
                                ping_sent_at = Some((std::time::Instant::now(), false));
                            }
                            Err(e) => {
                                state.connection.status = state::MediatorStatus::Failed(
                                    format!("keepalive failed: {e}"),
                                );
                                state.connection.messaging_active = false;
                                state.main_page.log(format!("Keepalive ping failed: {e}"));
                            }
                        }
                    }
                },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
            }
            let _ = self.state_tx.send(state.clone());
        };

        // Shut down the DIDComm service gracefully
        shutdown_token.cancel();
        didcomm_service.shutdown().await;

        Ok(result)
    }

    /// Minimal event loop for when init fails -- keeps UI alive so user sees the error and can exit.
    async fn run_degraded_loop(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        terminator: &mut Terminator,
        state: &mut State,
    ) -> Result<Interrupted> {
        loop {
            tokio::select! {
                Some(action) = action_rx.recv() => match action {
                    Action::Exit => {
                        if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        return Ok(Interrupted::UserInt);
                    }
                    Action::UXError(interrupted) => {
                        if let Err(e) = terminator.terminate(interrupted.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        return Ok(interrupted);
                    }
                    Action::MainMenuSelected(menu_item) => {
                        state.main_page.menu_panel.selected_menu = menu_item;
                    }
                    Action::MainPanelSwitch(panel) => {
                        match panel {
                            MainPanel::ContentPanel => {
                                state.main_page.menu_panel.selected = false;
                                state.main_page.content_panel.selected = true;
                            }
                            MainPanel::MainMenu => {
                                state.main_page.menu_panel.selected = true;
                                state.main_page.content_panel.selected = false;
                            }
                        }
                    }
                    _ => {}
                },
                Ok(interrupted) = interrupt_rx.recv() => {
                    return Ok(interrupted);
                }
            }
            let _ = self.state_tx.send(state.clone());
        }
    }
}

// ============================================================
// Inbox action handlers
// ============================================================

fn handle_inbox_select(state: &mut State, index: usize) {
    state.main_page.content_panel.inbox.selected_index = index;
}

fn handle_inbox_open_detail(state: &mut State, index: usize) {
    use main_page::content::{ActiveTaskView, TaskKind};

    state.main_page.content_panel.inbox.selected_index = index;
    if let Some(task) = state.main_page.content_panel.inbox.tasks.get(index) {
        let view = match &task.kind {
            TaskKind::RelationshipRequestInbound {
                from_did,
                their_did,
                reason,
                name,
            } => Some(ActiveTaskView::RelationshipRequestInbound {
                task_id: task.id.clone(),
                from_did: from_did.clone(),
                their_did: their_did.clone(),
                reason: reason.clone(),
                name: name.clone(),
            }),
            TaskKind::VRCRequestInbound { reason } => Some(ActiveTaskView::VRCRequestInbound {
                task_id: task.id.clone(),
                from_did: task.remote_did.clone(),
                reason: reason.clone(),
            }),
            TaskKind::VRCIssued => Some(ActiveTaskView::VRCIssued {
                task_id: task.id.clone(),
                issuer: task.remote_did.clone(),
            }),
            TaskKind::RelationshipRequestOutbound { our_did } => {
                Some(ActiveTaskView::RelationshipRequestOutbound {
                    task_id: task.id.clone(),
                    to_did: task.remote_did.clone(),
                    our_did: our_did.clone(),
                    state: "Request Sent".to_string(),
                })
            }
            TaskKind::VRCRequestOutbound => Some(ActiveTaskView::VRCRequestOutbound {
                task_id: task.id.clone(),
                remote_did: task.remote_did.clone(),
            }),
            TaskKind::TrustPing | TaskKind::Informational(_) => Some(ActiveTaskView::Info {
                task_id: task.id.clone(),
                type_display: task.type_display.clone(),
                remote_did: task.remote_did.clone(),
            }),
        };
        state.main_page.content_panel.inbox.active_task = view;
    }
}

/// Helper: save config after an inbox action, sync UI state, and log messages.
fn inbox_save_and_sync(
    config: &Config,
    state: &mut State,
    profile: &str,
    success_status: &str,
    success_log: &str,
) {
    state.main_page.content_panel.inbox.active_task = None;
    state.main_page.content_panel.inbox.status_message = Some(success_status.to_string());
    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log(format!("Failed to save config: {e}"));
    }
    state.main_page.sync_from_config(config);
    state.main_page.log(success_log);
}

fn inbox_error(state: &mut State, context: &str, err: &anyhow::Error) {
    state.main_page.content_panel.inbox.status_message = Some(format!("Error: {err}"));
    state.main_page.log(format!("{context}: {err}"));
}

async fn handle_inbox_accept_relationship(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    state: &mut State,
    profile: &str,
    task_id: &str,
    generate_r_did: bool,
) {
    match inbox_actions::accept_relationship_request(config, tdk, service, task_id, generate_r_did)
        .await
    {
        Ok(()) => inbox_save_and_sync(
            config,
            state,
            profile,
            "Relationship request accepted",
            "Accepted relationship request",
        ),
        Err(e) => inbox_error(state, "Failed to accept relationship", &e),
    }
}

async fn handle_inbox_reject_relationship(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    state: &mut State,
    profile: &str,
    task_id: &str,
    reason: Option<&str>,
) {
    match inbox_actions::reject_relationship_request(config, tdk, service, task_id, reason).await {
        Ok(()) => inbox_save_and_sync(
            config,
            state,
            profile,
            "Relationship request rejected",
            "Rejected relationship request",
        ),
        Err(e) => inbox_error(state, "Failed to reject relationship", &e),
    }
}

fn handle_inbox_accept_vrc(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    task_id: &str,
) {
    match inbox_actions::accept_vrc(config, task_id) {
        Ok(()) => inbox_save_and_sync(
            config,
            state,
            profile,
            "VRC accepted and stored",
            "VRC accepted and stored",
        ),
        Err(e) => inbox_error(state, "Failed to accept VRC", &e),
    }
}

async fn handle_inbox_accept_vrc_request(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    state: &mut State,
    profile: &str,
    task_id: &str,
) {
    match inbox_actions::accept_vrc_request(config, tdk, service, task_id).await {
        Ok(()) => inbox_save_and_sync(
            config,
            state,
            profile,
            "VRC issued and sent",
            "VRC issued and sent",
        ),
        Err(e) => inbox_error(state, "Failed to issue VRC", &e),
    }
}

async fn handle_inbox_reject_vrc_request(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    state: &mut State,
    profile: &str,
    task_id: &str,
    reason: Option<&str>,
) {
    match inbox_actions::reject_vrc_request(config, tdk, service, task_id, reason).await {
        Ok(()) => inbox_save_and_sync(
            config,
            state,
            profile,
            "VRC request rejected",
            "Rejected VRC request",
        ),
        Err(e) => inbox_error(state, "Failed to reject VRC request", &e),
    }
}

fn handle_inbox_dismiss_task(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    task_id: &str,
) {
    let _ = inbox_actions::dismiss_task(config, task_id);
    state.main_page.content_panel.inbox.active_task = None;
    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log(format!("Failed to save config: {e}"));
    }
    state.main_page.sync_from_config(config);
    state.main_page.log("Task dismissed");
}

fn handle_inbox_clear_all(config: &mut Box<Config>, state: &mut State, profile: &str) {
    let _ = inbox_actions::clear_all_tasks(config);
    state.main_page.content_panel.inbox.active_task = None;
    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log(format!("Failed to save config: {e}"));
    }
    state.main_page.sync_from_config(config);
    state.main_page.log("All inbox tasks cleared");
}

// ============================================================
// Relationship action handlers
// ============================================================

fn handle_relationship_open_detail(state: &mut State, index: usize) {
    use main_page::content::RelationshipsMode;
    state.main_page.content_panel.relationships.selected_index = index;
    state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail { index };
}

fn handle_relationship_start_new_request(state: &mut State) {
    use main_page::content::RelationshipsMode;
    state.main_page.content_panel.relationships.mode = RelationshipsMode::NewRequest {
        did_input: String::new(),
        alias_input: String::new(),
        reason_input: String::new(),
        generate_r_did: false,
        active_field: 0,
    };
}

fn handle_relationship_cancel_or_back(state: &mut State) {
    use main_page::content::RelationshipsMode;
    state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
    state.main_page.content_panel.relationships.status_message = None;
}

fn handle_relationship_input_update(state: &mut State, field: usize, value: String) {
    use main_page::content::RelationshipsMode;
    if let RelationshipsMode::NewRequest {
        ref mut did_input,
        ref mut alias_input,
        ref mut reason_input,
        ..
    } = state.main_page.content_panel.relationships.mode
    {
        match field {
            0 => *did_input = value,
            1 => *alias_input = value,
            _ => *reason_input = value,
        }
    }
}

fn handle_relationship_toggle_r_did(state: &mut State) {
    use main_page::content::RelationshipsMode;
    if let RelationshipsMode::NewRequest {
        ref mut generate_r_did,
        ..
    } = state.main_page.content_panel.relationships.mode
    {
        *generate_r_did = !*generate_r_did;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_relationship_submit(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    state: &mut State,
    state_tx: &tokio::sync::watch::Sender<State>,
    profile: &str,
    did: &str,
    alias: &str,
    reason: Option<&str>,
    generate_r_did: bool,
) {
    use main_page::content::RelationshipsMode;

    // Show progress immediately if R-DID generation will involve network calls
    if generate_r_did {
        state.main_page.content_panel.relationships.status_message =
            Some("Creating relationship DID...".to_string());
        state
            .main_page
            .log("Creating relationship DID via key backend...");
        let _ = state_tx.send(state.clone());
    } else {
        state.main_page.content_panel.relationships.status_message =
            Some("Sending request...".to_string());
        let _ = state_tx.send(state.clone());
    }

    match relationship_actions::send_relationship_request(
        config,
        tdk,
        service,
        did,
        alias,
        reason,
        generate_r_did,
    )
    .await
    {
        Ok(()) => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
            state.main_page.content_panel.relationships.status_message =
                Some(format!("Request sent to {}", truncate_did(did)));
            if let Err(e) = settings_actions::save_config(config, profile) {
                state.main_page.log(format!("Failed to save config: {e}"));
            }
            state.main_page.sync_from_config(config);
            state.main_page.log(format!(
                "Relationship request sent to {}",
                truncate_did(did)
            ));
        }
        Err(e) => {
            state.main_page.content_panel.relationships.status_message =
                Some(format!("Error: {e}"));
            state
                .main_page
                .log(format!("Failed to send relationship request: {e}"));
        }
    }
}

async fn handle_relationship_ping(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
) {
    use main_page::content::RelationshipsMode;
    match relationship_actions::ping_relationship(config, tdk, service, remote_p_did).await {
        Ok(()) => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
            state.main_page.content_panel.relationships.status_message =
                Some("Ping sent".to_string());
            if let Err(e) = settings_actions::save_config(config, profile) {
                state.main_page.log(format!("Failed to save config: {e}"));
            }
            state.main_page.sync_from_config(config);
            state
                .main_page
                .log(format!("Trust-ping sent to {}", truncate_did(remote_p_did)));
        }
        Err(e) => {
            state.main_page.content_panel.relationships.status_message =
                Some(format!("Ping failed: {e}"));
            state.main_page.log(format!("Ping failed: {e}"));
        }
    }
}

fn handle_relationship_remove(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
) {
    use main_page::content::RelationshipsMode;
    let _ = relationship_actions::remove_relationship(config, remote_p_did);
    state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
    state.main_page.content_panel.relationships.status_message =
        Some("Relationship removed".to_string());
    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log(format!("Failed to save config: {e}"));
    }
    state.main_page.sync_from_config(config);
    state.main_page.log("Relationship removed");
}

fn handle_relationship_edit_alias(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
    alias: &str,
) {
    use main_page::content::RelationshipsMode;
    use openvtc::config::protected_config::Contact;

    // Remove old contact entry (clears old alias mapping too)
    config
        .private
        .contacts
        .remove_contact(&mut config.public.logs, remote_p_did);

    // Re-add with the new alias
    let alias_opt = if alias.trim().is_empty() {
        None
    } else {
        Some(alias.trim().to_string())
    };
    let contact_did = Arc::new(remote_p_did.to_string());
    let contact = Arc::new(Contact {
        did: contact_did.clone(),
        alias: alias_opt.clone(),
    });
    config
        .private
        .contacts
        .contacts
        .insert(contact_did, contact.clone());
    if let Some(ref a) = alias_opt {
        config.private.contacts.aliases.insert(a.clone(), contact);
    }

    config.public.logs.insert(
        openvtc::logs::LogFamily::Config,
        format!(
            "Alias updated for {}: {}",
            remote_p_did,
            alias_opt.as_deref().unwrap_or("(removed)")
        ),
    );

    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log(format!("Failed to save config: {e}"));
    }
    state.main_page.sync_from_config(config);
    // Return to detail view — find the index for this remote_p_did
    let index = state
        .main_page
        .content_panel
        .relationships
        .relationships
        .iter()
        .position(|r| r.remote_p_did == remote_p_did)
        .unwrap_or(0);
    state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail { index };
    state.main_page.content_panel.relationships.status_message = Some("Alias updated".to_string());
    state.main_page.log("Alias updated");
}

// ============================================================
// Credential action handlers
// ============================================================

fn handle_credential_switch_tab(state: &mut State) {
    use main_page::content::CredentialTab;
    state.main_page.content_panel.credentials.selected_tab =
        match state.main_page.content_panel.credentials.selected_tab {
            CredentialTab::Received => CredentialTab::Issued,
            CredentialTab::Issued => CredentialTab::Received,
        };
    state.main_page.content_panel.credentials.selected_index = 0;
}

fn handle_credential_open_detail(state: &mut State, index: usize) {
    use main_page::content::CredentialsMode;
    state.main_page.content_panel.credentials.selected_index = index;
    state.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index };
}

fn handle_credential_back(state: &mut State) {
    use main_page::content::CredentialsMode;
    state.main_page.content_panel.credentials.mode = CredentialsMode::List;
    state.main_page.content_panel.credentials.selected_index = 0;
}

fn handle_credential_start_new_request(state: &mut State) {
    use main_page::content::CredentialsMode;
    state.main_page.content_panel.credentials.mode = CredentialsMode::NewRequest {
        relationship_index: 0,
        reason_input: String::new(),
    };
}

fn handle_credential_select_relationship(state: &mut State, index: usize) {
    use main_page::content::CredentialsMode;
    if let CredentialsMode::NewRequest {
        ref mut relationship_index,
        ..
    } = state.main_page.content_panel.credentials.mode
    {
        let established_count = state
            .main_page
            .content_panel
            .relationships
            .relationships
            .iter()
            .filter(|r| r.state == "Established")
            .count();
        if index < established_count {
            *relationship_index = index;
        }
    }
}

fn handle_credential_reason_update(state: &mut State, value: String) {
    use main_page::content::CredentialsMode;
    if let CredentialsMode::NewRequest {
        ref mut reason_input,
        ..
    } = state.main_page.content_panel.credentials.mode
    {
        *reason_input = value;
    }
}

async fn handle_credential_submit_request(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    state: &mut State,
    profile: &str,
    relationship_p_did: &str,
    reason: Option<&str>,
) {
    use main_page::content::CredentialsMode;
    match credential_actions::send_vrc_request(config, tdk, service, relationship_p_did, reason)
        .await
    {
        Ok(()) => {
            state.main_page.content_panel.credentials.mode = CredentialsMode::List;
            state.main_page.content_panel.credentials.status_message = Some(format!(
                "VRC request sent to {}",
                truncate_did(relationship_p_did)
            ));
            if let Err(e) = settings_actions::save_config(config, profile) {
                state.main_page.log(format!("Failed to save config: {e}"));
            }
            state.main_page.sync_from_config(config);
            state.main_page.log(format!(
                "VRC request sent to {}",
                truncate_did(relationship_p_did)
            ));
        }
        Err(e) => {
            state.main_page.content_panel.credentials.status_message = Some(format!("Error: {e}"));
            state
                .main_page
                .log(format!("Failed to send VRC request: {e}"));
        }
    }
}

fn handle_credential_remove(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    vrc_id: &str,
) {
    use main_page::content::CredentialsMode;
    let _ = credential_actions::remove_vrc(config, vrc_id);
    state.main_page.content_panel.credentials.mode = CredentialsMode::List;
    state.main_page.content_panel.credentials.selected_index = 0;
    state.main_page.content_panel.credentials.status_message = Some("VRC removed".to_string());
    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log(format!("Failed to save config: {e}"));
    }
    state.main_page.sync_from_config(config);
    state.main_page.log("VRC removed");
}

// ============================================================
// Contact action handlers
// ============================================================

fn handle_contact_add(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    did: &str,
    alias: Option<&str>,
) {
    match settings_actions::add_contact(config, profile, did, alias) {
        Ok(()) => {
            state.main_page.sync_from_config(config);
            state
                .main_page
                .log(format!("Contact added: {}", truncate_did(did)));
        }
        Err(e) => {
            state.main_page.log(format!("Failed to add contact: {e}"));
        }
    }
}

fn handle_contact_remove(config: &mut Box<Config>, state: &mut State, profile: &str, did: &str) {
    match settings_actions::remove_contact(config, profile, did) {
        Ok(()) => {
            state.main_page.sync_from_config(config);
            state
                .main_page
                .log(format!("Contact removed: {}", truncate_did(did)));
        }
        Err(e) => {
            state
                .main_page
                .log(format!("Failed to remove contact: {e}"));
        }
    }
}

// ============================================================
// Settings action handlers
// ============================================================

fn handle_settings_select(state: &mut State, index: usize) {
    use main_page::content::SettingsMode;
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

fn handle_settings_start_edit(state: &mut State) {
    use main_page::content::SettingsMode;
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

fn handle_settings_field_update(state: &mut State, value: String) {
    use main_page::content::SettingsMode;
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::EditFriendlyName { input }
        | SettingsMode::EditMediatorDid { input }
        | SettingsMode::EditOrgDid { input } => {
            *input = value;
        }
        _ => {}
    }
}

fn handle_settings_form_field_update(state: &mut State, field: usize, value: String) {
    use main_page::content::SettingsMode;
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { path_input, .. }
        | SettingsMode::ImportConfig { path_input, .. } => {
            if field == 0 {
                *path_input = value;
            }
            // Passphrase updates are handled via SettingsPassphraseLen
        }
        _ => {}
    }
}

fn handle_settings_passphrase_len(state: &mut State, len: usize) {
    use main_page::content::SettingsMode;
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { passphrase_len, .. }
        | SettingsMode::ImportConfig { passphrase_len, .. } => {
            *passphrase_len = len;
        }
        _ => {}
    }
}

fn handle_settings_form_tab_switch(state: &mut State) {
    use main_page::content::SettingsMode;
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { active_field, .. }
        | SettingsMode::ImportConfig { active_field, .. } => {
            *active_field = if *active_field == 0 { 1 } else { 0 };
        }
        _ => {}
    }
}

fn handle_settings_protection_option_select(state: &mut State, option: usize) {
    use main_page::content::SettingsMode;
    if let SettingsMode::ChangeProtection {
        selected_option, ..
    } = &mut state.main_page.content_panel.settings.mode
    {
        *selected_option = option;
    }
}

fn handle_settings_protection_start_input(state: &mut State) {
    use main_page::content::SettingsMode;
    if let SettingsMode::ChangeProtection { active_field, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *active_field = 1;
    }
}

fn handle_settings_protection_passphrase_len(state: &mut State, len: usize) {
    use main_page::content::SettingsMode;
    if let SettingsMode::ChangeProtection { passphrase_len, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *passphrase_len = len;
    }
}

fn handle_settings_protection_confirm_len(state: &mut State, len: usize) {
    use main_page::content::SettingsMode;
    if let SettingsMode::ChangeProtection { confirm_len, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *confirm_len = len;
    }
}

fn handle_settings_protection_tab_switch(state: &mut State, next_field: usize) {
    use main_page::content::SettingsMode;
    if let SettingsMode::ChangeProtection { active_field, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *active_field = next_field;
    }
}

/// Returns `true` if the mediator DID was changed and a reconnect is needed.
fn handle_settings_submit_edit(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    value: &str,
) -> bool {
    use main_page::content::SettingsMode;
    let idx = state.main_page.content_panel.settings.selected_index;
    let result = match idx {
        0 => settings_actions::update_friendly_name(config, profile, value),
        1 => settings_actions::update_mediator_did(config, profile, value),
        2 => settings_actions::update_org_did(config, profile, value),
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
            state.main_page.content_panel.settings.status_message = Some(format!("Error: {e}"));
            state.main_page.log(format!("Failed to save setting: {e}"));
            false
        }
    }
}

fn handle_settings_export_config(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    path: &str,
    passphrase: &str,
) {
    use main_page::content::SettingsMode;
    match settings_actions::export_config(config, path, passphrase) {
        Ok(()) => {
            config
                .public
                .logs
                .insert(LogFamily::Config, format!("Config exported to {}", path));
            let _ = settings_actions::save_config(config, profile);
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message =
                Some(format!("Config exported to {}", path));
            state.main_page.log(format!("Config exported to {}", path));
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message =
                Some(format!("Export failed: {e}"));
            state.main_page.log(format!("Config export failed: {e}"));
        }
    }
}

fn handle_settings_import_config(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    path: &str,
    passphrase: &str,
) {
    use main_page::content::SettingsMode;
    match settings_actions::import_config(path, passphrase) {
        Ok(msg) => {
            config
                .public
                .logs
                .insert(LogFamily::Config, format!("Config imported from {}", path));
            let _ = settings_actions::save_config(config, profile);
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message = Some(msg.clone());
            state.main_page.log(msg);
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message =
                Some(format!("Import failed: {e}"));
            state.main_page.log(format!("Config import failed: {e}"));
        }
    }
}

fn handle_settings_change_protection(state: &mut State) {
    use main_page::content::SettingsMode;
    state.main_page.content_panel.settings.mode = SettingsMode::ChangeProtection {
        selected_option: 0,
        passphrase_len: 0,
        confirm_len: 0,
        active_field: 0,
    };
}

fn handle_settings_set_passphrase(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    passphrase: &str,
) {
    use main_page::content::SettingsMode;
    match settings_actions::set_passphrase(config, profile, passphrase) {
        Ok(()) => {
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message =
                Some("Passphrase protection enabled".to_string());
            state.main_page.sync_from_config(config);
            state.main_page.log("Passphrase protection enabled");
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message = Some(format!("Error: {e}"));
            state
                .main_page
                .log(format!("Failed to set passphrase: {e}"));
        }
    }
}

fn handle_settings_remove_passphrase(config: &mut Box<Config>, state: &mut State, profile: &str) {
    use main_page::content::SettingsMode;
    match settings_actions::remove_passphrase(config, profile) {
        Ok(()) => {
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            state.main_page.content_panel.settings.status_message =
                Some("Protection reverted to keyring only".to_string());
            state.main_page.sync_from_config(config);
            state.main_page.log("Protection reverted to keyring only");
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message = Some(format!("Error: {e}"));
            state
                .main_page
                .log(format!("Failed to remove passphrase: {e}"));
        }
    }
}

#[cfg(feature = "openpgp-card")]
fn handle_settings_token_management(state: &mut State) {
    use main_page::content::SettingsMode;
    state.main_page.content_panel.settings.mode =
        SettingsMode::TokenManagement { selected_index: 0 };
    match openvtc::openpgp_card::get_cards() {
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
fn handle_settings_token_detect(state: &mut State) {
    match openvtc::openpgp_card::get_cards() {
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
fn handle_settings_token_factory_reset(state: &mut State) {
    match openvtc::openpgp_card::get_cards() {
        Ok(cards) if !cards.is_empty() => {
            match openvtc::openpgp_card::factory_reset(cards[0].clone()) {
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
fn handle_settings_token_back(state: &mut State) {
    use main_page::content::SettingsMode;
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

/// Build a DIDComm trust-ping message.
fn build_trust_ping(from: &str, to: &str) -> Result<affinidi_tdk::didcomm::Message, anyhow::Error> {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let message = affinidi_tdk::didcomm::Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping".to_string(),
        serde_json::json!({"response_requested": true}),
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now)
    .expires_time(60 * 5) // 5 minutes
    .finalize();

    Ok(message)
}

/// Build a trust-pong response message.
fn build_trust_pong(
    to: &str,
    ping_id: &str,
) -> Result<affinidi_tdk::didcomm::Message, anyhow::Error> {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let message = affinidi_tdk::didcomm::Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping-response".to_string(),
        serde_json::Value::Null,
    )
    .to(to.to_string())
    .thid(ping_id.to_string())
    .created_time(now)
    .finalize();

    Ok(message)
}
