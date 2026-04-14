use std::borrow::Cow;

use crate::{
    Interrupted, Terminator,
    state_handler::{
        actions::Action,
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
mod inbox_actions;
pub mod main_page;
mod message_dispatch;
pub mod messaging;
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

        // Spawn DIDComm init + validation as a background task
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
        let mut msg_task_handle: Option<tokio::task::JoinHandle<()>> = None;

        let (conn_result_tx, mut conn_result_rx) = mpsc::channel::<messaging::ConnInitResult>(1);
        let shared_state = tdk.get_shared_state();
        let persona_did = config.public.persona_did.to_string();
        let mediator_did = config.public.mediator_did.clone();

        tokio::spawn(async move {
            let result =
                messaging::init_and_validate(shared_state, persona_did, mediator_did).await;
            if let Err(e) = conn_result_tx.send(result).await {
                debug!("Failed to send connection init result: {e}");
            }
        });

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
                    Action::InboxSelectTask(index) => {
                        handle_inbox_select(&mut state, index);
                    },
                    Action::InboxOpenDetail(index) => {
                        handle_inbox_open_detail(&mut state, index);
                    },
                    Action::InboxBack => {
                        state.main_page.content_panel.inbox.active_task = None;
                    },
                    Action::InboxAcceptRelationship { task_id } => {
                        handle_inbox_accept_relationship(&mut config, &tdk, &mut state, &self.profile, &task_id).await;
                    },
                    Action::InboxRejectRelationship { task_id, reason } => {
                        handle_inbox_reject_relationship(&mut config, &tdk, &mut state, &self.profile, &task_id, reason.as_deref()).await;
                    },
                    Action::InboxAcceptVrc { task_id } => {
                        handle_inbox_accept_vrc(&mut config, &mut state, &self.profile, &task_id);
                    },
                    Action::InboxAcceptVrcRequest { task_id } => {
                        handle_inbox_accept_vrc_request(&mut config, &tdk, &mut state, &self.profile, &task_id).await;
                    },
                    Action::InboxRejectVrcRequest { task_id, reason } => {
                        handle_inbox_reject_vrc_request(&mut config, &tdk, &mut state, &self.profile, &task_id, reason.as_deref()).await;
                    },
                    Action::InboxDismissTask { task_id } => {
                        handle_inbox_dismiss_task(&mut config, &mut state, &self.profile, &task_id);
                    },
                    Action::InboxClearAll => {
                        handle_inbox_clear_all(&mut config, &mut state, &self.profile);
                    },
                    // Relationship actions
                    Action::RelationshipSelect(index) => {
                        state.main_page.content_panel.relationships.selected_index = index;
                    },
                    Action::RelationshipOpenDetail(index) => {
                        handle_relationship_open_detail(&mut state, index);
                    },
                    Action::RelationshipStartNewRequest => {
                        handle_relationship_start_new_request(&mut state);
                    },
                    Action::RelationshipCancelNewRequest | Action::RelationshipBack => {
                        handle_relationship_cancel_or_back(&mut state);
                    },
                    Action::RelationshipInputUpdate { field, value } => {
                        handle_relationship_input_update(&mut state, field, value);
                    },
                    Action::RelationshipToggleRDid => {
                        handle_relationship_toggle_r_did(&mut state);
                    },
                    Action::RelationshipSubmitRequest { did, alias, reason, generate_r_did } => {
                        handle_relationship_submit(&mut config, &tdk, &mut state, &self.profile, &did, &alias, reason.as_deref(), generate_r_did).await;
                    },
                    Action::RelationshipPing { remote_p_did } => {
                        handle_relationship_ping(&mut config, &tdk, &mut state, &self.profile, &remote_p_did).await;
                    },
                    Action::RelationshipRemove { remote_p_did } => {
                        handle_relationship_remove(&mut config, &mut state, &self.profile, &remote_p_did);
                    },
                    // Credential actions
                    Action::CredentialSwitchTab => {
                        handle_credential_switch_tab(&mut state);
                    },
                    Action::CredentialSelect(index) => {
                        state.main_page.content_panel.credentials.selected_index = index;
                    },
                    Action::CredentialOpenDetail(index) => {
                        handle_credential_open_detail(&mut state, index);
                    },
                    Action::CredentialBack | Action::CredentialCancelNewRequest => {
                        handle_credential_back(&mut state);
                    },
                    Action::CredentialStartNewRequest => {
                        handle_credential_start_new_request(&mut state);
                    },
                    Action::CredentialSelectRelationship(index) => {
                        handle_credential_select_relationship(&mut state, index);
                    },
                    Action::CredentialReasonUpdate(value) => {
                        handle_credential_reason_update(&mut state, value);
                    },
                    Action::CredentialSubmitRequest { relationship_p_did, reason } => {
                        handle_credential_submit_request(&mut config, &tdk, &mut state, &self.profile, &relationship_p_did, reason.as_deref()).await;
                    },
                    Action::CredentialRemove { vrc_id } => {
                        handle_credential_remove(&mut config, &mut state, &self.profile, &vrc_id);
                    },
                    // Contact actions
                    Action::ContactAdd { did, alias } => {
                        handle_contact_add(&mut config, &mut state, &self.profile, &did, alias.as_deref());
                    },
                    Action::ContactRemove { did } => {
                        handle_contact_remove(&mut config, &mut state, &self.profile, &did);
                    },
                    // Settings actions
                    Action::SettingsSelect(index) => {
                        handle_settings_select(&mut state, index);
                    },
                    Action::SettingsStartEdit => {
                        handle_settings_start_edit(&mut state);
                    },
                    Action::SettingsCancelEdit => {
                        state.main_page.content_panel.settings.mode = main_page::content::SettingsMode::View;
                    },
                    Action::SettingsFieldUpdate(value) => {
                        handle_settings_field_update(&mut state, value);
                    },
                    Action::SettingsFormFieldUpdate { field, value } => {
                        handle_settings_form_field_update(&mut state, field, value);
                    },
                    Action::SettingsFormTabSwitch => {
                        handle_settings_form_tab_switch(&mut state);
                    },
                    Action::SettingsProtectionOptionSelect(option) => {
                        handle_settings_protection_option_select(&mut state, option);
                    },
                    Action::SettingsProtectionStartInput => {
                        handle_settings_protection_start_input(&mut state);
                    },
                    Action::SettingsProtectionPassphraseLen(len) => {
                        handle_settings_protection_passphrase_len(&mut state, len);
                    },
                    Action::SettingsProtectionConfirmLen(len) => {
                        handle_settings_protection_confirm_len(&mut state, len);
                    },
                    Action::SettingsProtectionTabSwitch(next_field) => {
                        handle_settings_protection_tab_switch(&mut state, next_field);
                    },
                    Action::SettingsPassphraseLen(len) => {
                        handle_settings_passphrase_len(&mut state, len);
                    },
                    Action::SettingsSubmitEdit { value } => {
                        handle_settings_submit_edit(&mut config, &mut state, &self.profile, &value);
                    },
                    Action::SettingsExportConfig { path, passphrase } => {
                        handle_settings_export_config(&mut config, &mut state, &self.profile, &path, &passphrase);
                    },
                    Action::SettingsImportConfig { path, passphrase } => {
                        handle_settings_import_config(&mut config, &mut state, &self.profile, &path, &passphrase);
                    },
                    Action::SettingsChangeProtection => {
                        handle_settings_change_protection(&mut state);
                    },
                    Action::SettingsSetPassphrase { passphrase } => {
                        handle_settings_set_passphrase(&mut config, &mut state, &self.profile, &passphrase);
                    },
                    Action::SettingsRemovePassphrase => {
                        handle_settings_remove_passphrase(&mut config, &mut state, &self.profile);
                    },
                    #[cfg(feature = "openpgp-card")]
                    Action::SettingsTokenManagement => {
                        handle_settings_token_management(&mut state);
                    },
                    #[cfg(feature = "openpgp-card")]
                    Action::SettingsTokenDetect => {
                        handle_settings_token_detect(&mut state);
                    },
                    #[cfg(feature = "openpgp-card")]
                    Action::SettingsTokenFactoryReset => {
                        handle_settings_token_factory_reset(&mut state);
                    },
                    #[cfg(feature = "openpgp-card")]
                    Action::SettingsTokenBack => {
                        handle_settings_token_back(&mut state);
                    },
                    _ => {}
                },
                Some(conn_result) = conn_result_rx.recv() => {
                    state.connection.status = conn_result.status;
                    state.connection.last_ping_latency_ms = conn_result.latency_ms;

                    if let Some(ms) = conn_result.latency_ms {
                        state.main_page.log(format!("Connected to mediator ({}ms)", ms));
                    } else {
                        state.main_page.log("Connected to mediator");
                    }

                    if let (Some(atm), Some(profile)) = (conn_result.atm, conn_result.profile) {
                        let handle = tokio::spawn(messaging::run_didcomm_loop(
                            atm,
                            profile,
                            conn_result.persona_did,
                            msg_tx.clone(),
                            interrupt_rx.resubscribe(),
                        ));
                        msg_task_handle = Some(handle);
                        state.connection.messaging_active = true;
                        state.main_page.log("DIDComm messaging active");
                    }
                },
                Some(event) = msg_rx.recv() => {
                    match event {
                        messaging::MessagingEvent::TrustPingReceived { .. } => {}
                        messaging::MessagingEvent::TrustPongReceived { latency_ms, .. } => {
                            if let Some(ms) = latency_ms {
                                state.connection.last_ping_latency_ms = Some(ms);
                            }
                        }
                        messaging::MessagingEvent::ConnectionStatus(status) => {
                            match status {
                                messaging::ConnectionStatus::Connected => {
                                    state.connection.status = state::MediatorStatus::Connected {
                                        latency_ms: state.connection.last_ping_latency_ms.unwrap_or(0),
                                    };
                                }
                                messaging::ConnectionStatus::Disconnected => {
                                    state.connection.status = state::MediatorStatus::Unknown;
                                    state.connection.messaging_active = false;
                                    state.main_page.log("Mediator disconnected");
                                }
                                messaging::ConnectionStatus::Error(e) => {
                                    state.main_page.log(format!("Connection error: {}", &e));
                                    state.connection.status = state::MediatorStatus::Failed(e);
                                }
                            }
                        }
                        messaging::MessagingEvent::InboundMessage { message } => {
                            match message_dispatch::process_inbound_message(
                                &mut config,
                                &tdk,
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
                    }
                },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
            }
            let _ = self.state_tx.send(state.clone());
        };

        // Wait for messaging task to finish shutdown
        if let Some(handle) = msg_task_handle {
            let _ = handle.await;
        }

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
            } => Some(ActiveTaskView::RelationshipRequestInbound {
                task_id: task.id.clone(),
                from_did: from_did.clone(),
                their_did: their_did.clone(),
                reason: reason.clone(),
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
            _ => None,
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
    state: &mut State,
    profile: &str,
    task_id: &str,
) {
    match inbox_actions::accept_relationship_request(config, tdk, task_id).await {
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
    state: &mut State,
    profile: &str,
    task_id: &str,
    reason: Option<&str>,
) {
    match inbox_actions::reject_relationship_request(config, tdk, task_id, reason).await {
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
    state: &mut State,
    profile: &str,
    task_id: &str,
) {
    match inbox_actions::accept_vrc_request(config, tdk, task_id).await {
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
    state: &mut State,
    profile: &str,
    task_id: &str,
    reason: Option<&str>,
) {
    match inbox_actions::reject_vrc_request(config, tdk, task_id, reason).await {
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
        ref mut active_field,
        ..
    } = state.main_page.content_panel.relationships.mode
    {
        if value.is_empty() {
            *active_field = field;
        } else {
            match field {
                0 => *did_input = value,
                1 => *alias_input = value,
                _ => *reason_input = value,
            }
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
    state: &mut State,
    profile: &str,
    did: &str,
    alias: &str,
    reason: Option<&str>,
    generate_r_did: bool,
) {
    use main_page::content::RelationshipsMode;
    match relationship_actions::send_relationship_request(
        config,
        tdk,
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
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
) {
    use main_page::content::RelationshipsMode;
    match relationship_actions::ping_relationship(config, tdk, remote_p_did).await {
        Ok(()) => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
            state.main_page.content_panel.relationships.status_message =
                Some("Ping sent".to_string());
            if let Err(e) = settings_actions::save_config(config, profile) {
                state.main_page.log(format!("Failed to save config: {e}"));
            }
            state.main_page.sync_from_config(config);
            state.main_page.log("Trust ping sent");
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
    state: &mut State,
    profile: &str,
    relationship_p_did: &str,
    reason: Option<&str>,
) {
    use main_page::content::CredentialsMode;
    match credential_actions::send_vrc_request(config, tdk, relationship_p_did, reason).await {
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

fn handle_settings_submit_edit(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    value: &str,
) {
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
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message = Some(format!("Error: {e}"));
            state.main_page.log(format!("Failed to save setting: {e}"));
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
