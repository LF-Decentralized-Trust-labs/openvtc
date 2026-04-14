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
use secrecy::SecretString;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tracing::debug;

pub mod actions;
mod inbox_actions;
pub mod main_page;
mod message_dispatch;
pub mod messaging;
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
    state_tx: UnboundedSender<State>,
    profile: String,
    starting_mode: StartingMode,
}

pub(crate) enum SetupWizardExit {
    Interrupted(Interrupted),
    Config(Box<Config>),
}

impl StateHandler {
    pub fn new(profile: &str, starting_mode: StartingMode) -> (Self, UnboundedReceiver<State>) {
        let (state_tx, state_rx) = mpsc::unbounded_channel::<State>();

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
                self.state_tx.send(state.clone())?;

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
                            state_tx: mpsc::UnboundedSender<crate::state_handler::state::State>,
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
                            self.state_tx.send(state.clone())?;
                        }
                        result = &mut load_handle => {
                            match result {
                                Ok(Ok((tdk, config))) => break (tdk, config),
                                Ok(Err(e)) => {
                                    state.connection.status =
                                        state::MediatorStatus::Failed(format!("{e}"));
                                    self.state_tx.send(state.clone())?;
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
                                    self.state_tx.send(state.clone())?;
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
        self.state_tx.send(state.clone())?;

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
                        // High bit set = open detail view
                        if index & 0x8000_0000 != 0 {
                            let real_index = index & 0x7FFF_FFFF;
                            state.main_page.content_panel.inbox.selected_index = real_index;
                            // Build ActiveTaskView from the task at this index
                            if let Some(task) = state.main_page.content_panel.inbox.tasks.get(real_index) {
                                use main_page::content::{ActiveTaskView, TaskKind};
                                let view = match &task.kind {
                                    TaskKind::RelationshipRequestInbound { from_did, their_did, reason } => {
                                        Some(ActiveTaskView::RelationshipRequestInbound {
                                            task_id: task.id.clone(),
                                            from_did: from_did.clone(),
                                            their_did: their_did.clone(),
                                            reason: reason.clone(),
                                        })
                                    }
                                    TaskKind::VRCRequestInbound { reason } => {
                                        Some(ActiveTaskView::VRCRequestInbound {
                                            task_id: task.id.clone(),
                                            from_did: task.remote_did.clone(),
                                            reason: reason.clone(),
                                        })
                                    }
                                    TaskKind::VRCIssued => {
                                        Some(ActiveTaskView::VRCIssued {
                                            task_id: task.id.clone(),
                                            issuer: task.remote_did.clone(),
                                        })
                                    }
                                    _ => None,
                                };
                                state.main_page.content_panel.inbox.active_task = view;
                            }
                        } else {
                            state.main_page.content_panel.inbox.selected_index = index;
                        }
                    },
                    Action::InboxBack => {
                        state.main_page.content_panel.inbox.active_task = None;
                    },
                    Action::InboxAcceptRelationship { task_id } => {
                        match inbox_actions::accept_relationship_request(&mut config, &tdk, &task_id).await {
                            Ok(()) => {
                                state.main_page.content_panel.inbox.active_task = None;
                                state.main_page.content_panel.inbox.status_message = Some("Relationship request accepted".to_string());
                                state.main_page.sync_from_config(&config);
                            }
                            Err(e) => {
                                state.main_page.content_panel.inbox.status_message = Some(format!("Error: {e}"));
                            }
                        }
                    },
                    Action::InboxRejectRelationship { task_id, reason } => {
                        match inbox_actions::reject_relationship_request(&mut config, &tdk, &task_id, reason.as_deref()).await {
                            Ok(()) => {
                                state.main_page.content_panel.inbox.active_task = None;
                                state.main_page.content_panel.inbox.status_message = Some("Relationship request rejected".to_string());
                                state.main_page.sync_from_config(&config);
                            }
                            Err(e) => {
                                state.main_page.content_panel.inbox.status_message = Some(format!("Error: {e}"));
                            }
                        }
                    },
                    Action::InboxAcceptVrc { task_id } => {
                        match inbox_actions::accept_vrc(&mut config, &task_id) {
                            Ok(()) => {
                                state.main_page.content_panel.inbox.active_task = None;
                                state.main_page.content_panel.inbox.status_message = Some("VRC accepted and stored".to_string());
                                state.main_page.sync_from_config(&config);
                            }
                            Err(e) => {
                                state.main_page.content_panel.inbox.status_message = Some(format!("Error: {e}"));
                            }
                        }
                    },
                    Action::InboxDismissTask { task_id } => {
                        let _ = inbox_actions::dismiss_task(&mut config, &task_id);
                        state.main_page.content_panel.inbox.active_task = None;
                        state.main_page.sync_from_config(&config);
                    },
                    _ => {}
                },
                Some(conn_result) = conn_result_rx.recv() => {
                    state.connection.status = conn_result.status;
                    state.connection.last_ping_latency_ms = conn_result.latency_ms;

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
                                }
                                messaging::ConnectionStatus::Error(e) => {
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
                                    state.main_page.sync_from_config(&config);
                                }
                                Ok(false) => {}
                                Err(e) => {
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
            self.state_tx.send(state.clone())?;
        };

        // Wait for messaging task to finish shutdown
        if let Some(handle) = msg_task_handle {
            let _ = handle.await;
        }

        Ok(result)
    }

    /// Minimal event loop for when init fails — keeps UI alive so user sees the error and can exit.
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
            self.state_tx.send(state.clone())?;
        }
    }
}
