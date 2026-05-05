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
use openvtc_core::config::{Config, UnlockCode, public_config::PublicConfig};
use openvtc_core::display::truncate_did;
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver},
};
use tracing::{debug, info};

/// Tail-truncate a DID for log-message display, fixed at 30 chars.
pub(crate) fn log_did(did: &str) -> std::borrow::Cow<'_, str> {
    truncate_did(did, 30)
}

/// Resolve a DID to a human-readable display name.
///
/// Tries: contact alias by DID → R-DID relationship → persona contact alias → truncated DID.
pub(crate) fn resolve_did_to_display(config: &openvtc_core::config::Config, did: &str) -> String {
    // Direct contact lookup
    if let Some(contact) = config.private.contacts.find_contact(did)
        && let Some(alias) = &contact.alias
    {
        return alias.clone();
    }
    // R-DID → persona DID → contact alias
    let did_arc = std::sync::Arc::new(did.to_string());
    if let Some(rel) = config.private.relationships.find_by_remote_did(&did_arc)
        && let Ok(lock) = rel.lock()
    {
        let p_did = lock.remote_p_did.to_string();
        if let Some(contact) = config.private.contacts.find_contact(&p_did)
            && let Some(alias) = &contact.alias
        {
            return alias.clone();
        }
        return log_did(&p_did).into_owned();
    }
    log_did(did).into_owned()
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
mod setup_did_git_sign_actions;
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

                        // Push the main menu skeleton *before* the slow
                        // post-setup work (keyring read, VTA round-trip,
                        // mediator handshake) so the operator isn't stuck
                        // on FinalPage for several seconds. The remaining
                        // tasks update connection status as they progress.
                        state.active_page = ActivePage::Main;
                        state.main_page.menu_panel.selected = true;
                        state.main_page.sync_from_config(&config);
                        state.connection.status =
                            state::MediatorStatus::Initializing("Loading credentials...".into());
                        let _ = self.state_tx.send(state.clone());

                        // The setup wizard saved the config but the TDK secrets
                        // resolver is empty. Load persona key secrets so the
                        // DIDComm service can authenticate with the mediator.
                        if let Err(e) = config.load_persona_secrets(&tdk).await {
                            state
                                .main_page
                                .log_error("Warning: failed to load persona keys", &e);
                        }
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

                // Dedicated channel for token-touch events.  The notifier sends a bool
                // (true = touch required, false = touch completed) and the StateHandler's
                // select loop below is the sole authority that updates `state` and
                // broadcasts it to the UI.  This preserves unidirectional data flow and
                // eliminates the previous race-prone Arc<Mutex<State>> pattern.
                //
                // The channel is always created so the select! branch below can be
                // unconditional; when the openpgp-card feature is disabled the sender is
                // dropped inside the spawn and recv() immediately returns None.
                let (token_touch_tx, mut token_touch_rx) = mpsc::unbounded_channel::<bool>();

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

                    // TokenInteractions impl for openpgp-card.
                    // Sends a plain bool through the dedicated channel instead of
                    // directly mutating shared state, keeping state transitions
                    // inside the StateHandler's main select loop.
                    #[cfg(feature = "openpgp-card")]
                    let token_notifier = {
                        use openvtc_core::config::TokenInteractions;

                        struct TokenNotifier {
                            touch_tx: mpsc::UnboundedSender<bool>,
                        }
                        impl TokenInteractions for TokenNotifier {
                            fn touch_notify(&self) {
                                let _ = self.touch_tx.send(true);
                            }
                            fn touch_completed(&self) {
                                let _ = self.touch_tx.send(false);
                            }
                        }
                        TokenNotifier {
                            touch_tx: token_touch_tx,
                        }
                    };
                    // When openpgp-card is disabled, drop the sender so the receiver
                    // in the select loop sees a closed channel immediately.
                    #[cfg(not(feature = "openpgp-card"))]
                    drop(token_touch_tx);

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
                        // Token-touch notifications arrive through the dedicated channel
                        // so that state is mutated only here, inside the StateHandler loop.
                        Some(pending) = token_touch_rx.recv() => {
                            state.token_touch_pending = pending;
                            self.state_tx.send(state.clone())?;
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

        // Set the profile name once (doesn't change during runtime)
        state.main_page.content_panel.vta.profile = self.profile.clone();

        // Fetch VTA context name if using VTA backend. The helper handles
        // both DIDComm and REST transports automatically.
        if matches!(
            &config.key_backend,
            openvtc_core::config::KeyBackend::Vta { .. }
        ) {
            if let Ok(client) =
                openvtc_core::config::build_runtime_vta_client(&config.key_backend).await
                && let Ok(resp) = client.list_contexts().await
            {
                if let Some(ctx) = resp
                    .contexts
                    .iter()
                    .find(|c| c.did.as_deref() == Some(config.public.persona_did.as_str()))
                {
                    state.main_page.content_panel.vta.context_name = Some(ctx.name.clone());
                } else if let Some(ctx) = resp.contexts.first() {
                    // Fallback to first context
                    state.main_page.content_panel.vta.context_name = Some(ctx.name.clone());
                }
            }
        }

        // Send initial state immediately so the UI renders without blocking
        state.connection.status = state::MediatorStatus::Connecting;
        let _ = self.state_tx.send(state.clone());

        // Start the DIDComm service (connection lifecycle, message dispatch, sending).
        // Bounded so a misbehaving mediator can't grow our memory without limit;
        // overflows surface as `try_send` warnings and the message is dropped
        // (the mediator pickup protocol will redeliver once we drain).
        let (didcomm_event_tx, mut didcomm_event_rx) =
            mpsc::channel(didcomm::DIDCOMM_EVENT_CHANNEL_CAPACITY);
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
                    state::MediatorStatus::Failed(format!("DIDComm service: {e:#}"));
                state
                    .main_page
                    .log_error("DIDComm service failed to start", &e);
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

        // Process-lifetime LRU of inbound message IDs. Backstop for replay
        // and mediator-pickup duplicates beyond what the TDK already filters.
        let mut seen_messages = message_dispatch::SeenMessages::new();

        // Forward lifecycle events (connect/disconnect/restart) to the activity log
        let (lifecycle_log_tx, mut lifecycle_log_rx) = mpsc::unbounded_channel::<String>();
        let _lifecycle_handle = didcomm::spawn_lifecycle_logger(&didcomm_service, lifecycle_log_tx);

        // Log registered listeners for diagnostics
        let listeners = didcomm_service.list_listeners().await;
        for l in &listeners {
            debug!(id = %l.id, state = ?l.state, "registered listener");
        }
        info!(count = listeners.len(), "DIDComm listeners registered");

        // Wait for persona listener to connect.
        // Latency starts at 0 and updates from the first keepalive ping round-trip.
        match didcomm_service
            .wait_connected(
                didcomm::PERSONA_LISTENER_ID,
                std::time::Duration::from_secs(30),
            )
            .await
        {
            Ok(()) => {
                state.connection.status = state::MediatorStatus::Connected;
                state.connection.messaging_active = true;
                state.main_page.log("Connected to mediator");
            }
            Err(e) => {
                state.connection.status = state::MediatorStatus::Failed(format!("{e:#}"));
                state.main_page.log_error("Mediator connection failed", &e);
            }
        }
        let _ = self.state_tx.send(state.clone());

        // Track when a manual trust-ping was sent (for activity log latency display).
        let mut ping_sent_at: Option<std::time::Instant> = None;

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
                    Action::Inbox(ia) => {
                        inbox_actions::dispatch(
                            ia,
                            &mut config,
                            &tdk,
                            &didcomm_service,
                            &mut state,
                            &self.state_tx,
                            &self.profile,
                        )
                        .await;
                    },
                    Action::Relationship(ra) => {
                        relationship_actions::dispatch(
                            ra,
                            &mut config,
                            &tdk,
                            &didcomm_service,
                            &mut state,
                            &self.state_tx,
                            &self.profile,
                            &mut ping_sent_at,
                        )
                        .await;
                    },
                    Action::Credential(ca) => {
                        credential_actions::dispatch(
                            ca,
                            &mut config,
                            &tdk,
                            &didcomm_service,
                            &mut state,
                            &self.profile,
                        )
                        .await;
                    },
                    Action::Contact(ca) => {
                        settings_actions::dispatch_contact(ca, &mut config, &mut state, &self.profile);
                    },
                    Action::Settings(sa) => {
                        match settings_actions::dispatch(
                            sa,
                            &mut config,
                            &tdk,
                            &didcomm_service,
                            &mut state,
                            &self.profile,
                        )
                        .await
                        {
                            settings_actions::SettingsOutcome::Continue => {}
                            settings_actions::SettingsOutcome::ExitUserInt => {
                                if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                                    debug!("Failed to send terminate signal: {e}");
                                }
                                break Interrupted::UserInt;
                            }
                        }
                    },
                    _ => {}
                },
                // DIDComm inbound message events
                Some(event) = didcomm_event_rx.recv() => {
                    match event {
                        didcomm::DIDCommEvent::InboundMessage { message, .. } => {
                            // Capture message info before processing for detailed logging
                            let msg_type = message.typ.clone();
                            let msg_from = message.from.clone().unwrap_or_else(|| "unknown".into());
                            let msg_to = message.to.as_ref().and_then(|v| v.first()).cloned().unwrap_or_default();
                            let msg_thid = message.thid.clone().unwrap_or_else(|| "none".into());

                            match message_dispatch::process_inbound_message(
                                &mut config,
                                &tdk,
                                &didcomm_service,
                                &mut seen_messages,
                                &message,
                            )
                            .await
                            {
                                Ok(true) => {
                                    if let Err(e) = settings_actions::save_config(&config, &self.profile) {
                                        state.main_page.log_error("Failed to save config", &e);
                                    }
                                    state.main_page.sync_from_config(&config);
                                    // Extract short type name for summary
                                    let short_type = msg_type.rsplit('/').next().unwrap_or(&msg_type);
                                    state.main_page.log_detailed(
                                        format!("Inbound: {short_type}"),
                                        format!(
                                            "Inbound DIDComm Message\n\
                                             ───────────────────────\n\
                                             Type:    {msg_type}\n\
                                             From:    {msg_from}\n\
                                             To:      {msg_to}\n\
                                             thid:    {msg_thid}",
                                        ),
                                    );
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    state.main_page.log_detailed(
                                        format!("Message error: {e}"),
                                        format!(
                                            "Failed Inbound Message\n\
                                             ──────────────────────\n\
                                             Type:    {msg_type}\n\
                                             From:    {msg_from}\n\
                                             To:      {msg_to}\n\
                                             thid:    {msg_thid}\n\
                                             Error:   {e}",
                                        ),
                                    );
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
                                        .map(|l| l.state == openvtc_core::relationships::RelationshipState::Established)
                                        .unwrap_or(false)
                                })
                                .unwrap_or(false);

                            if is_mediator || has_relationship {
                                // Send pong to verified sender, setting `from` to our
                                // listener's DID so the recipient can identify us.
                                let our_listener_did = didcomm_service
                                    .listener_did(&listener_id)
                                    .await
                                    .unwrap_or_else(|| config.public.persona_did.to_string());
                                if let Some(ref from_did) = from
                                    && let Ok(pong_msg) =
                                        build_trust_pong(&our_listener_did, from_did, &message_id)
                                    && let Err(e) = didcomm_service
                                        .send_message(&listener_id, pong_msg, from_did)
                                        .await
                                {
                                    state.main_page.log_error("Failed to send pong", &e);
                                }
                                let ping_display = resolve_did_to_display(&config, sender);
                                state.main_page.log_detailed(
                                    format!("Ping from {ping_display} — pong sent"),
                                    format!(
                                        "Trust-Ping Received\n\
                                         ───────────────────\n\
                                         From (display):  {ping_display}\n\
                                         From (DID):      {sender}\n\
                                         Listener:        {listener_id}\n\
                                         Response:        pong sent",
                                    ),
                                );
                            } else {
                                state.main_page.log_detailed(
                                    format!("Ping from {} — ignored", log_did(sender)),
                                    format!(
                                        "Trust-Ping Rejected\n\
                                         ───────────────────\n\
                                         From (DID):      {sender}\n\
                                         Reason:          no established relationship",
                                    ),
                                );
                            }
                        }
                        didcomm::DIDCommEvent::TrustPongReceived { from } => {
                            debug!(from = ?from, "TrustPongReceived event");
                            let sender_did = from.as_deref().unwrap_or("");
                            // Pong often has no `from` field. Resolve by looking
                            // at our most recent outbound ping task to determine
                            // who we pinged.
                            let sender_display = if sender_did.is_empty() {
                                // Find the most recent TrustPing task to get the target
                                config
                                    .private
                                    .tasks
                                    .tasks
                                    .values()
                                    .filter_map(|t| {
                                        let task = t.lock().ok()?;
                                        if let openvtc_core::tasks::TaskType::TrustPing { to, .. } = &task.type_ {
                                            Some(resolve_did_to_display(&config, to))
                                        } else {
                                            None
                                        }
                                    })
                                    .next()
                                    .unwrap_or_else(|| "unknown".to_string())
                            } else {
                                resolve_did_to_display(&config, sender_did)
                            };
                            let ms = ping_sent_at
                                .take()
                                .map(|sent_at| sent_at.elapsed().as_millis());
                            let latency_str = ms
                                .map(|v| format!(" ({v}ms)"))
                                .unwrap_or_default();
                            state.main_page.log_detailed(
                                format!("Pong from {sender_display}{latency_str}"),
                                format!(
                                    "Trust-Pong Received\n\
                                     ───────────────────\n\
                                     From (display):  {sender_display}\n\
                                     From (DID):      {sender_did}\n\
                                     Latency:         {}",
                                    ms.map(|v| format!("{v}ms")).unwrap_or_else(|| "n/a".into()),
                                ),
                            );
                        }
                    }
                },
                // Lifecycle log messages from the DIDCommService
                Some(log_msg) = lifecycle_log_rx.recv() => {
                    state.main_page.log(log_msg);
                },
                // (keepalive removed — WebSocket-level pings handle connectivity)
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

// Per-domain action dispatch lives in the corresponding sub-module:
//   inbox_actions::dispatch
//   relationship_actions::dispatch
//   credential_actions::dispatch
//   settings_actions::dispatch / dispatch_contact

/// Build a DIDComm trust-pong message in response to a verified ping.
/// Used inline by the trust-ping handler in the main loop.
fn build_trust_pong(
    from: &str,
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
    .from(from.to_string())
    .to(to.to_string())
    .thid(ping_id.to_string())
    .created_time(now)
    .finalize();

    Ok(message)
}
