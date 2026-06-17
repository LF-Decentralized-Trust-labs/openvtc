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
use tracing::{debug, info, warn};

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
    if let Some(rel) = config.private.relationships.find_by_remote_did(&did_arc) {
        let p_did = rel.remote_p_did.to_string();
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
mod background_dispatch;
mod credential_actions;
pub mod didcomm;
mod dispatch_util;
mod inbox_actions;
pub mod join;
mod join_flow;
pub mod main_page;
mod message_dispatch;
mod relationship_actions;
mod save_coalesce;
mod session_manager;
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

pub enum StartingMode {
    NotSet,
    // Eager main-page boot path, superseded by `MainPageDeferred` (which main.rs
    // now constructs). The match-arm handler is retained for the eager path.
    #[allow(dead_code)]
    MainPage(Box<Config>, TDK),
    MainPageDeferred(DeferredLoad),
    SetupWizard,
}

pub struct StateHandler {
    state_tx: tokio::sync::watch::Sender<State>,
    profile: String,
    starting_mode: StartingMode,
    /// Invitation credential (VIC) supplied at launch via `--invitation`, seeded
    /// into the loop's initial [`State`] so the join flow can present it.
    invitation_credential: Option<serde_json::Value>,
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
                invitation_credential: None,
            },
            state_rx,
        )
    }

    /// Seed the invitation credential (VIC) to present when joining, parsed from
    /// the `--invitation <file>` launch argument. No-op when `None`.
    pub fn set_invitation_credential(&mut self, vic: Option<serde_json::Value>) {
        self.invitation_credential = vic;
    }

    pub async fn main_loop(
        mut self,
        mut terminator: Terminator,
        mut action_rx: UnboundedReceiver<Action>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> Result<Interrupted> {
        let mut state = State::default();
        // Carry the launch-supplied invitation credential into the live state so
        // the join flow can present it (it survives `JoinState::reset`, which
        // only clears the transient join sub-state).
        state.invitation_credential = self.invitation_credential.take();

        let starting_mode = std::mem::replace(&mut self.starting_mode, StartingMode::NotSet);
        // The third element is the live admin VTA session handed back by
        // `load_step2` (PERF #1) for reuse below; `None` for the modes that
        // don't open one (they fall back to building one as before).
        let (tdk, config, loaded_admin_vta) = match starting_mode {
            StartingMode::MainPage(config, tdk) => {
                state.active_page = ActivePage::Main;
                state.main_page.menu_panel.selected = true;
                state.main_page.config = (&config).into();
                state.main_page.log("Configuration loaded");

                (tdk.to_owned(), config, None)
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

                        // Show the loading screen during the slow post-setup work
                        // (keyring read, VTA round-trip, mediator handshake)
                        // instead of a not-yet-interactive main page; it switches
                        // to Main once the connection is ready.
                        state.active_page = ActivePage::Loading;
                        state.main_page.menu_panel.selected = true;
                        state.main_page.sync_from_config(&config);
                        state.connection.status =
                            state::MediatorStatus::Initializing("Loading credentials...".into());
                        let _ = self.state_tx.send(state.clone());

                        // The setup wizard saved the config but the TDK secrets
                        // resolver is empty. Load persona key secrets so the
                        // DIDComm service can authenticate with the mediator.
                        // R-A-5: a State-A account has no persona, so there are no
                        // secrets to load — skip it (and the VTA round-trip).
                        if config.active_identity().is_some()
                            && let Err(e) = config.load_persona_secrets(&tdk).await
                        {
                            state
                                .main_page
                                .log_error("Warning: failed to load persona keys", &e);
                        }
                        state.main_page.log("Setup complete — configuration loaded");

                        (tdk, config, None)
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
                // Show the loading screen while the config decrypts and the
                // mediator connection is established; it switches to Main once
                // ready (or stays up to show a startup error).
                state.active_page = ActivePage::Loading;
                state.main_page.menu_panel.selected = true;
                state.main_page.config = main_page::MainMenuConfigState {
                    name: deferred.public_config.friendly_name.clone(),
                    // The persona DID now lives in the encrypted account, which
                    // isn't decrypted yet at this pre-load render. It (and the
                    // working community name) populate from the full Config once
                    // load_step2 completes.
                    did: std::sync::Arc::new(String::new()),
                    community: String::new(),
                };
                state.connection.status = state::MediatorStatus::Initializing("Starting...".into());
                let _ = self.state_tx.send(state.clone());

                // Spawn TDK init + config load as a background task with
                // hierarchical progress reporting: each event is (major, sub).
                let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<(String, String)>();

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
                    let on_progress = |major: &str, sub: &str| {
                        if let Err(e) = progress_tx.send((major.to_string(), sub.to_string())) {
                            debug!("Failed to send progress event: {e}");
                        }
                    };

                    on_progress("Local configuration", "Starting TDK");
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

                    // PERF #1: load_step2 returns its live admin VTA session for
                    // reuse downstream instead of opening a second one here.
                    let (config, admin_session) = Config::load_step2(
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

                    Ok::<_, anyhow::Error>((tdk, config, admin_session))
                });

                // Listen for progress updates + handle user actions while
                // loading. `progress` drives the hierarchical loading model,
                // stamping each sub-step/major with its duration as the next
                // begins (and the whole thing when the load finishes).
                let mut progress = state::LoadingProgress::default();
                let (tdk, config, loaded_admin_vta) = loop {
                    tokio::select! {
                        Some((major, sub)) = progress_rx.recv() => {
                            progress.begin(&mut state.loading, &major, &sub);
                            state.tip_index = state.tip_index.wrapping_add(1);
                            state.connection.status =
                                state::MediatorStatus::Initializing(
                                    format!("{major} — {sub}"),
                                );
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
                                Ok(Ok((tdk, config, admin_session))) => {
                                    // Stamp the final step + major as Done.
                                    progress.finish(&mut state.loading);
                                    break (tdk, config, admin_session);
                                }
                                Ok(Err(e)) => {
                                    progress.fail(&mut state.loading);
                                    state.connection.status =
                                        state::MediatorStatus::Failed(format!("{e}"));
                                    let _ = self.state_tx.send(state.clone());
                                    // No config loaded here — join is unavailable.
                                    return self
                                        .run_degraded_loop_terminal(
                                            &mut action_rx,
                                            &mut interrupt_rx,
                                            &mut terminator,
                                            &mut state,
                                            None,
                                        )
                                        .await;
                                }
                                Err(join_err) => {
                                    progress.fail(&mut state.loading);
                                    state.connection.status =
                                        state::MediatorStatus::Failed(
                                            format!("Internal error: {join_err}"),
                                        );
                                    let _ = self.state_tx.send(state.clone());
                                    return self
                                        .run_degraded_loop_terminal(
                                            &mut action_rx,
                                            &mut interrupt_rx,
                                            &mut terminator,
                                            &mut state,
                                            None,
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

                (tdk, config, loaded_admin_vta)
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

        // The always-on admin VTA session for VTA backends. It stays open for
        // the whole time openvtc runs and is reused by every runtime VTA op
        // (context-name fetch, relationship creation, and future community joins
        // / context creation), so the admin DID holds ONE mediator connection
        // instead of reconnecting per operation. It is shut down at every exit
        // path below (degraded returns + end of the main loop).
        //
        // PERF #1: prefer the session `load_step2` already opened (handed back
        // as `loaded_admin_vta`) so the whole runtime uses a SINGLE admin
        // connection. Only fall back to opening one here when there isn't one
        // (the SetupWizard / pre-loaded-Config modes, or a State-A account that
        // had no persona to open a session for).
        let admin_vta: Option<vta_sdk::client::VtaClient> = if loaded_admin_vta.is_some() {
            loaded_admin_vta
        } else if matches!(
            &config.key_backend,
            openvtc_core::config::KeyBackend::Vta { .. }
        ) {
            openvtc_core::config::build_runtime_vta_client(&config.key_backend)
                .await
                .ok()
        } else {
            None
        };

        // Fetch VTA context name, reusing the always-on admin session.
        if let Some(client) = admin_vta.as_ref()
            && let Ok(resp) = client.list_contexts().await
        {
            if let Some(ctx) = resp
                .contexts
                .iter()
                .find(|c| c.did.as_deref() == Some(config.persona_did()))
            {
                state.main_page.content_panel.vta.context_name = Some(ctx.name.clone());
            } else if let Some(ctx) = resp.contexts.first() {
                // Fallback to first context
                state.main_page.content_panel.vta.context_name = Some(ctx.name.clone());
            }
        }

        // Phase 1 (config load + VTA) is complete. Stay on the loading screen
        // and offer "Press Enter to continue" — but kick off phase 2 (the
        // per-community DIDComm connection) right away below, so the work is
        // already happening in the background regardless of when the user hits
        // Enter. Dismissing the loading screen (Enter) reveals the main page.
        state.loading_complete = true;

        // A State-A account has no persona/community yet (R-A-5): there is no
        // DID to open a DIDComm session for. Skip the persona listener entirely
        // and run the responsive degraded loop so the user can still navigate,
        // open the Communities page, and start a join.
        //
        // Hot-start: if the user *joins* a community in the degraded loop, the
        // join mints a persona into `config.identities` (so `active_identity()`
        // flips None→Some). The degraded loop detects that and hands the runtime
        // context back as `DegradedOutcome::Joined` instead of looping, so we
        // fall through to the messaging setup below and bring up the persona
        // listener immediately — no process restart needed to receive the
        // approval credential.
        let (tdk, mut config, admin_vta) = if config.active_identity().is_none() {
            state.connection.status = state::MediatorStatus::NoActiveCommunity;
            let _ = self.state_tx.send(state.clone());
            // No persona yet (State A). Hand the always-on admin session to the
            // degraded loop so the Communities `j` → join flow (R-A-5 Stage 4)
            // can reuse it; the loop closes it on exit (or hands it back on a
            // successful in-session join).
            let join_ctx = DegradedJoinContext {
                tdk,
                config,
                admin_vta,
                profile: self.profile.clone(),
            };
            match self
                .run_degraded_loop(
                    &mut action_rx,
                    &mut interrupt_rx,
                    &mut terminator,
                    &mut state,
                    Some(join_ctx),
                )
                .await?
            {
                DegradedOutcome::Exit(interrupted) => return Ok(interrupted),
                DegradedOutcome::Joined(ctx) => {
                    state.main_page.sync_from_config(&ctx.config);
                    (ctx.tdk, ctx.config, ctx.admin_vta)
                }
            }
        } else {
            (tdk, config, admin_vta)
        };

        // Point the runtime active identity at the default working community and
        // refilter the community-scoped panels before the first paint (D10 /
        // R-C-6) — otherwise a multi-persona account renders empty panels until
        // the first event re-syncs (the per-path syncs above run with no
        // selection set yet).
        state.reconcile_selected_community(&config.account);
        let initial_active = state
            .selected_community
            .as_ref()
            .and_then(|vtc| config.account.community(vtc))
            .map(|c| c.persona_ref);
        config.set_active_persona(initial_active);
        state.main_page.sync_from_config(&config);

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
                // Messaging is down but the admin VTA session may still be live;
                // hand it to the degraded loop so the user can still join a
                // community (State-B path). The loop closes the session on exit.
                let join_ctx = DegradedJoinContext {
                    tdk,
                    config,
                    admin_vta,
                    profile: self.profile.clone(),
                };
                return self
                    .run_degraded_loop_terminal(
                        &mut action_rx,
                        &mut interrupt_rx,
                        &mut terminator,
                        &mut state,
                        Some(join_ctx),
                    )
                    .await;
            }
        };

        // Process-lifetime LRU of inbound message IDs. Backstop for replay
        // and mediator-pickup duplicates beyond what the TDK already filters.
        let mut seen_messages = openvtc_core::messaging::SeenMessages::new();

        // Forward lifecycle events (connect/disconnect/restart) to the activity log
        let (lifecycle_log_tx, mut lifecycle_log_rx) = mpsc::unbounded_channel::<String>();
        let _lifecycle_handle = didcomm::spawn_lifecycle_logger(&didcomm_service, lifecycle_log_tx);

        // Log registered listeners for diagnostics
        let listeners = didcomm_service.list_listeners().await;
        for l in &listeners {
            debug!(id = %l.id, state = ?l.state, "registered listener");
        }
        info!(count = listeners.len(), "DIDComm listeners registered");

        // Phase 2 (community/persona DIDComm connection) runs ASYNCHRONOUSLY: we
        // do NOT block the UI waiting for the listener. The main page is already
        // showing (Connecting); the persona connection proceeds in the
        // background and the runtime loop below flips the status to Connected the
        // moment a `ListenerEvent::Connected` arrives — and back to Connecting on
        // a disconnect. Subscribe to typed lifecycle events for that.
        let mut listener_events = didcomm_service.subscribe();

        // Supervised multi-session manager (D11/D15): one persona-session per
        // active community (a reused persona shares one), tracking per-session
        // connection status over the listeners `start_service` already launched.
        // Messaging runs through it from here on; at N=1 it holds one session and
        // behaves identically to the previous single global flag.
        let mut session_manager = session_manager::SessionManager::default();
        {
            use session_manager::RegisterOutcome;
            // NOTE: a mid-session leave/reject/expire does NOT yet deregister its
            // session (that is T6/T7), so until then `any_connected()` can read
            // live for a persona whose communities have all gone inactive. Startup
            // registers exactly the communities that require a live session at load
            // time (`IdentityRegistry::sessions`).
            let registry = openvtc_core::identity::IdentityRegistry::new(&config.account);
            let mut at_capacity = 0usize;
            for (persona_id, vtcs) in registry.sessions() {
                let Some(ctx) = config.identities.get(&persona_id) else {
                    // A live community whose persona didn't resolve to an identity
                    // has no listener either — surfaced here for parity, not silent.
                    debug!(%persona_id, "live-community persona missing from resolved identities — not tracked");
                    continue;
                };
                let lid = didcomm::persona_listener_id(&ctx.did);
                for vtc in vtcs {
                    if matches!(
                        session_manager.register(persona_id, &lid, vtc.clone()),
                        RegisterOutcome::AtCapacity
                    ) {
                        at_capacity += 1;
                        warn!(%persona_id, vtc = %vtc, "session manager at capacity — community not tracked");
                    }
                }
            }
            // No silent caps (D15): tell the user if any community exceeded the bound.
            if at_capacity > 0 {
                state.main_page.log(format!(
                    "Warning: {at_capacity} communit{} exceeded the session limit ({}) and are not actively connected.",
                    if at_capacity == 1 { "y" } else { "ies" },
                    session_manager.max_sessions(),
                ));
            }
        }

        state.connection.status = state::MediatorStatus::Connecting;
        state.main_page.log("Connecting to the mediator…");
        let _ = self.state_tx.send(state.clone());

        // Track when a manual trust-ping was sent (for activity log latency display).
        let mut ping_sent_at: Option<std::time::Instant> = None;

        // Background-dispatch plumbing (R13). Network-bound actions whose await
        // would otherwise park the whole select loop are spawned as background
        // tasks; they do I/O only and send their result back as a
        // `DispatchOutcome` on this channel. The select arm below applies the
        // outcome on the loop thread (the single mutator), keeping the loop live
        // during the wait. `in_flight` rejects a second action on a busy domain.
        let (dispatch_tx, mut dispatch_rx) =
            mpsc::unbounded_channel::<background_dispatch::DispatchOutcome>();
        let mut in_flight = background_dispatch::InFlight::default();

        // Coalesced + offloaded config persistence (R11). Mutation sites mark the
        // config dirty on the loop thread instead of saving inline; the
        // `deadline` arm below debounces a burst into a single `spawn_blocking`
        // save, with at most one in flight at a time. Durability-critical points
        // (Exit, passphrase/protection change, export) force-flush synchronously.
        let mut save = save_coalesce::SaveScheduler::new(self.profile.clone());
        // Channel carrying a completed background save's success flag, so the loop
        // can clear the in-flight flag and re-arm if the config was dirtied again
        // while the save ran. Save failures are surfaced as a status/log here,
        // matching the pre-R11 inline `save_config` failure handling.
        let (save_done_tx, mut save_done_rx) = mpsc::unbounded_channel::<Result<(), String>>();

        // 7-day Pending timeout sweep (R-B-7 / D16). `interval`'s first tick fires
        // immediately, so a Pending that aged out while the app was closed expires
        // on launch; thereafter it sweeps hourly.
        let mut pending_expiry_tick = tokio::time::interval(std::time::Duration::from_secs(3600));

        let result = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => match action {
                    // Shared nav reducer first: pure-state nav arms live in exactly
                    // one place (`handle_nav_action`). It returns true when it
                    // handled the action; the loop-specific arms below run only when
                    // it didn't.
                    _ if handle_nav_action(&mut state, &action) => {},
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
                    Action::DeleteCommunity(i) => {
                        // Capture the deleted community + its persona BEFORE the
                        // delete so we can deregister its session and tear down
                        // *its* listener (not the active one) if its persona ends
                        // up with no live community.
                        let target = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .get(i)
                            .map(|c| (c.vtc_did.clone(), c.persona_ref));
                        self.remove_community(&mut state, &mut config, &mut save, i);
                        // A deleted community must not leave its persona's mediator
                        // connection running. Deregister it from the session
                        // manager (D15/R-S-3); if that persona no longer has any
                        // live community, stop and remove its listener so the
                        // connection is torn down with the community, not left
                        // dangling.
                        if let Some((vtc, pid)) = target {
                            let removed = session_manager.deregister(&vtc);
                            let still_live = config
                                .account
                                .communities
                                .values()
                                .any(|c| c.persona_ref == pid && c.is_live());
                            if !still_live
                                && let Some(did) =
                                    config.identities.get(&pid).map(|id| id.did.clone())
                            {
                                // Prefer the listener id the manager recorded for
                                // the torn-down session; fall back to deriving it.
                                let listener_id = removed
                                    .map(|s| s.listener_id)
                                    .unwrap_or_else(|| didcomm::persona_listener_id(&did));
                                if let Err(e) =
                                    didcomm_service.remove_listener(&listener_id).await
                                {
                                    debug!("remove_listener after community delete: {e}");
                                }
                                state
                                    .main_page
                                    .log("Community removed — persona listener stopped.");
                            }
                        }
                        // Drop the global messaging status only when NO persona
                        // has a live community left.
                        if !config.account.communities.values().any(|c| c.is_live()) {
                            state.connection.status = state::MediatorStatus::NoActiveCommunity;
                            state.connection.messaging_active = false;
                        }
                    },
                    Action::SetActiveCommunity(i) => {
                        // Switch the working context to the Active community at
                        // display index `i` (R-C-6 / D10). Extract owned values to
                        // end the immutable account borrow before mutating config.
                        let target = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .get(i)
                            .filter(|c| c.status.is_active())
                            .map(|c| (c.vtc_did.clone(), c.persona_ref));
                        if let Some((vtc, persona)) = target {
                            state.selected_community = Some(vtc);
                            config.set_active_persona(Some(persona));
                            // Refilter the community-scoped panels immediately so
                            // the switch is reflected this frame.
                            state.main_page.sync_from_config(&config);
                        }
                    },
                    Action::ToggleFavourite(i) => {
                        // R-C-4: flip the star on the community at display index
                        // `i`, persist (coalesced), then keep the highlight on it
                        // as the list re-sorts (favourites float to the top).
                        let vtc = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .get(i)
                            .map(|c| c.vtc_did.clone());
                        if let Some(vtc) = vtc {
                            if let Some(c) = config.account.community_mut(&vtc) {
                                c.toggle_favourite();
                            }
                            save.mark_dirty();
                            state.main_page.sync_from_config(&config);
                            if let Some(new_idx) = config
                                .account
                                .communities_for_display(state.main_page.content_panel.communities.show_archived)
                                .iter()
                                .position(|c| c.vtc_did == vtc)
                            {
                                state.main_page.content_panel.communities.selected_index =
                                    new_idx;
                            }
                        }
                    },
                    Action::AcknowledgeCommunity(i) => {
                        // R-S-2: clear the actions-required badge on a terminal
                        // outcome (Rejected / Expired) the user has now seen.
                        let vtc = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .get(i)
                            .map(|c| c.vtc_did.clone());
                        if let Some(vtc) = vtc
                            && let Some(c) = config.account.community_mut(&vtc)
                        {
                            c.acknowledge();
                            save.mark_dirty();
                            state.main_page.sync_from_config(&config);
                        }
                    },
                    Action::LeaveCommunity(i) => {
                        // R-L-1: send MEMBER_SELF_REMOVE, then set Left + deregister
                        // the session on send success (the receipt is advisory).
                        state.main_page.content_panel.communities.confirm_leave = None;
                        let target = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .get(i)
                            .filter(|c| c.status.is_active())
                            .map(|c| (c.vtc_did.clone(), c.persona_ref));
                        if let Some((vtc, persona_id)) = target {
                            // Owned send inputs from the persona's runtime identity,
                            // so no config borrow is held across the network await.
                            let sender = config.identities.get(&persona_id).map(|id| {
                                (
                                    id.persona_did().to_string(),
                                    id.profile().clone(),
                                    id.mediator_did.clone().unwrap_or_default(),
                                )
                            });
                            let send = match (sender, tdk.atm.as_ref()) {
                                (Some((member_did, profile, mediator)), Some(atm)) => {
                                    openvtc_core::join::submit_self_remove(
                                        atm, &profile, &member_did, &vtc, &mediator, None,
                                    )
                                    .await
                                }
                                _ => Err(openvtc_core::errors::OpenVTCError::Config(
                                    "Messaging unavailable — cannot leave right now.".into(),
                                )),
                            };
                            match send {
                                Ok(_) => {
                                    if let Some(c) = config.account.community_mut(&vtc) {
                                        c.leave();
                                    }
                                    save.mark_dirty();
                                    deregister_inactive_community(
                                        &mut session_manager,
                                        &didcomm_service,
                                        &config,
                                        &mut state,
                                        &vtc,
                                    )
                                    .await;
                                    state.main_page.sync_from_config(&config);
                                    state
                                        .main_page
                                        .content_panel
                                        .communities
                                        .status_message = Some("Left the community.".to_string());
                                }
                                Err(e) => {
                                    state.main_page.log_error("Leave failed", &e);
                                    state
                                        .main_page
                                        .content_panel
                                        .communities
                                        .status_message = Some(format!("Couldn't leave: {e}"));
                                }
                            }
                        }
                    },
                    Action::WithdrawJoin(i) => {
                        // Cancel a Pending join: best-effort notify the VTC, set
                        // the record `Withdrawn`, and tear down its now-dead
                        // session (R-S-3) so it can be deleted or re-joined.
                        state.main_page.content_panel.communities.confirm_withdraw = None;
                        let target = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .get(i)
                            .filter(|c| matches!(
                                c.status,
                                openvtc_core::config::account::CommunityStatus::Pending { .. }
                            ))
                            .map(|c| c.vtc_did.clone());
                        if let Some(vtc) = target {
                            // Best-effort VTC notification. The applicant-side
                            // withdraw DIDComm message does not exist in vta-sdk
                            // yet (only the `withdrawn` *status* the VTC reports),
                            // so there is nothing to send. The cancel is otherwise
                            // fully local; the request will also lapse to the VTC's
                            // own timeout. TODO(VTI): once vta-sdk gains a
                            // `join-requests/withdraw/1.0` message, send it here.
                            debug!(
                                vtc = %vtc,
                                "cancel pending join: VTC notify pending protocol support (vta-sdk withdraw message)"
                            );
                            if config
                                .account
                                .community_mut(&vtc)
                                .is_some_and(|c| c.withdraw())
                            {
                                save.mark_dirty();
                                deregister_inactive_community(
                                    &mut session_manager,
                                    &didcomm_service,
                                    &config,
                                    &mut state,
                                    &vtc,
                                )
                                .await;
                                state.main_page.sync_from_config(&config);
                                state
                                    .main_page
                                    .content_panel
                                    .communities
                                    .status_message =
                                    Some("Join cancelled — request withdrawn.".to_string());
                            }
                        }
                    },
                    Action::ArchiveCommunity(i) => {
                        // R-C-8: archive an inactive community (hide it, retain the
                        // record). Guarded inactive-only by `archive_community`.
                        let vtc = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .get(i)
                            .map(|c| c.vtc_did.clone());
                        if let Some(vtc) = vtc {
                            match config.account.archive_community(&vtc) {
                                Ok(()) => {
                                    save.mark_dirty();
                                    state.main_page.sync_from_config(&config);
                                    state
                                        .main_page
                                        .content_panel
                                        .communities
                                        .status_message =
                                        Some("Community archived.".to_string());
                                }
                                Err(e) => {
                                    state
                                        .main_page
                                        .content_panel
                                        .communities
                                        .status_message =
                                        Some(format!("Couldn't archive: {e}"));
                                }
                            }
                        }
                    },
                    Action::ToggleShowArchived => {
                        // R-C-8: flip archived visibility and rebuild the list so
                        // archived records stay discoverable.
                        let comms = &mut state.main_page.content_panel.communities;
                        comms.show_archived = !comms.show_archived;
                        state.main_page.sync_from_config(&config);
                    },
                    Action::OpenCommunitySwitcher => {
                        // R-C-7: list the Active communities (the only switchable
                        // ones) in display order and preselect the current one.
                        let current = state.selected_community.clone();
                        let items: Vec<_> = config
                            .account
                            .communities_for_display(state.main_page.content_panel.communities.show_archived)
                            .into_iter()
                            .filter(|c| c.status.is_active())
                            .map(|c| main_page::content::SwitcherItem {
                                vtc_did: c.vtc_did.clone(),
                                display_name: c
                                    .display_name
                                    .clone()
                                    .unwrap_or_else(|| main_page::shorten_did(&c.vtc_did, 40)),
                                is_current: Some(&c.vtc_did) == current.as_ref(),
                            })
                            .collect();
                        // Don't pop an empty overlay when there's nothing to switch.
                        if !items.is_empty() {
                            let selected =
                                items.iter().position(|it| it.is_current).unwrap_or(0);
                            state.main_page.switcher =
                                Some(main_page::content::CommunitySwitcherState {
                                    items,
                                    selected,
                                });
                        }
                    },
                    Action::CommunitySwitcherSelect => {
                        // Switch the working context to the highlighted Active
                        // community, then close the overlay (R-C-6 / R-C-7).
                        let target = state.main_page.switcher.as_ref().and_then(|sw| {
                            sw.items.get(sw.selected).map(|it| it.vtc_did.clone())
                        });
                        if let Some(vtc) = target {
                            let persona = config
                                .account
                                .community(&vtc)
                                .filter(|c| c.status.is_active())
                                .map(|c| c.persona_ref);
                            if let Some(persona) = persona {
                                state.selected_community = Some(vtc);
                                config.set_active_persona(Some(persona));
                                state.main_page.sync_from_config(&config);
                            }
                        }
                        state.main_page.switcher = None;
                    },
                    Action::DeleteDid(i) => {
                        // Identity deletion does a VTA `delete_did_webvh` + listener
                        // teardown (R14): claim the Did domain, run the guards +
                        // extraction on-thread, then spawn the I/O; local config
                        // cleanup + save apply on the outcome. Guard failures (DID
                        // bound to a community, not found) are surfaced inline and
                        // spawn nothing.
                        let domain = background_dispatch::DispatchDomain::Did;
                        if !in_flight.try_begin(domain) {
                            let msg = background_dispatch::InFlight::busy_message(domain);
                            state.main_page.log(msg);
                        } else if let Some(job) = self.prepare_delete_context_did(
                            &mut state,
                            &mut config,
                            admin_vta.as_ref(),
                            &didcomm_service,
                            i,
                        ) {
                            background_dispatch::spawn_dispatch(
                                dispatch_tx.clone(),
                                domain,
                                async move {
                                    background_dispatch::DispatchOutcome::Did(job.run().await)
                                },
                            );
                        } else {
                            // Guard rejected the delete (logged inline); release.
                            in_flight.finish(domain);
                        }
                    },
                    Action::StartJoin => {
                        // State-B join from the live runtime: reuse the always-on
                        // admin VTA session. The DIDComm service keeps running in
                        // the background; the join flow owns the screen until the
                        // user returns. Restart is required to activate the new
                        // community (hot-start is a deliberate follow-up).
                        match self
                            .join_flow(
                                &mut action_rx,
                                &mut interrupt_rx,
                                &mut state,
                                &tdk,
                                &mut config,
                                admin_vta.as_ref(),
                                self.profile.as_str(),
                            )
                            .await
                        {
                            Ok(join_flow::JoinExit::Returned(joined)) => {
                                state.active_page = state::ActivePage::Main;
                                // R-B-5 / D11: bring the new community's session up
                                // live so the VTC's async receipt is received now,
                                // not only after a restart.
                                if let Some(joined) = joined {
                                    register_joined_session(
                                        &mut session_manager,
                                        &didcomm_service,
                                        &tdk,
                                        &config,
                                        joined,
                                        &mut state,
                                    )
                                    .await;
                                }
                            }
                            Ok(join_flow::JoinExit::Exit(interrupted)) => {
                                break interrupted;
                            }
                            Err(e) => {
                                state.main_page.log_error("Join flow failed", &e);
                                state.active_page = state::ActivePage::Main;
                            }
                        }
                    },
                    Action::Inbox(ia) => {
                        // Network inbox actions (accept/reject relationship or VRC
                        // request) run off the loop (R14): claim the Inbox domain,
                        // do the loop-thread pre-send work, then spawn the send;
                        // the outcome arm applies the post-send mutation. A second
                        // inbox network action while one is in flight is rejected
                        // with a status. Local actions run inline as before.
                        if inbox_actions::is_network(&ia) {
                            let domain = background_dispatch::DispatchDomain::Inbox;
                            if !in_flight.try_begin(domain) {
                                let msg = background_dispatch::InFlight::busy_message(domain);
                                state.main_page.content_panel.inbox.status_message =
                                    Some(msg.clone());
                                state.main_page.log(msg);
                            } else {
                                match inbox_actions::dispatch(
                                    ia,
                                    &mut config,
                                    &tdk,
                                    &didcomm_service,
                                    &mut state,
                                    &mut save,
                                    admin_vta.as_ref(),
                                )
                                .await
                                {
                                    inbox_actions::InboxDispatch::Spawn(job) => {
                                        background_dispatch::spawn_dispatch(
                                            dispatch_tx.clone(),
                                            domain,
                                            async move {
                                                background_dispatch::DispatchOutcome::Inbox(
                                                    job.run().await,
                                                )
                                            },
                                        );
                                    }
                                    // Pre-send failure recorded a status; nothing
                                    // was spawned, so release the domain now.
                                    inbox_actions::InboxDispatch::Handled => {
                                        in_flight.finish(domain);
                                    }
                                }
                            }
                        } else {
                            let _ = inbox_actions::dispatch(
                                ia,
                                &mut config,
                                &tdk,
                                &didcomm_service,
                                &mut state,
                                &mut save,
                                admin_vta.as_ref(),
                            )
                            .await;
                        }
                    },
                    Action::Relationship(ra) => {
                        // Network relationship actions (create/ping/remove/request
                        // VRC) run off the loop (R14). Same pattern as Inbox: claim
                        // the Relationship domain, prepare on-thread, spawn the I/O,
                        // apply the outcome later. `is_ping` stamps `ping_sent_at`
                        // for pong-latency display.
                        if relationship_actions::is_network(&ra) {
                            let domain = background_dispatch::DispatchDomain::Relationship;
                            if !in_flight.try_begin(domain) {
                                let msg = background_dispatch::InFlight::busy_message(domain);
                                state
                                    .main_page
                                    .content_panel
                                    .relationships
                                    .status_message = Some(msg.clone());
                                state.main_page.log(msg);
                            } else {
                                match relationship_actions::dispatch(
                                    ra,
                                    &mut config,
                                    &tdk,
                                    &didcomm_service,
                                    &mut state,
                                    &mut save,
                                    admin_vta.as_ref(),
                                )
                                .await
                                {
                                    relationship_actions::RelationshipDispatch::Spawn {
                                        job,
                                        is_ping,
                                    } => {
                                        if is_ping {
                                            ping_sent_at = Some(std::time::Instant::now());
                                        }
                                        background_dispatch::spawn_dispatch(
                                            dispatch_tx.clone(),
                                            domain,
                                            async move {
                                                background_dispatch::DispatchOutcome::Relationship(
                                                    job.run().await,
                                                )
                                            },
                                        );
                                    }
                                    relationship_actions::RelationshipDispatch::Handled => {
                                        in_flight.finish(domain);
                                    }
                                }
                            }
                        } else {
                            let _ = relationship_actions::dispatch(
                                ra,
                                &mut config,
                                &tdk,
                                &didcomm_service,
                                &mut state,
                                &mut save,
                                admin_vta.as_ref(),
                            )
                            .await;
                        }
                    },
                    Action::Credential(ca) => {
                        credential_actions::dispatch(
                            ca,
                            &mut config,
                            &tdk,
                            &didcomm_service,
                            &mut state,
                            &mut save,
                        )
                        .await;
                    },
                    Action::Settings(sa) => {
                        match settings_actions::dispatch(
                            sa,
                            &mut config,
                            &mut state,
                            &self.state_tx,
                            &mut save,
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
                            settings_actions::SettingsOutcome::ReconnectMediator => {
                                // R13 proving case: the up-to-30s mediator
                                // reconnect ran inline here before, freezing the
                                // UI (queued keys, dropped inbound events, dead
                                // `q`). Now it runs as a background task and the
                                // loop stays live.
                                //
                                // The busy-guard rejects a second reconnect while
                                // one is in flight (matching the old effectively
                                // serialised behaviour) with a visible status.
                                if !in_flight
                                    .try_begin(background_dispatch::DispatchDomain::Mediator)
                                {
                                    let msg = background_dispatch::InFlight::busy_message(
                                        background_dispatch::DispatchDomain::Mediator,
                                    );
                                    state.connection.status =
                                        state::MediatorStatus::Connecting;
                                    state.main_page.log(msg);
                                } else {
                                    // Build the new listener config on the loop
                                    // thread (cheap, local: reads secrets from the
                                    // TDK resolver, no network), then hand only the
                                    // slow connect I/O to a background task.
                                    let listener_id =
                                        didcomm::persona_listener_id(config.persona_did());
                                    let new_listener_config =
                                        didcomm::persona_listener_config(&config, &tdk).await;
                                    let service = didcomm_service.clone();
                                    background_dispatch::spawn_dispatch(
                                        dispatch_tx.clone(),
                                        background_dispatch::DispatchDomain::Mediator,
                                        async move {
                                            let outcome =
                                                didcomm::reconnect_persona_listener_io(
                                                    &service,
                                                    listener_id,
                                                    new_listener_config,
                                                )
                                                .await;
                                            background_dispatch::DispatchOutcome::MediatorReconnect(
                                                outcome,
                                            )
                                        },
                                    );
                                }
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

                            let mut inactivated = Vec::new();
                            match message_dispatch::process_inbound_message(
                                &mut config,
                                &tdk,
                                &didcomm_service,
                                &mut seen_messages,
                                &message,
                                &mut inactivated,
                            )
                            .await
                            {
                                Ok(true) => {
                                    // R11: a config-mutating inbound message used
                                    // to save inline here — the per-message cost
                                    // that turned a mediator redelivery burst into
                                    // N sequential keyring+file+card writes. Now we
                                    // mark dirty (coalesced + offloaded); the UI
                                    // sync stays immediate.
                                    save.mark_dirty();
                                    // R-S-3: a community resolved to an inactive
                                    // status (e.g. a rejection) — tear down its
                                    // live session so a dead community stops
                                    // holding a mediator connection.
                                    for vtc in &inactivated {
                                        deregister_inactive_community(
                                            &mut session_manager,
                                            &didcomm_service,
                                            &config,
                                            &mut state,
                                            vtc,
                                        )
                                        .await;
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
                            let is_mediator = sender == config.mediator_did();
                            let has_relationship = config
                                .private
                                .relationships
                                .find_by_remote_did(&sender_arc)
                                .map(|r| {
                                    r.state == openvtc_core::relationships::RelationshipState::Established
                                })
                                .unwrap_or(false);

                            if is_mediator || has_relationship {
                                // Send pong to verified sender, setting `from` to our
                                // listener's DID so the recipient can identify us.
                                let our_listener_did = didcomm_service
                                    .listener_did(&listener_id)
                                    .await
                                    .unwrap_or_else(|| config.persona_did().to_string());
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
                                    .filter_map(|task| {
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
                // Background-dispatch completions (R13). A network-bound action
                // that was spawned off the loop (e.g. the mediator reconnect)
                // delivers its result here; the outcome is applied on this thread
                // (the single mutator) and the domain's busy-flag is cleared.
                // Because this is just another select arm, nav actions, `q`/Exit,
                // and inbound DIDComm events are all serviced *while* the spawned
                // I/O is still pending.
                Some(outcome) = dispatch_rx.recv() => {
                    background_dispatch::apply_outcome(
                        &mut state,
                        &mut config,
                        &mut save,
                        &mut in_flight,
                        outcome,
                    );
                },
                // Lifecycle log messages from the DIDCommService
                Some(log_msg) = lifecycle_log_rx.recv() => {
                    state.main_page.log(log_msg);
                },
                // Typed listener lifecycle events → drive the connection status
                // asynchronously (phase 2). The persona listener connecting flips
                // the status to Connected; a disconnect drops back to Connecting
                // while the service auto-reconnects.
                ev = listener_events.recv() => {
                    use affinidi_messaging_didcomm_service::ListenerEvent;
                    if let Ok(ev) = ev {
                        // Route persona-listener lifecycle through the session
                        // manager (D11/D15), which holds per-session status; a
                        // disconnect carrying an error is recorded as that one
                        // session failing (isolated — others are untouched). The
                        // SDK keeps retrying per its restart policy, so a restart
                        // or clean drop is "not connected" until the next connect.
                        // Events for R-DID listeners (not persona sessions) match
                        // nothing and are ignored.
                        let changed = match ev {
                            ListenerEvent::Connected { listener_id } => {
                                session_manager.mark_connected(&listener_id)
                            }
                            ListenerEvent::Disconnected { listener_id, error } => match error {
                                Some(e) => session_manager.mark_failed(&listener_id, e),
                                None => session_manager.mark_disconnected(&listener_id),
                            },
                            ListenerEvent::Restarting { listener_id, .. } => {
                                session_manager.mark_disconnected(&listener_id)
                            }
                        };
                        // Derive the global connection indicator from the
                        // aggregate of all persona-sessions (a per-community
                        // status panel is future UI work). Leave a
                        // `NoActiveCommunity` state untouched when no session
                        // exists.
                        if changed {
                            if session_manager.any_connected() {
                                state.connection.status = state::MediatorStatus::Connected;
                                state.connection.messaging_active = true;
                            } else if session_manager.session_count() > 0 {
                                state.connection.status = state::MediatorStatus::Connecting;
                                state.connection.messaging_active = false;
                            }
                        }
                    }
                },
                // Coalesced-save debounce (R11). Fires when the debounce window
                // since the first dirty mark of a burst elapses. Builds an owned
                // snapshot on this (the single mutator) thread and runs the heavy
                // serialize+encrypt+keyring+card I/O on a blocking thread so the
                // loop stays responsive. At most one save is in flight; a mark
                // that lands while a save runs is re-scheduled on completion.
                // When nothing is scheduled the arm parks forever (no busy-wait).
                _ = pending_expiry_tick.tick() => {
                    // R-B-7: expire Pending joins unanswered for 7 days, raising
                    // actions-required, and tear down each one's now-dead session
                    // (R-S-3). Records are retained read-only (R-S-1).
                    let expired = config.account.expire_stale_pending(chrono::Utc::now());
                    if !expired.is_empty() {
                        save.mark_dirty();
                        for vtc in &expired {
                            deregister_inactive_community(
                                &mut session_manager,
                                &didcomm_service,
                                &config,
                                &mut state,
                                vtc,
                            )
                            .await;
                        }
                        state.main_page.sync_from_config(&config);
                        state.main_page.log(format!(
                            "{} pending join{} expired (no response within 7 days).",
                            expired.len(),
                            if expired.len() == 1 { "" } else { "s" },
                        ));
                        let _ = self.state_tx.send(state.clone());
                    }
                },
                _ = save.wait_deadline() => {
                    match save.take_for_save(|| config.clone_for_save()) {
                        Ok(Ok(pending)) => {
                            let done_tx = save_done_tx.clone();
                            tokio::task::spawn_blocking(move || {
                                let result = pending.run().map_err(|e| format!("{e}"));
                                let _ = done_tx.send(result);
                            });
                        }
                        // Snapshot failed: surface like an inline save failure.
                        // The scheduler kept the config dirty + re-armed, so it
                        // retries on the next deadline.
                        Ok(Err(e)) => {
                            state.main_page.log_error("Failed to save config", &e);
                        }
                        // NotDirty / InFlight — nothing to start right now.
                        Err(_) => {}
                    }
                },
                // A backgrounded coalesced save finished (R11). Clear the
                // in-flight flag and re-arm if the config was dirtied again. A
                // failed save is surfaced exactly as the old inline `save_config`
                // failure did (status + log) and left dirty for retry.
                Some(result) = save_done_rx.recv() => {
                    match &result {
                        Ok(()) => {}
                        Err(reason) => {
                            state
                                .main_page
                                .log_error("Failed to save config", &anyhow::anyhow!("{reason}"));
                        }
                    }
                    save.finish(result.is_ok());
                },
                // (keepalive removed — WebSocket-level pings handle connectivity)
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
            }
            // Keep the working-context selection valid against any account change
            // this iteration applied (join/leave/status transition) before the UI
            // re-renders from the broadcast (D10 / R-C-6), then point the runtime
            // active identity at the selected community's persona so all
            // identity-derived reads scope to the working community. When the
            // working persona actually changes (e.g. the active community left and
            // the default shifted), refilter the community-scoped panels so the UI
            // reflects the new context this frame.
            state.reconcile_selected_community(&config.account);
            let active_persona = state
                .selected_community
                .as_ref()
                .and_then(|vtc| config.account.community(vtc))
                .map(|c| c.persona_ref);
            if active_persona != config.active_persona {
                config.set_active_persona(active_persona);
                state.main_page.sync_from_config(&config);
            }
            let _ = self.state_tx.send(state.clone());
        };

        // R11: if a backgrounded coalesced save was still running when the loop
        // broke, wait for it to complete before the force-flush below. A
        // `spawn_blocking` task is NOT cancelled when its `JoinHandle` is dropped,
        // so that save is still live; running the shutdown save concurrently would
        // mean two `Config::save`s racing the same (non-atomic) file + keyring
        // writes. Draining the completion channel serialises shutdown after it.
        // After `finish`, `needs_flush()` is only still true if the config was
        // dirtied *after* the in-flight save's snapshot — exactly what the
        // force-flush must persist.
        if save.in_flight()
            && let Some(result) = save_done_rx.recv().await
        {
            save.finish(result.is_ok());
        }

        // R11 force-flush: persist the latest state before tearing down, so
        // coalescing never loses the final mutation on Exit/interrupt. Runs a
        // direct blocking save (the loop has broken; there is no runtime arm left
        // to schedule against). `needs_flush` is true when the config is dirty or
        // a background save was still in flight when the loop broke.
        if save.needs_flush() {
            match save.snapshot_now(&config) {
                Ok(pending) => {
                    if let Err(e) = pending.run() {
                        state
                            .main_page
                            .log_error("Failed to save config on exit", &e);
                    }
                }
                Err(e) => {
                    state
                        .main_page
                        .log_error("Failed to snapshot config on exit", &e);
                }
            }
        }

        // Shut down the DIDComm service gracefully
        shutdown_token.cancel();
        didcomm_service.shutdown().await;

        // Close the always-on admin VTA session.
        if let Some(c) = admin_vta {
            c.shutdown().await;
        }

        Ok(result)
    }

    /// Remove the community at `index` in the Communities display list: withdraw
    /// a live (Pending/Active) membership first (R-C-8 — for a pending join this
    /// is the withdrawal), then delete the record, persist, and refresh the
    /// panel. Surfaces the outcome as a status message.
    fn remove_community(
        &self,
        state: &mut State,
        config: &mut Config,
        save: &mut save_coalesce::SaveScheduler,
        index: usize,
    ) {
        let Some(vtc) = config
            .account
            .communities_for_display(state.main_page.content_panel.communities.show_archived)
            .get(index)
            .map(|c| c.vtc_did.clone())
        else {
            return;
        };
        // The confirmation is now resolved.
        state.main_page.content_panel.communities.confirm_delete = None;
        // Delete is inactive-only (R-C-8): an Active/Pending community must be
        // left first (the `d` key is gated to inactive rows, and `delete_community`
        // re-checks). We no longer silently `leave()` here — that conflated leave
        // with delete and skipped the protocol self-removal.
        match config.account.delete_community(&vtc) {
            Ok(_) => {
                // R11: coalesced save (was an inline `config.save`). The
                // Exit/shutdown force-flush guarantees the deletion is persisted
                // even if the user quits within the debounce window.
                save.mark_dirty();
                state.main_page.sync_from_config(config);
                state.main_page.content_panel.communities.status_message =
                    Some("Community removed.".to_string());
            }
            Err(e) => {
                state.main_page.content_panel.communities.status_message =
                    Some(format!("Could not remove community: {e}"));
            }
        }
    }

    /// Loop-thread preparation for deleting an **orphan** context identity
    /// (persona DID) at `index` in the VTA DID manager. Runs the guards (DID
    /// resolution + the community-bound check — a community-bound identity must
    /// not be deleted out from under its membership) and snapshots the persona /
    /// key ids, then returns a [`relationship_actions::DidDeleteJob`] for the loop
    /// to run off-thread (VTA `delete_did_webvh` + listener teardown). The local
    /// cleanup (persona/identity/key removal + save + sync) is applied later by
    /// [`relationship_actions::DidDeleteOutcome`].
    ///
    /// Returns `None` (and logs inline) when a guard rejects the delete, so the
    /// caller can release the busy-domain without spawning anything.
    fn prepare_delete_context_did(
        &self,
        state: &mut State,
        config: &mut Config,
        admin_vta: Option<&vta_sdk::client::VtaClient>,
        didcomm_service: &affinidi_messaging_didcomm_service::DIDCommService,
        index: usize,
    ) -> Option<relationship_actions::DidDeleteJob> {
        state.main_page.content_panel.vta.confirm_delete_did = None;
        let did = state
            .main_page
            .content_panel
            .vta
            .context_dids
            .get(index)
            .map(|d| d.did.clone())?;

        // Resolve the persona for this DID + its key ids.
        let Some(persona) = config.account.personas.values().find(|p| p.did == did) else {
            state.main_page.log("DID not found — nothing removed.");
            return None;
        };
        let persona_id = persona.persona_id;
        let key_ids: Vec<String> = persona.key_refs.iter().map(|k| k.key_id.clone()).collect();

        // Guard: refuse to delete an identity any community still presents.
        let bound = config
            .account
            .communities
            .values()
            .filter(|c| c.persona_ref == persona_id)
            .count();
        if bound > 0 {
            state.main_page.log(format!(
                "Can't delete — {bound} communit{} still use this identity; leave them first.",
                if bound == 1 { "y" } else { "ies" }
            ));
            return None;
        }

        state.main_page.log(format!("Removing identity {did}…"));

        Some(relationship_actions::DidDeleteJob {
            admin_vta: admin_vta.cloned(),
            service: didcomm_service.clone(),
            did,
            persona_id,
            key_ids,
        })
    }

    /// Minimal event loop for when there is no active community / messaging
    /// (State-A) or after an init failure — keeps the UI alive so the user can
    /// navigate, exit, and (when `join_ctx` is supplied) start a join.
    ///
    /// `join_ctx` carries the runtime pieces the join flow needs (TDK, the live
    /// `Config`, the always-on admin VTA session, profile). The early
    /// load-failure callers have no loaded config, so they pass `None` and
    /// `StartJoin` is a no-op there.
    ///
    /// Returns [`DegradedOutcome::Joined`] when an in-session join mints the
    /// account's first persona (State-A → member). The caller then brings up the
    /// persona's DIDComm listener without a restart (hot-start). All other exits
    /// return [`DegradedOutcome::Exit`] after closing the admin session.
    async fn run_degraded_loop(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        terminator: &mut Terminator,
        state: &mut State,
        mut join_ctx: Option<DegradedJoinContext>,
    ) -> Result<DegradedOutcome> {
        // R11: the degraded loop persists only via `remove_community` (State-A
        // community withdrawal); `join_flow` saves itself synchronously. Coalesce
        // here too and force-flush on every exit path so a withdrawal isn't lost.
        let mut save = save_coalesce::SaveScheduler::new(self.profile.clone());
        let result = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => match action {
                    // Shared nav reducer first — degraded mode now routes the exact
                    // same pure-state nav set as the runtime loop (previously these
                    // arms were duplicated here and the VTA DID-manager nav arms were
                    // silently dropped by the trailing `_ => {}`).
                    _ if handle_nav_action(state, &action) => {}
                    Action::Exit => {
                        if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        break DegradedOutcome::Exit(Interrupted::UserInt);
                    }
                    Action::UXError(interrupted) => {
                        if let Err(e) = terminator.terminate(interrupted.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        break DegradedOutcome::Exit(interrupted);
                    }
                    Action::DeleteCommunity(i) => {
                        if let Some(ctx) = join_ctx.as_mut() {
                            self.remove_community(state, &mut ctx.config, &mut save, i);
                            // The degraded loop has no debounce arm and a `Joined`
                            // handoff carries the config into the runtime loop, so
                            // force-flush this single destructive action now rather
                            // than risk losing it on handoff. (Low-traffic State-A
                            // path — no burst to coalesce.)
                            if save.needs_flush()
                                && let Err(e) = save.flush(&ctx.config).await
                            {
                                state
                                    .main_page
                                    .log_error("Failed to save after removing community", &e);
                            }
                        }
                    }
                    Action::StartJoin => {
                        // Set when the join minted our first persona: the loop
                        // then breaks `Joined` so `run()` can start messaging.
                        let mut joined_with_identity = false;
                        if let Some(ctx) = join_ctx.as_mut() {
                            // A State-A account has no identity yet; a successful
                            // join flips this None→Some. (An account that already
                            // had one — the messaging-startup-failure path — never
                            // transitions here.)
                            let had_identity = ctx.config.active_identity().is_some();
                            match self
                                .join_flow(
                                    action_rx,
                                    interrupt_rx,
                                    state,
                                    &ctx.tdk,
                                    &mut ctx.config,
                                    ctx.admin_vta.as_ref(),
                                    ctx.profile.as_str(),
                                )
                                .await
                            {
                                // The joined session is ignored here: a first join
                                // from State A flips `joined_with_identity`, breaking
                                // `Joined` so `run()` restarts into the full pipeline,
                                // whose startup registration (`IdentityRegistry`)
                                // brings the new session up (R-B-5). Live in-loop
                                // registration is only needed in the runtime loop.
                                Ok(join_flow::JoinExit::Returned(_)) => {
                                    // Back on the main page; resume the degraded loop.
                                    state.active_page = state::ActivePage::Main;
                                    joined_with_identity =
                                        !had_identity && ctx.config.active_identity().is_some();
                                }
                                Ok(join_flow::JoinExit::Exit(interrupted)) => {
                                    if let Err(e) = terminator.terminate(interrupted.clone()) {
                                        debug!("Failed to send terminate signal: {e}");
                                    }
                                    break DegradedOutcome::Exit(interrupted);
                                }
                                Err(e) => {
                                    state
                                        .main_page
                                        .log_error("Join flow failed", &e);
                                    state.active_page = state::ActivePage::Main;
                                }
                            }
                        } else {
                            state
                                .main_page
                                .log("Cannot join: no active VTA session.");
                        }
                        // Hot-start: the borrow on `join_ctx` has ended, so take
                        // the context and hand it back to `run()`, which brings up
                        // the new persona's DIDComm listener without a restart.
                        if joined_with_identity {
                            state
                                .main_page
                                .log("Joined — starting secure messaging…");
                            let _ = self.state_tx.send(state.clone());
                            break DegradedOutcome::Joined(
                                join_ctx
                                    .take()
                                    .expect("join_ctx present when join succeeded"),
                            );
                        }
                    }
                    // Messaging-only actions (Inbox / Relationship / Credential /
                    // Settings / Contact, DeleteDid) are intentionally inert in the
                    // degraded loop — there's no live messaging/admin context to
                    // service them. The pure nav arms they previously shared this
                    // catch-all with now go through `handle_nav_action` above.
                    _ => {}
                },
                Ok(interrupted) = interrupt_rx.recv() => {
                    break DegradedOutcome::Exit(interrupted);
                }
            }
            let _ = self.state_tx.send(state.clone());
        };

        // Close the always-on admin VTA session owned by the join context, if
        // any. On a `Joined` outcome the context was already `take`n above (so
        // `join_ctx` is None here) and the session is carried into the messaging
        // path — this shutdown is correctly skipped.
        if let Some(ctx) = join_ctx
            && let Some(c) = ctx.admin_vta
        {
            c.shutdown().await;
        }

        Ok(result)
    }

    /// Run the degraded loop for a path that cannot hot-start (no loaded config,
    /// or messaging already failed for an existing member), collapsing the
    /// outcome to an [`Interrupted`]. `DegradedOutcome::Joined` is unreachable
    /// for these callers — only the State-A entry can transition None→Some.
    async fn run_degraded_loop_terminal(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        terminator: &mut Terminator,
        state: &mut State,
        join_ctx: Option<DegradedJoinContext>,
    ) -> Result<Interrupted> {
        match self
            .run_degraded_loop(action_rx, interrupt_rx, terminator, state, join_ctx)
            .await?
        {
            DegradedOutcome::Exit(interrupted) => Ok(interrupted),
            DegradedOutcome::Joined(_) => {
                unreachable!("degraded loop transitioned to messaging on a terminal path")
            }
        }
    }
}

/// Runtime context the degraded loop hands to [`StateHandler::join_flow`].
///
/// Owns the live `Config` (mutated + persisted by a successful join), the TDK,
/// the always-on admin VTA session, and the profile name. The admin session is
/// shut down when the degraded loop returns.
struct DegradedJoinContext {
    tdk: TDK,
    config: Box<Config>,
    admin_vta: Option<vta_sdk::client::VtaClient>,
    profile: String,
}

/// Outcome of [`StateHandler::run_degraded_loop`].
enum DegradedOutcome {
    /// The user exited or an interrupt fired. The admin session (if any) was
    /// closed by the loop before returning.
    Exit(Interrupted),
    /// An in-session join minted the account's first persona. The runtime
    /// context (with its still-open admin session) is handed back so `run()` can
    /// bring up the persona's DIDComm listener without a process restart.
    Joined(DegradedJoinContext),
}

/// Apply a pure navigation action to `state`, shared by the runtime loop and the
/// degraded loop so both modes route the same nav set from exactly one place.
///
/// Returns `true` if `action` was a nav action and was handled here; `false`
/// otherwise, signalling the caller to fall through to its loop-specific arms
/// (DIDComm events for the runtime loop; join hot-start etc. for degraded).
///
/// Only arms that mutate `&mut State` and nothing else live here. Loop-local
/// arms stay in their loops because they need resources this signature can't
/// carry cleanly:
///   * `Exit` / `UXError` — must signal the terminator and `break` with the
///     loop's own outcome type (`Interrupted` vs `DegradedOutcome`).
///   * `DeleteCommunity` / `DeleteDid` — `async`, and reach into the live
///     `Config`, the admin VTA session, and the DIDComm service to tear down
///     listeners; the two loops genuinely differ here.
///   * `StartJoin` — `async`; drives `join_flow` with loop-specific context and
///     (degraded only) the join hot-start handoff.
fn handle_nav_action(state: &mut State, action: &Action) -> bool {
    match action {
        Action::DismissLoading => {
            // Phase 1 done + user pressed Enter — reveal the main page
            // (phase-2 connection is already running in the background).
            state.active_page = state::ActivePage::Main;
        }
        Action::MainMenuSelected(menu_item) => {
            // User has changed main menu selection.
            state.main_page.menu_panel.selected_menu = menu_item.clone();
        }
        Action::MainPanelSwitch(panel) => match panel {
            MainPanel::ContentPanel => {
                // When switching to ContentPanel, move focus to the content panel.
                state.main_page.menu_panel.selected = false;
                state.main_page.content_panel.selected = true;
            }
            MainPanel::MainMenu => {
                // When switching to MainMenu, move focus back to the menu.
                state.main_page.menu_panel.selected = true;
                state.main_page.content_panel.selected = false;
            }
        },
        Action::CommunitySelect(i) => {
            state.main_page.content_panel.communities.selected_index = *i;
        }
        Action::CommunityConfirmDelete(i) => {
            state.main_page.content_panel.communities.confirm_delete = Some(*i);
        }
        Action::CommunityCancelDelete => {
            state.main_page.content_panel.communities.confirm_delete = None;
        }
        Action::CommunityConfirmLeave(i) => {
            state.main_page.content_panel.communities.confirm_leave = Some(*i);
        }
        Action::CommunityCancelLeave => {
            state.main_page.content_panel.communities.confirm_leave = None;
        }
        Action::CommunityConfirmWithdraw(i) => {
            state.main_page.content_panel.communities.confirm_withdraw = Some(*i);
        }
        Action::CommunityCancelWithdraw => {
            state.main_page.content_panel.communities.confirm_withdraw = None;
        }
        Action::CommunitySwitcherMove(i) => {
            if let Some(switcher) = state.main_page.switcher.as_mut() {
                switcher.selected = (*i).min(switcher.items.len().saturating_sub(1));
            }
        }
        Action::CloseCommunitySwitcher => {
            state.main_page.switcher = None;
        }
        Action::DidSelect(i) => {
            state.main_page.content_panel.vta.did_selected_index = *i;
        }
        Action::DidConfirmDelete(i) => {
            state.main_page.content_panel.vta.confirm_delete_did = Some(*i);
        }
        Action::DidCancelDelete => {
            state.main_page.content_panel.vta.confirm_delete_did = None;
        }
        _ => return false,
    }
    true
}

/// Bring a just-joined community's session live (R-B-5 / D11): register it with
/// the multi-session manager and, when that creates a fresh session, start the
/// persona's DIDComm listener now so the VTC's asynchronous receipt arrives
/// without a restart. `add_listener` returns promptly — the mediator connect
/// proceeds under the listener's restart policy, and the `ListenerEvent::Connected`
/// handler flips the session to `Connected`. Failures are non-fatal (a restart
/// recovers the session) and surfaced to the activity log.
/// Tear down a community's live session after it transitioned to an inactive
/// status (rejected, expired) — the lifecycle twin of [`register_joined_session`]
/// (R-S-3 / D15). Deregisters the session and, if its persona now serves no live
/// community, stops + removes the persona's listener so a dead community stops
/// holding a mediator connection. The community **record is retained** (R-S-1);
/// only the live session is dropped. Also drops the global messaging indicator to
/// `NoActiveCommunity` when the account has no live community left.
async fn deregister_inactive_community(
    session_manager: &mut session_manager::SessionManager,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    config: &Config,
    state: &mut State,
    vtc: &openvtc_core::config::account::VtcDid,
) {
    // The persona that served this (now-inactive but retained) community.
    let Some(pid) = config.account.community(vtc).map(|c| c.persona_ref) else {
        session_manager.deregister(vtc);
        return;
    };
    let removed = session_manager.deregister(vtc);
    let still_live = config
        .account
        .communities
        .values()
        .any(|c| c.persona_ref == pid && c.is_live());
    if !still_live && let Some(did) = config.identities.get(&pid).map(|id| id.did.clone()) {
        // Prefer the listener id the manager recorded; fall back to deriving it.
        let listener_id = removed
            .map(|s| s.listener_id)
            .unwrap_or_else(|| didcomm::persona_listener_id(&did));
        if let Err(e) = service.remove_listener(&listener_id).await {
            debug!("remove_listener after community inactivation: {e}");
        }
        state
            .main_page
            .log("Community inactive — persona listener stopped.");
    }
    // Drop the global messaging indicator when no persona has a live community.
    if !config.account.communities.values().any(|c| c.is_live()) {
        state.connection.status = state::MediatorStatus::NoActiveCommunity;
        state.connection.messaging_active = false;
    }
}

async fn register_joined_session(
    session_manager: &mut session_manager::SessionManager,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    tdk: &TDK,
    config: &Config,
    joined: join_flow::JoinedSession,
    state: &mut State,
) {
    use session_manager::RegisterOutcome;

    let lid = didcomm::persona_listener_id(&joined.persona_did);
    match session_manager.register(joined.persona_id, &lid, joined.vtc_did.clone()) {
        RegisterOutcome::JoinedExisting => {
            // A reused persona that is already live — the new community shares its
            // session; no new listener (D1/D11).
            state
                .main_page
                .log("New community attached to an existing live session.");
        }
        RegisterOutcome::AtCapacity => {
            // No silent caps (D15): the join succeeded but the bound is reached.
            state.main_page.log(format!(
                "Joined, but its live session is not active yet: the session limit ({}) is \
                 reached. It will connect when one frees up or on next launch.",
                session_manager.max_sessions(),
            ));
        }
        RegisterOutcome::Created => {
            match didcomm::persona_listener_config_for(config, tdk, joined.persona_id).await {
                Some(cfg) => {
                    if let Err(e) = service.add_listener(cfg).await {
                        session_manager.mark_failed(&lid, format!("{e:#}"));
                        state.main_page.log(format!(
                            "Joined, but couldn't start its live session now (it will connect \
                             on next launch): {e}"
                        ));
                    } else {
                        state.main_page.log("New community session connecting…");
                    }
                }
                None => {
                    // The join just wrote this identity, so this is unexpected — but
                    // never leave a registered session with no listener behind it.
                    session_manager.deregister(&joined.vtc_did);
                    state.main_page.log(
                        "Joined, but its identity could not be resolved to start a live session.",
                    );
                }
            }
        }
    }
}

// Per-domain action dispatch lives in the corresponding sub-module:
//   inbox_actions::dispatch
//   relationship_actions::dispatch
//   credential_actions::dispatch
//   settings_actions::dispatch

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::menu::MainMenu;

    /// Drive `handle_nav_action` directly over a fresh `State`. Because the
    /// reducer is the single code path both the runtime loop and the degraded
    /// loop call, asserting it here proves *both* loops apply identical handling
    /// for these actions — there is no per-loop copy to drift.
    #[test]
    fn nav_reducer_handles_shared_arms_identically() {
        struct Case {
            name: &'static str,
            action: Action,
            assert_fn: fn(&State),
        }

        let cases = [
            Case {
                name: "DismissLoading reveals the main page",
                action: Action::DismissLoading,
                assert_fn: |s| {
                    assert!(
                        matches!(s.active_page, state::ActivePage::Main),
                        "expected ActivePage::Main"
                    )
                },
            },
            Case {
                name: "MainMenuSelected updates the menu selection",
                action: Action::MainMenuSelected(MainMenu::Settings),
                assert_fn: |s| assert_eq!(s.main_page.menu_panel.selected_menu, MainMenu::Settings),
            },
            Case {
                name: "MainPanelSwitch(ContentPanel) moves focus to the content panel",
                action: Action::MainPanelSwitch(MainPanel::ContentPanel),
                assert_fn: |s| {
                    assert!(!s.main_page.menu_panel.selected);
                    assert!(s.main_page.content_panel.selected);
                },
            },
            Case {
                name: "MainPanelSwitch(MainMenu) moves focus back to the menu",
                action: Action::MainPanelSwitch(MainPanel::MainMenu),
                assert_fn: |s| {
                    assert!(s.main_page.menu_panel.selected);
                    assert!(!s.main_page.content_panel.selected);
                },
            },
            Case {
                name: "CommunitySelect updates the selected index",
                action: Action::CommunitySelect(3),
                assert_fn: |s| assert_eq!(s.main_page.content_panel.communities.selected_index, 3),
            },
            Case {
                name: "CommunityConfirmDelete arms the confirmation",
                action: Action::CommunityConfirmDelete(2),
                assert_fn: |s| {
                    assert_eq!(
                        s.main_page.content_panel.communities.confirm_delete,
                        Some(2)
                    )
                },
            },
            Case {
                name: "CommunityConfirmLeave arms the leave confirmation",
                action: Action::CommunityConfirmLeave(1),
                assert_fn: |s| {
                    assert_eq!(s.main_page.content_panel.communities.confirm_leave, Some(1))
                },
            },
            Case {
                name: "DidConfirmDelete arms the VTA DID confirmation (degraded mode used to drop this)",
                action: Action::DidConfirmDelete(1),
                assert_fn: |s| {
                    assert_eq!(s.main_page.content_panel.vta.confirm_delete_did, Some(1))
                },
            },
        ];

        for case in cases {
            let mut state = State::default();
            let handled = handle_nav_action(&mut state, &case.action);
            assert!(handled, "nav reducer should handle: {}", case.name);
            (case.assert_fn)(&state);
        }
    }

    /// Loop-local arms (terminating + async) must NOT be claimed by the shared
    /// reducer; it returns `false` so each loop falls through to its own arm.
    /// `Exit` in particular is signalled via the return value, not handled here.
    #[test]
    fn nav_reducer_defers_loop_local_arms() {
        let mut state = State::default();
        assert!(
            !handle_nav_action(&mut state, &Action::Exit),
            "Exit must be deferred to the loop (it breaks with the loop's outcome type)"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::DeleteCommunity(0)),
            "DeleteCommunity is async/loop-local"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::DeleteDid(0)),
            "DeleteDid is async/loop-local"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::StartJoin),
            "StartJoin is async/loop-local"
        );
        // The switcher's config-mutating arms resolve a community + persona and
        // must reach the loop, not the pure reducer (R-C-7).
        assert!(
            !handle_nav_action(&mut state, &Action::OpenCommunitySwitcher),
            "OpenCommunitySwitcher reads config in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::CommunitySwitcherSelect),
            "CommunitySwitcherSelect mutates config in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::ToggleFavourite(0)),
            "ToggleFavourite mutates + persists config in the loop"
        );
        // T7 community-management arms also reach the loop (network send / config
        // mutation / re-sync), not the pure reducer.
        assert!(
            !handle_nav_action(&mut state, &Action::LeaveCommunity(0)),
            "LeaveCommunity sends MEMBER_SELF_REMOVE in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::ArchiveCommunity(0)),
            "ArchiveCommunity mutates + persists config in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::ToggleShowArchived),
            "ToggleShowArchived re-syncs from config in the loop"
        );
    }

    /// The switcher's UI-only arms (move highlight / close) are handled by the
    /// pure reducer so both loops share them (R-C-7).
    #[test]
    fn nav_reducer_handles_switcher_navigation() {
        use crate::state_handler::main_page::content::{CommunitySwitcherState, SwitcherItem};

        let item = |n: &str| SwitcherItem {
            vtc_did: format!("did:example:{n}"),
            display_name: n.to_string(),
            is_current: false,
        };
        let mut state = State::default();
        state.main_page.switcher = Some(CommunitySwitcherState {
            items: vec![item("a"), item("b"), item("c")],
            selected: 0,
        });

        assert!(handle_nav_action(
            &mut state,
            &Action::CommunitySwitcherMove(2)
        ));
        assert_eq!(state.main_page.switcher.as_ref().unwrap().selected, 2);

        // Out-of-range moves clamp to the last entry rather than panicking.
        assert!(handle_nav_action(
            &mut state,
            &Action::CommunitySwitcherMove(99)
        ));
        assert_eq!(state.main_page.switcher.as_ref().unwrap().selected, 2);

        assert!(handle_nav_action(
            &mut state,
            &Action::CloseCommunitySwitcher
        ));
        assert!(state.main_page.switcher.is_none());
    }
}
