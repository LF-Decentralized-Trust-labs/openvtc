//! DIDComm service integration for the TUI.
//!
//! Replaces the manual ATM/WebSocket/message-loop plumbing in `messaging/mod.rs`
//! with `DIDCommService`, which handles connection lifecycle, message pickup,
//! dispatch via `Router`, and outbound sending with retry.

use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, DIDCommServiceError, ListenerConfig, ListenerEvent,
    RestartPolicy, RetryConfig, Router, handler_fn,
};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use openvtc_core::config::Config;
use openvtc_core::relationships::RelationshipState;
use tokio::sync::mpsc;
use tracing::debug;

/// Fallback listener ID for the persona DID listener when no DID is available
/// (e.g. a State-A account with no persona).
pub const PERSONA_LISTENER_ID: &str = "persona";

/// The listener ID for a persona, derived from its DID slug so it is stable,
/// unique per community (one persona per community), and identifiable in the
/// activity log — e.g. `silent-tongue` rather than a generic `persona`. Derived
/// from the DID alone (not the full `Config`) so the runtime and message senders
/// (`listener_id_for_did`) agree on the same id without extra context.
pub fn persona_listener_id(persona_did: &str) -> String {
    let slug = openvtc_core::config::context_path::render_for_display(persona_did).to_string();
    if slug.is_empty() {
        PERSONA_LISTENER_ID.to_string()
    } else {
        slug
    }
}

/// Build a timestamped DIDComm message with standard 48-hour expiry.
///
/// Re-exported from [`openvtc_core::messaging`]; the implementation moved to
/// core (it is pure) so the protocol logic there can build its own messages.
pub use openvtc_core::messaging::build_didcomm_message;

/// Events sent from DIDComm router handlers to the state handler main loop.
#[derive(Debug)]
pub enum DIDCommEvent {
    /// An inbound message that needs business-logic processing.
    InboundMessage {
        message: Box<Message>,
        #[allow(dead_code)]
        from: Option<String>,
    },
    /// A trust-ping was received — state handler decides whether to respond.
    TrustPingReceived {
        from: Option<String>,
        /// The listener that received the ping (needed to send pong back).
        listener_id: String,
        /// The original message ID (needed for pong thid).
        message_id: String,
    },
    /// A trust-pong response was received.
    TrustPongReceived { from: Option<String> },
}

/// Capacity of the DIDComm event channel. Backpressure target: a
/// pathological mediator pushing messages faster than the state handler
/// can drain them gets `try_send` failures (logged + dropped), instead
/// of growing memory without bound. 256 is enough headroom that normal
/// operator activity doesn't ever overflow.
pub const DIDCOMM_EVENT_CHANNEL_CAPACITY: usize = 256;

/// Reason string included in a "Reconnect failed" log entry, plus the
/// updated MediatorStatus the caller should drive into the connection
/// state. Returned to the caller so it can update the State accordingly
/// without this helper having to know about the outer state shape.
pub enum ReconnectOutcome {
    Connected,
    Failed(String),
}

/// Replace the persona listener and wait for it to come up. Used by the
/// mediator-change branch of SubmitEdit and by the manual ReconnectMediator
/// settings action — both go through this dance.
///
/// The work is split in two: `persona_listener_config` builds the new listener
/// config (local-only: reads secrets from the TDK resolver, no network), and
/// [`reconnect_persona_listener_io`] does the slow connect I/O. The runtime loop
/// (R13) drives them separately — building the config on its own thread and
/// handing only the I/O half to a background task — so the up-to-30 s wait no
/// longer parks the select loop. Returns:
///   * `Connected` once the listener reaches the connected state, or
///   * `Failed(reason)` on any error during the replace / connect path.
///
/// This is the I/O-only half: it tears down the existing persona listener,
/// installs the prebuilt `new_config`, and waits up to 30 s for it to connect.
/// It borrows nothing tied to the loop's `Config`/`TDK` — `DIDCommService` is
/// cheap to clone (`Arc`-based) and `ListenerConfig`/`listener_id` are owned —
/// which makes it `tokio::spawn`-friendly.
///
/// Active-persona only (these manual actions act on the active identity);
/// per-persona reconnect lands with the persona-selection slice.
pub async fn reconnect_persona_listener_io(
    service: &DIDCommService,
    listener_id: String,
    new_config: ListenerConfig,
) -> ReconnectOutcome {
    if let Err(e) = service.remove_listener(&listener_id).await {
        debug!("remove_listener during reconnect: {e}");
    }
    if let Err(e) = service.add_listener(new_config).await {
        return ReconnectOutcome::Failed(format!("{e:#}"));
    }
    match service
        .wait_connected(&listener_id, std::time::Duration::from_secs(30))
        .await
    {
        Ok(()) => ReconnectOutcome::Connected,
        Err(e) => ReconnectOutcome::Failed(format!("{e:#}")),
    }
}

/// Build the DIDComm message router.
///
/// Trust pings are handled automatically via the built-in handler.
/// All OpenVTC protocol messages and trust pongs are forwarded as
/// `DIDCommEvent::InboundMessage` for the state handler to process.
///
/// Returns an error if any route or regex registration fails. Routes
/// are otherwise stable — only the OpenVTC protocol regex can fail at
/// runtime if it ever becomes invalid.
pub fn build_router(event_tx: mpsc::Sender<DIDCommEvent>) -> Result<Router, anyhow::Error> {
    let openvtc_handler = handler_fn({
        let tx = event_tx.clone();
        move |ctx: affinidi_messaging_didcomm_service::HandlerContext, msg: Message| {
            let tx = tx.clone();
            async move {
                tracing::info!(
                    listener = %ctx.listener_id,
                    msg_type = %msg.typ,
                    from = ?msg
                        .from
                        .as_deref()
                        .map(|d| openvtc_core::display::truncate_did(d, 32)),
                    to = ?msg.to.as_ref().map(|dids| {
                        dids.iter()
                            .map(|d| openvtc_core::display::truncate_did(d, 32))
                            .collect::<Vec<_>>()
                    }),
                    thid = ?msg.thid,
                    "inbound OpenVTC message received"
                );
                if let Err(e) = tx.try_send(DIDCommEvent::InboundMessage {
                    from: msg.from.clone(),
                    message: Box::new(msg),
                }) {
                    tracing::warn!(error = %e, "DIDComm event channel saturated — dropping inbound message");
                }
                Ok(None)
            }
        }
    });

    let router = Router::new()
        // Trust ping — forward to state handler for relationship verification
        // before responding. Only respond to pings from established relationships.
        .route(
            affinidi_messaging_didcomm_service::TRUST_PING_TYPE,
            handler_fn({
                let tx = event_tx.clone();
                move |ctx: affinidi_messaging_didcomm_service::HandlerContext, msg: Message| {
                    let tx = tx.clone();
                    let listener_id = ctx.listener_id.clone();
                    async move {
                        if let Err(e) = tx.try_send(DIDCommEvent::TrustPingReceived {
                            from: msg.from.clone(),
                            listener_id,
                            message_id: msg.id.clone(),
                        }) {
                            tracing::warn!(error = %e, "DIDComm event channel saturated — dropping trust-ping");
                        }
                        // Do NOT auto-respond — state handler will send pong
                        // only after verifying the sender has a relationship.
                        Ok(None)
                    }
                }
            }),
        )?
        // Trust pong — notify state handler for logging and task removal
        .route(
            affinidi_messaging_didcomm_service::TRUST_PONG_TYPE,
            handler_fn({
                let tx = event_tx.clone();
                move |_ctx: affinidi_messaging_didcomm_service::HandlerContext, msg: Message| {
                    let tx = tx.clone();
                    async move {
                        let from = msg.from.clone();
                        // Forward the pong as InboundMessage for task removal
                        if let Err(e) = tx.try_send(DIDCommEvent::InboundMessage {
                            from: from.clone(),
                            message: Box::new(msg),
                        }) {
                            tracing::warn!(error = %e, "DIDComm event channel saturated — dropping trust-pong");
                            return Ok(None);
                        }
                        // Also send specific pong event for logging — best-effort.
                        let _ = tx.try_send(DIDCommEvent::TrustPongReceived { from });
                        Ok(None)
                    }
                }
            }),
        )?
        // Catch-all for OpenVTC protocol messages + VTC Trust-Task replies
        // (e.g. join-requests/submit-receipt). The state handler dispatches
        // by type and ignores any it doesn't handle.
        .route_regex(
            "https://linuxfoundation\\.org/openvtc/.*|https://firstperson\\.network/.*|https://trusttasks\\.org/openvtc/vtc/.*|https://trusttasks\\.org/spec/credential-exchange/.*",
            openvtc_handler,
        )?
        // Message pickup status — silently drop
        .route(
            openvtc_core::protocol_urls::MESSAGEPICKUP_STATUS,
            handler_fn(
                |_ctx: affinidi_messaging_didcomm_service::HandlerContext, _msg: Message| async {
                    Ok(None)
                },
            ),
        )?
        // Fallback for unknown message types
        .fallback(handler_fn(
            |_ctx: affinidi_messaging_didcomm_service::HandlerContext, msg: Message| async move {
                debug!(typ = %msg.typ, "unhandled message type — dropped");
                Ok(None)
            },
        ));
    Ok(router)
}

/// Extract secrets for a DID from the TDK's secrets resolver.
///
/// Uses `config.key_info` to find the verification method IDs associated with the DID,
/// then looks up the corresponding secrets from the TDK's threaded secrets resolver.
async fn get_secrets_for_did(
    tdk: &affinidi_tdk::TDK,
    config: &Config,
    did: &str,
) -> Vec<affinidi_tdk::secrets_resolver::secrets::Secret> {
    let resolver = tdk.shared().secrets_resolver();

    let mut secrets = vec![];
    for key_id in config.key_info.keys() {
        if key_id.starts_with(did)
            && let Some(secret) = resolver.get_secret(key_id).await
        {
            secrets.push(secret);
        }
    }
    secrets
}

/// Create a `TDKProfile` from DID/mediator strings with optional secrets.
fn make_profile(
    did: &str,
    mediator: &str,
    alias: &str,
    secrets: Vec<affinidi_tdk::secrets_resolver::secrets::Secret>,
) -> TDKProfile {
    TDKProfile::new(alias, did, Some(mediator), secrets)
}

/// Default restart policy for all listeners.
///
/// Only restart on failure, not on clean disconnect. This prevents a
/// reconnect loop when the mediator closes our connection as a "duplicate"
/// (e.g. when a second process or listener opens a connection for the same DID).
/// Clean exits (listen() returns Ok) will NOT trigger a restart.
fn default_listener_restart_policy() -> RestartPolicy {
    RestartPolicy::OnFailure {
        max_retries: None,
        backoff: RetryConfig {
            initial_delay_secs: 5,
            max_delay_secs: 60,
        },
    }
}

/// Build `ListenerConfig`s from the loaded `Config`.
///
/// Includes one persona listener per resolved identity (so every community's
/// persona receives messages), plus per-relationship listeners for established
/// relationships that use a dedicated R-DID (different from any persona DID).
///
/// Secrets for each DID are extracted from the TDK's secrets resolver
/// so that each listener can authenticate with the mediator.
pub async fn build_listener_configs(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
) -> Vec<ListenerConfig> {
    let restart = default_listener_restart_policy();

    // One persona listener per resolved identity. A single-persona account
    // yields exactly one — identical to the previous behaviour. `persona_dids`
    // is also the exclusion set for the R-DID listeners below.
    let mut configs = Vec::new();
    let mut persona_dids = std::collections::HashSet::new();
    for identity in config.identities.values() {
        let did = identity.did.as_str();
        if !persona_dids.insert(did.to_string()) {
            continue;
        }
        let persona_secrets = get_secrets_for_did(tdk, config, did).await;
        let mediator = identity
            .mediator_did
            .as_deref()
            .unwrap_or(config.mediator_did());
        let label = config.persona_profile_label_for(identity.persona_id);
        configs.push(ListenerConfig {
            id: persona_listener_id(did),
            profile: make_profile(did, mediator, &label, persona_secrets),
            restart_policy: restart.clone(),
            // Keep `auto_delete: true`. It delegates message deletion to the
            // mediator's live-stream protocol, which uses the mediator-native
            // storage id. If you ever set this to false and delete from app
            // code, you MUST delete by `UnpackMetadata.sha256_hash` (the
            // mediator-native id), NOT by the DIDComm protocol id `msg.id` —
            // they are different domains and the mediator's delete API only
            // accepts the former. Mixing them silently leaks messages and
            // causes duplicate processing on reconnect (see issue #44).
            auto_delete: true,
            ..Default::default()
        });
    }

    // Add listeners for each relationship with a dedicated R-DID.
    // Include pending relationships (RequestSent, RequestAccepted) so that
    // messages arriving during an in-progress handshake are received after restart.
    // Deduplicate by our_did to prevent multiple listeners for the same DID,
    // which would cause a reconnect loop as the mediator detects duplicates.
    // Exclude ALL persona DIDs (their own listeners carry those relationships).
    // Extract data from the Mutex before any .await to avoid holding the guard.
    let mut seen_dids = std::collections::HashSet::new();
    let r_did_entries: Vec<(String, String)> = config
        .private
        .relationships
        .relationships
        .iter()
        .filter_map(|(remote_p_did, rel)| {
            if matches!(
                rel.state,
                RelationshipState::Established
                    | RelationshipState::RequestSent
                    | RelationshipState::RequestAccepted
            ) && !persona_dids.contains(rel.our_did.as_str())
                && seen_dids.insert(rel.our_did.to_string())
            {
                Some((rel.our_did.to_string(), remote_p_did.to_string()))
            } else {
                None
            }
        })
        .collect();

    for (our_did, remote_p_did) in &r_did_entries {
        let r_did_secrets = get_secrets_for_did(tdk, config, our_did).await;
        configs.push(ListenerConfig {
            id: format!("rel-{}", short_did_id(our_did)),
            profile: make_profile(
                our_did,
                config.mediator_did(),
                &format!(
                    "R-DID for {}",
                    openvtc_core::display::truncate_did(remote_p_did, 32)
                ),
                r_did_secrets,
            ),
            restart_policy: restart.clone(),
            auto_delete: true,
            ..Default::default()
        });
    }

    debug!(
        persona_listeners = persona_dids.len(),
        r_did_listeners = r_did_entries.len(),
        total = configs.len(),
        "built listener configs"
    );

    configs
}

/// Determine the listener ID to use for sending messages from a given DID.
///
/// If `our_did` is one of our persona DIDs, use that persona's listener.
/// Otherwise, use the relationship-listener naming convention.
pub fn listener_id_for_did(our_did: &str, config: &Config) -> String {
    if config.is_persona_did(our_did) {
        persona_listener_id(our_did)
    } else {
        format!("rel-{}", short_did_id(our_did))
    }
}

/// Convenience wrapper: send a DIDComm message through the correct listener
/// based on the sender DID, with retry on transient failures.
pub async fn send_message(
    service: &DIDCommService,
    config: &Config,
    message: &Message,
    from_did: &str,
    to_did: &str,
) -> Result<(), DIDCommServiceError> {
    let listener_id = listener_id_for_did(from_did, config);
    send_message_via(service, message, &listener_id, to_did).await
}

/// Send a DIDComm message through a specific listener, with retry on transient failures.
///
/// Use this when the transport listener should differ from the logical sender —
/// for example, sending via the already-connected persona listener when a newly
/// created R-DID listener may not be ready yet.
pub async fn send_message_via(
    service: &DIDCommService,
    message: &Message,
    listener_id: &str,
    to_did: &str,
) -> Result<(), DIDCommServiceError> {
    tracing::info!(
        listener = %listener_id,
        msg_type = %message.typ,
        from = ?message
            .from
            .as_deref()
            .map(|d| openvtc_core::display::truncate_did(d, 32)),
        to = %openvtc_core::display::truncate_did(to_did, 32),
        thid = ?message.thid,
        "sending DIDComm message"
    );
    service
        .send_message_with_retry(
            listener_id,
            message.clone(),
            to_did,
            3,
            std::time::Duration::from_secs(2),
        )
        .await
}

/// Subscribe to `DIDCommService` lifecycle events and forward them as
/// log messages via the provided sender. Detects rapid reconnect cycling
/// and logs warnings. Returns the spawned task handle.
pub fn spawn_lifecycle_logger(
    service: &DIDCommService,
    log_tx: mpsc::UnboundedSender<String>,
) -> tokio::task::JoinHandle<()> {
    let mut events_rx = service.subscribe();
    tokio::spawn(async move {
        // Track disconnect timestamps per listener to detect rapid cycling
        let mut last_disconnect: std::collections::HashMap<String, std::time::Instant> =
            std::collections::HashMap::new();

        loop {
            match events_rx.recv().await {
                Ok(ListenerEvent::Connected { listener_id }) => {
                    let _ = log_tx.send(format!("Listener '{listener_id}' connected"));
                }
                Ok(ListenerEvent::Disconnected { listener_id, error }) => {
                    let now = std::time::Instant::now();
                    let msg = match &error {
                        Some(e) => format!("Listener '{listener_id}' disconnected: {e}"),
                        None => format!("Listener '{listener_id}' disconnected"),
                    };
                    let _ = log_tx.send(msg);

                    // Detect rapid cycling: if we disconnected within 10s of last disconnect
                    if let Some(prev) = last_disconnect.get(&listener_id)
                        && now.duration_since(*prev).as_secs() < 10
                    {
                        let warn_msg = format!(
                            "WARNING: Listener '{listener_id}' cycling rapidly — possible duplicate connection"
                        );
                        tracing::warn!(listener = %listener_id, "rapid disconnect cycling detected");
                        let _ = log_tx.send(warn_msg);
                    }
                    last_disconnect.insert(listener_id, now);
                }
                Ok(ListenerEvent::Restarting {
                    listener_id,
                    attempt,
                    delay,
                }) => {
                    let _ = log_tx.send(format!(
                        "Listener '{listener_id}' restarting (attempt {attempt}, backoff {delay:?})"
                    ));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let _ = log_tx.send(format!("Missed {n} lifecycle event(s)"));
                }
            }
        }
    })
}

/// Build a single `ListenerConfig` for the persona DID.
pub async fn persona_listener_config(config: &Config, tdk: &affinidi_tdk::TDK) -> ListenerConfig {
    let secrets = get_secrets_for_did(tdk, config, config.persona_did()).await;
    ListenerConfig {
        id: persona_listener_id(config.persona_did()),
        profile: make_profile(
            config.persona_did(),
            config.mediator_did(),
            &config.persona_profile_label(),
            secrets,
        ),
        restart_policy: default_listener_restart_policy(),
        auto_delete: true,
        ..Default::default()
    }
}

/// Start the DIDComm service with the given config.
pub async fn start_service(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    event_tx: mpsc::Sender<DIDCommEvent>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<DIDCommService, DIDCommServiceError> {
    let router = build_router(event_tx)
        .map_err(|e| DIDCommServiceError::Internal(format!("router init failed: {e}")))?;
    let listener_configs = build_listener_configs(config, tdk).await;

    DIDCommService::start(
        DIDCommServiceConfig {
            listeners: listener_configs,
        },
        router,
        shutdown,
    )
    .await
}

/// Produce a short, collision-resistant identifier from a DID for listener IDs.
///
/// Uses a SHA-256 hash (first 16 hex chars) to avoid collisions that would occur
/// with simple truncation — did:peer DIDs share a long common prefix.
fn short_did_id(did: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(did.as_bytes());
    hex::encode(&hash[..8])
}

/// Build a relationship R-DID `ListenerConfig` from already-owned secrets.
///
/// Config/TDK-free, so a backgrounded relationship-creation task (R14) can build
/// the new R-DID listener from the secrets it just minted — no resolver lookup,
/// no `Config` borrow — keeping the task `'static` + `Send`.
pub fn relationship_listener_config_from_secrets(
    our_did: &str,
    remote_p_did: &str,
    mediator_did: &str,
    secrets: Vec<affinidi_tdk::secrets_resolver::secrets::Secret>,
) -> ListenerConfig {
    ListenerConfig {
        id: format!("rel-{}", short_did_id(our_did)),
        profile: make_profile(
            our_did,
            mediator_did,
            &format!(
                "R-DID for {}",
                openvtc_core::display::truncate_did(remote_p_did, 32)
            ),
            secrets,
        ),
        restart_policy: default_listener_restart_policy(),
        auto_delete: true,
        ..Default::default()
    }
}
