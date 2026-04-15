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
use openvtc::config::Config;
use openvtc::relationships::RelationshipState;
use tokio::sync::mpsc;
use tracing::debug;

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

/// Build the DIDComm message router.
///
/// Trust pings are handled automatically via the built-in handler.
/// All OpenVTC protocol messages and trust pongs are forwarded as
/// `DIDCommEvent::InboundMessage` for the state handler to process.
pub fn build_router(event_tx: mpsc::UnboundedSender<DIDCommEvent>) -> Router {
    let openvtc_handler = handler_fn({
        let tx = event_tx.clone();
        move |ctx: affinidi_messaging_didcomm_service::HandlerContext, msg: Message| {
            let tx = tx.clone();
            async move {
                tracing::info!(
                    listener = %ctx.listener_id,
                    msg_type = %msg.typ,
                    from = ?msg.from,
                    to = ?msg.to,
                    thid = ?msg.thid,
                    "inbound OpenVTC message received"
                );
                let _ = tx.send(DIDCommEvent::InboundMessage {
                    from: msg.from.clone(),
                    message: Box::new(msg),
                });
                Ok(None)
            }
        }
    });

    Router::new()
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
                        let _ = tx.send(DIDCommEvent::TrustPingReceived {
                            from: msg.from.clone(),
                            listener_id,
                            message_id: msg.id.clone(),
                        });
                        // Do NOT auto-respond — state handler will send pong
                        // only after verifying the sender has a relationship.
                        Ok(None)
                    }
                }
            }),
        )
        .expect("valid route")
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
                        let _ = tx.send(DIDCommEvent::InboundMessage {
                            from: from.clone(),
                            message: Box::new(msg),
                        });
                        // Also send specific pong event for logging
                        let _ = tx.send(DIDCommEvent::TrustPongReceived { from });
                        Ok(None)
                    }
                }
            }),
        )
        .expect("valid route")
        // Catch-all for OpenVTC protocol messages
        .route_regex(
            "https://linuxfoundation\\.org/openvtc/.*|https://firstperson\\.network/.*",
            openvtc_handler,
        )
        .expect("valid route")
        // Message pickup status — silently drop
        .route(
            openvtc::protocol_urls::MESSAGEPICKUP_STATUS,
            handler_fn(
                |_ctx: affinidi_messaging_didcomm_service::HandlerContext, _msg: Message| async {
                    Ok(None)
                },
            ),
        )
        .expect("valid route")
        // Fallback for unknown message types
        .fallback(handler_fn(
            |_ctx: affinidi_messaging_didcomm_service::HandlerContext, msg: Message| async move {
                debug!(typ = %msg.typ, "unhandled message type — dropped");
                Ok(None)
            },
        ))
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
    let resolver = &tdk.get_shared_state().secrets_resolver;

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

/// Build `ListenerConfig`s from the loaded `Config`.
///
/// Always includes a "persona" listener. Adds per-relationship listeners
/// for established relationships that use a dedicated R-DID (different
/// from the persona DID).
///
/// Secrets for each DID are extracted from the TDK's secrets resolver
/// so that each listener can authenticate with the mediator.
pub async fn build_listener_configs(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
) -> Vec<ListenerConfig> {
    let restart = RestartPolicy::Always {
        backoff: RetryConfig::default(),
    };

    let persona_secrets = get_secrets_for_did(tdk, config, &config.public.persona_did).await;

    let mut configs = vec![ListenerConfig {
        id: "persona".to_string(),
        profile: make_profile(
            &config.public.persona_did,
            &config.public.mediator_did,
            "Persona",
            persona_secrets,
        ),
        restart_policy: restart.clone(),
        auto_delete: true,
        ..Default::default()
    }];

    // Add listeners for each relationship with a dedicated R-DID.
    // Include pending relationships (RequestSent, RequestAccepted) so that
    // messages arriving during an in-progress handshake are received after restart.
    // Extract data from the Mutex before any .await to avoid holding the guard.
    let r_did_entries: Vec<(String, String)> = config
        .private
        .relationships
        .relationships
        .iter()
        .filter_map(|(remote_p_did, rel_arc)| {
            let rel = rel_arc.lock().ok()?;
            if matches!(
                rel.state,
                RelationshipState::Established
                    | RelationshipState::RequestSent
                    | RelationshipState::RequestAccepted
            ) && *rel.our_did != *config.public.persona_did
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
                &config.public.mediator_did,
                &format!("R-DID for {}", truncate_did_display(remote_p_did)),
                r_did_secrets,
            ),
            restart_policy: restart.clone(),
            auto_delete: true,
            ..Default::default()
        });
    }

    configs
}

/// Determine the listener ID to use for sending messages from a given DID.
///
/// If `our_did` matches the persona DID, use "persona". Otherwise, use
/// the relationship-listener naming convention.
pub fn listener_id_for_did(our_did: &str, persona_did: &str) -> String {
    if our_did == persona_did {
        "persona".to_string()
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
    let listener_id = listener_id_for_did(from_did, &config.public.persona_did);
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
        from = ?message.from,
        to = %to_did,
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
/// log messages via the provided sender. Returns the spawned task handle.
pub fn spawn_lifecycle_logger(
    service: &DIDCommService,
    log_tx: mpsc::UnboundedSender<String>,
) -> tokio::task::JoinHandle<()> {
    let mut events_rx = service.subscribe();
    tokio::spawn(async move {
        loop {
            match events_rx.recv().await {
                Ok(ListenerEvent::Connected { listener_id }) => {
                    let _ = log_tx.send(format!("Listener '{listener_id}' connected"));
                }
                Ok(ListenerEvent::Disconnected { listener_id, error }) => {
                    let msg = match error {
                        Some(e) => format!("Listener '{listener_id}' disconnected: {e}"),
                        None => format!("Listener '{listener_id}' disconnected"),
                    };
                    let _ = log_tx.send(msg);
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
    let secrets = get_secrets_for_did(tdk, config, &config.public.persona_did).await;
    ListenerConfig {
        id: "persona".to_string(),
        profile: make_profile(
            &config.public.persona_did,
            &config.public.mediator_did,
            "Persona",
            secrets,
        ),
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        ..Default::default()
    }
}

/// Start the DIDComm service with the given config.
pub async fn start_service(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    event_tx: mpsc::UnboundedSender<DIDCommEvent>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<DIDCommService, DIDCommServiceError> {
    let router = build_router(event_tx);
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

/// Truncate a DID for human-readable display (not for unique identification).
fn truncate_did_display(did: &str) -> &str {
    let end = did.len().min(32);
    &did[..end]
}

/// Create a `ListenerConfig` for a relationship R-DID.
pub async fn relationship_listener_config(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    our_did: &str,
    remote_p_did: &str,
    mediator_did: &str,
) -> ListenerConfig {
    let secrets = get_secrets_for_did(tdk, config, our_did).await;
    ListenerConfig {
        id: format!("rel-{}", short_did_id(our_did)),
        profile: make_profile(
            our_did,
            mediator_did,
            &format!("R-DID for {}", truncate_did_display(remote_p_did)),
            secrets,
        ),
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        ..Default::default()
    }
}
