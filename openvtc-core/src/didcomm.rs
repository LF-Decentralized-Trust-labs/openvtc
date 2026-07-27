//! DIDComm **transport** plumbing: listener construction, routing, outbound
//! sending, and listener lifecycle.
//!
//! Runs on the **delivery layer** (`affinidi-messaging-delivery`): one
//! `MessagingService` holding one `DidCommTransport` per identity, with a
//! durable outbox behind every send.
//!
//! It used to wrap `affinidi-messaging-didcomm-service`, the type-routed framework
//! both VTI services cut away from (#189). That crate is no longer a dependency of
//! this workspace.
//!
//! ## Why this is in `openvtc-core` and not the TUI
//!
//! It lived at `openvtc/src/state_handler/didcomm.rs` until the delivery-layer
//! migration (#189) needed it under test. `openvtc` is a **binary-only** crate
//! (`[[bin]]`, no `src/lib.rs`), so no integration test can import it — which is
//! why this module, alone among OpenVTC's messaging code, had no coverage beyond
//! two pure unit groups. Its failure mode is `duplicate-channel` and duelling
//! reconnect loops, which produce neither a compile error nor a failing unit
//! test, so rewriting it without integration coverage was the wrong trade.
//!
//! Nothing here referenced the binary crate, so the move is mechanical.
//!
//! ## Relationship to [`crate::messaging`]
//!
//! Deliberately separate, and the split is load-bearing:
//!
//! - [`crate::messaging`] is **pure protocol logic** — inbound handling over core
//!   domain types, no async I/O orchestration. That purity is what makes the
//!   dispatch state machine unit-testable, so transport plumbing must not leak
//!   into it.
//! - this module is the **transport**: sockets, listeners, mediators, retries.
//!
//! The one crossing point is [`crate::messaging::build_didcomm_message`],
//! re-exported below because building a message is pure and belongs with the
//! protocol logic.

use crate::config::Config;
use crate::relationships::RelationshipState;
/// A listener's live connection state, re-exported so consumers of this module
/// need not depend on `affinidi-messaging-core` directly.
pub use affinidi_messaging_core::ConnState;
use affinidi_messaging_core::MessageTransport;
use affinidi_messaging_delivery::{
    Delivery, InMemoryOutboxStore, MessagingService, OutboxStore, drain_loop_via,
};
use affinidi_messaging_sdk::DidCommTransport;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::debug;

/// Anything that can go wrong bringing a listener up or sending through one.
#[derive(Debug, thiserror::Error)]
pub enum MessagingError {
    /// The identity's ATM / profile / websocket could not be established.
    #[error("could not bring up listener {listener_id}: {reason}")]
    Listener { listener_id: String, reason: String },
    /// A send named a listener that is not installed. Distinct from a transport
    /// failure: this is a caller bug or a torn-down listener, not the network
    /// (R6.4 — the operator must be able to tell them apart).
    #[error("no listener installed for {0}")]
    UnknownListener(String),
    /// Packing the message for the recipient failed.
    #[error("could not pack message for {recipient}: {reason}")]
    Pack { recipient: String, reason: String },
    /// The delivery layer rejected the send or the outbox enqueue.
    #[error("send failed: {0}")]
    Send(String),
}

/// How a listener is described, independently of the framework that runs it.
///
/// The delivery-layer swap replaces `ListenerConfig` (a
/// `affinidi-messaging-didcomm-service` type) with an ATM profile plus a
/// `DidCommTransport`, and the two have no common constructor. This spec is the
/// shape both can be built from — DID, mediator, label, secrets — so the callers
/// that build listeners (persona reconnect, relationship creation) name *what*
/// they want without naming *which* framework runs it.
///
/// Deliberately not `ListenerConfig` re-exported: keeping the framework type in
/// the signatures is what would force every caller to change again at the swap.
#[derive(Clone)]
pub struct ListenerSpec {
    /// The listener id — the DID, per [`persona_listener_id`].
    pub id: String,
    /// The identity this listener speaks as.
    pub did: String,
    /// The mediator it connects through.
    pub mediator_did: String,
    /// Human label for the messaging profile (the community, or the relationship).
    pub label: String,
    /// Signing + key-agreement secrets for [`did`](Self::did).
    pub secrets: Vec<Secret>,
}

impl std::fmt::Debug for ListenerSpec {
    /// Hand-written so the secrets are never rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerSpec")
            .field("id", &self.id)
            .field("did", &self.did)
            .field("mediator_did", &self.mediator_did)
            .field("label", &self.label)
            .field(
                "secrets",
                &format_args!("<{} redacted>", self.secrets.len()),
            )
            .finish()
    }
}

/// DIDComm trust-ping / trust-pong types.
///
/// Re-declared rather than imported from the framework: this module is moving off
/// `affinidi-messaging-didcomm-service`, and these two constants are the only part
/// of its type vocabulary the dispatcher still needs. `vtc-service` re-declared the
/// same pair for the same reason when it cut over.
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PONG_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

/// How often the drain retries a queued outbound message.
///
/// The outbox replaces the framework's `send_message_with_retry` (3 attempts, 2 s
/// exponential, on a disconnected listener). A short interval keeps the common
/// case — a send issued moments before the socket settles — feeling immediate;
/// the per-entry exponential backoff in `drain_once_via` is what stops a genuinely
/// unreachable mediator from being hammered.
const DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// The delivery window for an outbound message before the outbox settles it
/// visibly rather than retrying forever (R1.2 — every wait is bounded).
///
/// Generous relative to the framework's ~6 s of retries, because the outbox
/// survives a reconnect where the old path simply failed. Past this the entry
/// becomes `Failed` and is surfaced, never a silent success.
const DELIVER_BY: std::time::Duration = std::time::Duration::from_secs(120);

/// How often listener connection state is sampled for the activity log.
///
/// The framework pushed `ListenerEvent`s; the delivery layer exposes a live state
/// per transport instead, so transitions are sampled. 500 ms is well inside human
/// perception for a status line and cheap — reading a `watch` borrow per transport.
const LIFECYCLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Two disconnects closer together than this are reported as rapid cycling —
/// usually a duplicate connection fighting itself for one DID.
const CYCLING_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// Buffered connection transitions per subscriber. Transitions are rare (a
/// listener connects, drops, reconnects), so this is generous; a subscriber that
/// still lags reports the gap rather than silently missing a state change.
const LISTENER_STATUS_CAPACITY: usize = 64;

/// One identity's wire: the ATM and profile outbound packing needs.
///
/// The delivery layer's `MessageTransport::send` takes **already-packed** bytes —
/// packing is `MessagingProtocol`'s concern, not the transport's — so sending *as*
/// an identity needs that identity's ATM, not just its transport. The framework
/// hid this behind `send_message(listener_id, …)`.
struct IdentityWire {
    atm: ATM,
    did: String,
}

/// The runtime messaging handle: one transport per identity, multiplexed through
/// one [`MessagingService`], with a durable outbox behind every send.
///
/// Replaces `DIDCommService`. The shape difference that matters: the framework
/// owned N *listeners*, and this owns N *transports keyed by identity* — the
/// transport determines the proven sender, so "send as this persona" is
/// `send_via(persona_did, …)` rather than a listener lookup.
///
/// Cheap to clone (`Arc` inside), because call sites hand it to spawned tasks.
#[derive(Clone)]
pub struct Messaging {
    inner: Arc<MessagingInner>,
}

/// A listener's connection transition, broadcast to every interested consumer.
///
/// Replaces the framework's `ListenerEvent`. Emitted by the single connection
/// poller [`Messaging`] owns, so the session manager and the activity log observe
/// the *same* transitions rather than each sampling independently and disagreeing.
#[derive(Debug, Clone)]
pub enum ListenerStatus {
    Connected {
        listener_id: String,
    },
    Disconnected {
        listener_id: String,
        /// Always `None` on the delivery layer: a transport surfaces a *state*,
        /// not a cause, and the framework's socket error has no equivalent here.
        /// Kept so the session manager's failed-vs-disconnected distinction stays
        /// expressible if the transport ever carries a reason.
        error: Option<String>,
    },
}

struct MessagingInner {
    service: Arc<MessagingService>,
    /// Connection transitions from the one poller.
    status_tx: tokio::sync::broadcast::Sender<ListenerStatus>,
    /// Shared by every identity's drain. One store, `via`-partitioned, so each
    /// entry is claimed by exactly one `drain_loop_via` (see
    /// `affinidi-messaging-delivery` 0.1.12).
    outbox: Arc<dyn OutboxStore>,
    identities: tokio::sync::RwLock<HashMap<String, IdentityWire>>,
    /// Dispatcher + per-identity drains, aborted on [`Messaging::shutdown`].
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Messaging {
    /// Stand up an empty messaging runtime and start its inbound dispatcher.
    ///
    /// Listeners are added with [`add_listener`]; starting empty is what lets the
    /// dispatcher be running before the first transport connects, so no inbound
    /// frame is missed on a listener that comes up quickly.
    pub fn start(event_tx: mpsc::Sender<DIDCommEvent>) -> Self {
        let outbox: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
        let service = Arc::new(MessagingService::empty(outbox.clone()));
        let (status_tx, _) = tokio::sync::broadcast::channel(LISTENER_STATUS_CAPACITY);
        let inner = Arc::new(MessagingInner {
            service: service.clone(),
            status_tx: status_tx.clone(),
            outbox,
            identities: tokio::sync::RwLock::new(HashMap::new()),
            tasks: std::sync::Mutex::new(Vec::new()),
        });

        let dispatcher = tokio::spawn(dispatch_inbound(service.clone(), event_tx));
        let poller = tokio::spawn(poll_listener_status(service, status_tx));
        {
            let mut tasks = inner.tasks.lock().expect("tasks mutex");
            tasks.push(dispatcher);
            tasks.push(poller);
        }

        Self { inner }
    }

    /// Whether a transport is installed for `listener_id`.
    pub async fn has_listener(&self, listener_id: &str) -> bool {
        self.inner.identities.read().await.contains_key(listener_id)
    }

    /// Every installed listener id.
    pub async fn list_listeners(&self) -> Vec<String> {
        self.inner.identities.read().await.keys().cloned().collect()
    }

    /// Remove a listener: drop its transport (closing the socket) and forget its
    /// wire. Queued outbox entries pinned to it stay queued — they are bound to an
    /// identity, and re-routing them would send from the wrong sender — and settle
    /// visibly when their delivery window expires.
    pub async fn remove_listener(&self, listener_id: &str) {
        self.inner.service.remove_transport(listener_id);
        self.inner.identities.write().await.remove(listener_id);
    }

    /// This listener's live connection state, or `None` if not installed.
    pub fn listener_state(&self, listener_id: &str) -> Option<ConnState> {
        self.inner.service.transport_state(listener_id)
    }

    /// The DID a listener speaks as.
    ///
    /// For a persona listener this is the id itself; for a relationship listener
    /// the id is a hash, so the mapping has to be looked up rather than assumed.
    pub async fn listener_did(&self, listener_id: &str) -> Option<String> {
        self.inner
            .identities
            .read()
            .await
            .get(listener_id)
            .map(|wire| wire.did.clone())
    }

    /// Subscribe to listener connection transitions.
    ///
    /// Every subscriber sees the same transitions from the one poller, so the
    /// session manager and the activity log cannot disagree about whether a
    /// listener is up.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ListenerStatus> {
        self.inner.status_tx.subscribe()
    }

    /// Wait until `listener_id` reports `Connected`, or `timeout` elapses.
    ///
    /// Polls the transport's live signal rather than latching at boot (R6.2), so a
    /// listener that connects, drops and reconnects reads truthfully throughout.
    pub async fn wait_connected(
        &self,
        listener_id: &str,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.listener_state(listener_id) {
                Some(ConnState::Connected) => return Ok(()),
                state if tokio::time::Instant::now() >= deadline => {
                    return Err(format!(
                        "listener {listener_id} did not connect within {timeout:?} \
                         (last state: {state:?})"
                    ));
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    }

    /// Stop every drain and the dispatcher, and drop all transports.
    pub async fn shutdown(&self) {
        let handles: Vec<_> = std::mem::take(&mut *self.inner.tasks.lock().expect("tasks mutex"));
        for handle in handles {
            handle.abort();
        }
        let ids: Vec<String> = self.inner.identities.read().await.keys().cloned().collect();
        for id in ids {
            self.inner.service.remove_transport(&id);
        }
        self.inner.identities.write().await.clear();
    }
}

/// Fallback listener ID for the persona DID listener when no DID is available
/// (e.g. a State-A account with no persona).
pub const PERSONA_LISTENER_ID: &str = "persona";

/// The listener ID for a persona: **its DID, verbatim**.
///
/// This is an *identity key*, not a label. It keys the rapid-cycling detection
/// map in [`spawn_lifecycle_logger`] and is what reconnect logic matches on, so
/// it has to be collision-free. A DID is; a trailing path segment is not —
/// `did:webvh:ScidA:host1.example:magic-depart` and
/// `did:webvh:ScidB:host2.example:magic-depart` would collapse onto one id and
/// two personas would share a listener. Do not shorten it here.
///
/// It used to run the DID through `context_path::render_for_display` and the doc
/// promised a short slug (`silent-tongue`). That call was always a no-op: it
/// splits on `/`, which a DID has none of, so the whole DID came back. Removing
/// it changes no behaviour and stops the contract claiming something it never
/// delivered.
///
/// Display is a separate concern, handled where the id is *rendered* rather than
/// where it is minted: the runtime loop formats listener ids through
/// `resolve_did_to_display`, so the activity log reads
/// `Listener 'webvh.storm.ws/@magic-depart' connected`.
///
/// Derived from the DID alone (not the full `Config`) so the runtime and message
/// senders (`listener_id_for_did`) agree on the same id without extra context.
pub fn persona_listener_id(persona_did: &str) -> String {
    if persona_did.is_empty() {
        PERSONA_LISTENER_ID.to_string()
    } else {
        persona_did.to_string()
    }
}

/// Build a timestamped DIDComm message with standard 48-hour expiry.
///
/// Re-exported from [`crate::messaging`]; the implementation moved to
/// core (it is pure) so the protocol logic there can build its own messages.
pub use crate::messaging::build_didcomm_message;

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
/// It borrows nothing tied to the loop's `Config`/`TDK` — [`Messaging`] is
/// cheap to clone (`Arc`-based) and [`ListenerSpec`]/`listener_id` are owned —
/// which makes it `tokio::spawn`-friendly.
///
/// Active-persona only (these manual actions act on the active identity);
/// per-persona reconnect lands with the persona-selection slice.
pub async fn reconnect_persona_listener_io(
    service: &Messaging,
    listener_id: String,
    new_config: ListenerSpec,
) -> ReconnectOutcome {
    // Drop the old transport first. The mediator permits one websocket per DID,
    // rejecting a second with `duplicate-channel`, so adding before removing would
    // leave two sockets racing on the same identity — the duelling-reconnect
    // failure this codebase has already been bitten by (#132).
    service.remove_listener(&listener_id).await;
    if let Err(e) = add_listener(service, &new_config).await {
        return ReconnectOutcome::Failed(format!("{e:#}"));
    }
    match service
        .wait_connected(&listener_id, std::time::Duration::from_secs(30))
        .await
    {
        Ok(()) => ReconnectOutcome::Connected,
        Err(e) => ReconnectOutcome::Failed(e),
    }
}

/// Install a listener described by `spec` on a running [`Messaging`].
///
/// Brings up one identity's wire, in the order the SDK requires: secrets seeded
/// **before** `ATM::new` (the resolver is read during construction), profile via
/// `from_tdk_profile`, then `profile_add(_, true)` to connect the websocket —
/// `DidCommTransport::new` fails on a profile with no websocket running.
///
/// The transport is installed under `spec.id`, which is the identity's DID. That
/// is what makes `send_via` mean "send **as** this persona": the transport
/// determines the proven sender, so the wire is not interchangeable between
/// identities.
///
/// Each identity also gets its own `drain_loop_via` over the shared outbox, so a
/// retried message goes back out over the socket it was queued for rather than
/// whichever transport happens to be primary.
pub async fn add_listener(service: &Messaging, spec: &ListenerSpec) -> Result<(), MessagingError> {
    let fail = |reason: String| MessagingError::Listener {
        listener_id: spec.id.clone(),
        reason,
    };

    let tdk_profile = make_profile(
        &spec.did,
        &spec.mediator_did,
        &spec.label,
        spec.secrets.clone(),
    );
    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .build()
            .map_err(|e| fail(format!("TDK config: {e}")))?,
    )
    .await
    .map_err(|e| fail(format!("TDK init: {e}")))?;
    for secret in spec.secrets.clone() {
        tdk.secrets_resolver().insert(secret).await;
    }
    let atm = ATM::new(
        ATMConfig::builder()
            .build()
            .map_err(|e| fail(format!("ATM config: {e}")))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| fail(format!("ATM init: {e}")))?;
    let atm_profile = ATMProfile::from_tdk_profile(&atm, &tdk_profile)
        .await
        .map_err(|e| fail(format!("profile: {e}")))?;
    let profile = atm
        .profile_add(&atm_profile, true)
        .await
        .map_err(|e| fail(format!("mediator connect: {e}")))?;
    let transport: Arc<dyn MessageTransport> = Arc::new(
        DidCommTransport::new(atm.clone(), profile)
            .await
            .map_err(|e| fail(format!("transport bind: {e}")))?,
    );

    service
        .inner
        .service
        .add_transport(spec.id.clone(), transport.clone());
    service.inner.identities.write().await.insert(
        spec.id.clone(),
        IdentityWire {
            atm,
            did: spec.did.clone(),
        },
    );

    let drain = tokio::spawn(drain_loop_via(
        service.inner.outbox.clone(),
        spec.id.clone(),
        transport,
        DRAIN_INTERVAL,
    ));
    service.inner.tasks.lock().expect("tasks mutex").push(drain);

    debug!(listener = %spec.id, "listener installed on the delivery layer");
    Ok(())
}

/// The single inbound dispatcher: read every transport's merged stream, classify
/// by message type, and forward as [`DIDCommEvent`].
///
/// Replaces the framework's `Router`. The delivery layer has no type-routed
/// dispatch — a consumer matches on the message itself — which is the same move
/// `vtc-service` made when it cut over. Acking is **not** done here: the service's
/// own dispatcher acks after handoff, never before.
async fn dispatch_inbound(service: Arc<MessagingService>, event_tx: mpsc::Sender<DIDCommEvent>) {
    let catch_all = match regex::Regex::new(&format!("^(?:{OPENVTC_CATCH_ALL_PATTERN})$")) {
        Ok(re) => re,
        Err(e) => {
            tracing::error!(error = %e, "catch-all pattern failed to compile — inbound dispatch is dead");
            return;
        }
    };

    let mut inbound = service.subscribe();
    while let Some(item) = inbound.next().await {
        // A DIDComm frame's payload is the `Message` JSON (`to_inbound` in the
        // SDK adapter). A TSP frame's is not, so it will not parse here — TSP
        // routing lands with #185 and is deliberately skipped rather than logged
        // as an error.
        let Ok(message) = serde_json::from_slice::<Message>(&item.message.payload) else {
            continue;
        };
        // The transport authenticated the sender; the plaintext `from` header is
        // sender-controlled. Prefer the cryptographically-bound one.
        let from = item.message.sender.clone().or_else(|| message.from.clone());
        let listener_id = item.message.recipient.clone();

        let event = if message.typ == TRUST_PING_TYPE {
            // Not auto-answered: the state handler pongs only after checking the
            // sender has a relationship.
            DIDCommEvent::TrustPingReceived {
                from,
                listener_id,
                message_id: message.id.clone(),
            }
        } else if message.typ == TRUST_PONG_TYPE {
            // Forwarded as both: InboundMessage drives task removal, the pong
            // event drives the activity log.
            let _ = event_tx
                .try_send(DIDCommEvent::TrustPongReceived { from: from.clone() })
                .inspect_err(|e| tracing::warn!(error = %e, "dropping trust-pong log event"));
            DIDCommEvent::InboundMessage {
                from,
                message: Box::new(message),
            }
        } else if catch_all.is_match(&message.typ) {
            tracing::info!(
                listener = %crate::display::truncate_did(&item.message.recipient, 32),
                msg_type = %message.typ,
                from = ?from.as_deref().map(|d| crate::display::truncate_did(d, 32)),
                thid = ?message.thid,
                "inbound OpenVTC message received"
            );
            DIDCommEvent::InboundMessage {
                from,
                message: Box::new(message),
            }
        } else {
            // Pickup-status heartbeats and anything else: dropped, as the
            // framework's ignore-handler and fallback did.
            debug!(typ = %message.typ, "unhandled message type — dropped");
            continue;
        };

        if let Err(e) = event_tx.try_send(event) {
            tracing::warn!(error = %e, "DIDComm event channel saturated — dropping inbound message");
        }
    }
}

/// Catch-all pattern for OpenVTC protocol messages + VTC Trust-Task
/// replies (e.g. `join-requests/submit-receipt`). The state handler
/// dispatches by type and ignores any it doesn't handle.
///
/// **Both VTC prefixes are accepted.** The VTC's Trust Tasks are moving
/// from the non-conformant `trusttasks.org/openvtc/vtc/…` authority to
/// the canonical registry at `trusttasks.org/spec/vtc/…`. This pattern
/// decides whether a message reaches the handler *at all*, so it must
/// accept the new prefix **before** any VTC starts emitting it —
/// otherwise migrated traffic is dropped here, silently, before dispatch
/// ever sees it. Accepting both also lets a migrated and an unmigrated
/// VTC be talked to during the rollout; the `openvtc/vtc/` arm can be
/// retired once no supported VTC emits it.
pub const OPENVTC_CATCH_ALL_PATTERN: &str = concat!(
    r"https://linuxfoundation\.org/openvtc/.*",
    r"|https://firstperson\.network/.*",
    r"|https://trusttasks\.org/openvtc/vtc/.*",
    r"|https://trusttasks\.org/spec/vtc/.*",
    r"|https://trusttasks\.org/spec/credential-exchange/.*",
    r"|https://didcomm\.org/report-problem/.*",
);

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

/// Build [`ListenerSpec`]s from the loaded `Config`.
///
/// Includes one persona listener per resolved identity (so every community's
/// persona receives messages), plus per-relationship listeners for established
/// relationships that use a dedicated R-DID (different from any persona DID).
///
/// Secrets for each DID are extracted from the TDK's secrets resolver
/// so that each listener can authenticate with the mediator.
pub async fn build_listener_configs(config: &Config, tdk: &affinidi_tdk::TDK) -> Vec<ListenerSpec> {
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
        configs.push(ListenerSpec {
            id: persona_listener_id(did),
            did: did.to_string(),
            mediator_did: mediator.to_string(),
            label,
            secrets: persona_secrets,
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
        configs.push(ListenerSpec {
            id: format!("rel-{}", short_did_id(our_did)),
            did: our_did.to_string(),
            mediator_did: config.mediator_did().to_string(),
            label: format!(
                "R-DID for {}",
                crate::display::truncate_did(remote_p_did, 32)
            ),
            secrets: r_did_secrets,
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
    service: &Messaging,
    config: &Config,
    message: &Message,
    from_did: &str,
    to_did: &str,
) -> Result<(), MessagingError> {
    let listener_id = listener_id_for_did(from_did, config);
    send_message_via(service, message, &listener_id, to_did).await
}

/// Send a DIDComm message through a specific listener, durably.
///
/// Use this when the transport listener should differ from the logical sender —
/// for example, sending via the already-connected persona listener when a newly
/// created R-DID listener may not be ready yet.
pub async fn send_message_via(
    service: &Messaging,
    message: &Message,
    listener_id: &str,
    to_did: &str,
) -> Result<(), MessagingError> {
    tracing::info!(
        listener = %crate::display::truncate_did(listener_id, 32),
        msg_type = %message.typ,
        from = ?message
            .from
            .as_deref()
            .map(|d| crate::display::truncate_did(d, 32)),
        to = %crate::display::truncate_did(to_did, 32),
        thid = ?message.thid,
        "sending DIDComm message"
    );

    // Pack as the sending identity. `MessageTransport::send` takes already-packed
    // bytes — packing is the protocol's concern, not the transport's — so this
    // needs that identity's own ATM, which is why the wire is kept per listener.
    let packed = {
        let identities = service.inner.identities.read().await;
        let wire = identities
            .get(listener_id)
            .ok_or_else(|| MessagingError::UnknownListener(listener_id.to_string()))?;
        wire.atm
            .pack_encrypted(message, to_did, Some(&wire.did), Some(&wire.did))
            .await
            .map_err(|e| MessagingError::Pack {
                recipient: to_did.to_string(),
                reason: e.to_string(),
            })?
            .0
    };

    // `Guaranteed`, not `BestEffort`. The framework call this replaces
    // (`send_message_with_retry`) retried on a disconnected listener; `BestEffort`
    // has no retry, so a straight swap would trade a retry for a dropped message
    // whenever a send lands mid-reconnect. The outbox IS that retry, and a better
    // one: it survives the reconnect and settles visibly if the window expires.
    //
    // Keyed by the message id, so a re-send of the same message dedups at the
    // recipient rather than double-delivering.
    service
        .inner
        .service
        .send_via(
            listener_id,
            to_did,
            packed.into_bytes(),
            Delivery::Guaranteed {
                idempotency_key: Some(message.id.clone()),
                ordering_key: None,
                deliver_by: DELIVER_BY,
            },
        )
        .await
        .map(|_accepted| ())
        .map_err(|e| MessagingError::Send(e.to_string()))
}

/// A listener lifecycle event, ready to be rendered into the activity log.
///
/// Deliberately **not** a pre-formatted string. A listener is identified by its
/// DID, and turning a DID into what the operator should read — a verified agent
/// name, a contact alias, or a truncated DID — needs the `Config`, which lives
/// on the runtime loop thread and is not available to this detached task. So the
/// event carries the identifier and the loop formats it; see
/// `StateHandler::format_lifecycle_log`.
#[derive(Debug, Clone)]
pub enum LifecycleLog {
    /// A listener established its connection.
    Connected { listener_id: String },
    /// A listener's connection dropped, with the transport error if there was one.
    Disconnected {
        listener_id: String,
        error: Option<String>,
    },
    /// A listener dropped again within the cycling window — usually a duplicate
    /// connection fighting itself.
    CyclingRapidly { listener_id: String },
    /// A listener is being restarted after a backoff.
    Restarting {
        listener_id: String,
        attempt: u32,
        delay: std::time::Duration,
    },
    /// The event stream lagged and dropped `count` events.
    Missed { count: u64 },
}

/// Subscribe to listener lifecycle transitions and forward them as
/// structured log events via the provided sender. Detects rapid reconnect
/// cycling. Returns the spawned task handle.
pub fn spawn_lifecycle_logger(
    service: &Messaging,
    log_tx: mpsc::UnboundedSender<LifecycleLog>,
) -> tokio::task::JoinHandle<()> {
    let mut status_rx = service.subscribe();
    tokio::spawn(async move {
        // Disconnect timestamps, for the rapid-cycling heuristic.
        let mut last_disconnect: HashMap<String, std::time::Instant> = HashMap::new();

        loop {
            match status_rx.recv().await {
                Ok(ListenerStatus::Connected { listener_id }) => {
                    let _ = log_tx.send(LifecycleLog::Connected { listener_id });
                }
                Ok(ListenerStatus::Disconnected { listener_id, error }) => {
                    let now = std::time::Instant::now();
                    let _ = log_tx.send(LifecycleLog::Disconnected {
                        listener_id: listener_id.clone(),
                        error,
                    });
                    if let Some(previous_drop) = last_disconnect.get(&listener_id)
                        && now.duration_since(*previous_drop) < CYCLING_WINDOW
                    {
                        tracing::warn!(
                            listener = %crate::display::truncate_did(&listener_id, 32),
                            "rapid disconnect cycling detected"
                        );
                        let _ = log_tx.send(LifecycleLog::CyclingRapidly {
                            listener_id: listener_id.clone(),
                        });
                    }
                    last_disconnect.insert(listener_id, now);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    let _ = log_tx.send(LifecycleLog::Missed { count });
                }
            }
        }
    })
}

/// The one connection poller: sample every transport's live state and broadcast
/// the transitions.
///
/// The framework pushed `ListenerEvent`s; the delivery layer exposes a live
/// `ConnState` per transport instead (R6.2 — re-falsifiable, never a boot-time
/// latch), so transitions are derived by sampling. Doing that once and
/// broadcasting is what keeps every consumer's view identical.
async fn poll_listener_status(
    service: Arc<MessagingService>,
    status_tx: tokio::sync::broadcast::Sender<ListenerStatus>,
) {
    let mut seen: HashMap<String, ConnState> = HashMap::new();
    loop {
        tokio::time::sleep(LIFECYCLE_POLL_INTERVAL).await;

        let states = service.transport_states();
        for (listener_id, state) in &states {
            if seen.insert(listener_id.clone(), *state) == Some(*state) {
                continue;
            }
            let event = match state {
                ConnState::Connected => ListenerStatus::Connected {
                    listener_id: listener_id.clone(),
                },
                _ => ListenerStatus::Disconnected {
                    listener_id: listener_id.clone(),
                    error: None,
                },
            };
            // `Err` only means nobody is subscribed yet — not a failure.
            let _ = status_tx.send(event);
        }

        // Forget removed transports, so a re-added listener reports its connect
        // rather than looking like it never dropped.
        let live: std::collections::HashSet<&String> = states.iter().map(|(id, _)| id).collect();
        seen.retain(|id, _| live.contains(id));
    }
}

/// Build a single [`ListenerSpec`] for the persona DID.
pub async fn persona_listener_config(config: &Config, tdk: &affinidi_tdk::TDK) -> ListenerSpec {
    let secrets = get_secrets_for_did(tdk, config, config.persona_did()).await;
    ListenerSpec {
        id: persona_listener_id(config.persona_did()),
        did: config.persona_did().to_string(),
        mediator_did: config.mediator_did().to_string(),
        label: config.persona_profile_label(),
        secrets,
    }
}

/// Build the persona listener config for a **specific** persona (not necessarily
/// the active one), mirroring one iteration of [`build_listener_configs`]. Used
/// to bring a freshly-joined community's session live at runtime (R-B-5) without
/// a restart. Returns `None` if `persona_id` does not resolve to an identity.
pub async fn persona_listener_config_for(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    persona_id: crate::config::account::PersonaId,
) -> Option<ListenerSpec> {
    let ident = config.identities.get(&persona_id)?;
    let did = ident.did.as_str();
    let secrets = get_secrets_for_did(tdk, config, did).await;
    let mediator = ident
        .mediator_did
        .as_deref()
        .unwrap_or(config.mediator_did());
    let label = config.persona_profile_label_for(persona_id);
    Some(ListenerSpec {
        id: persona_listener_id(did),
        did: did.to_string(),
        mediator_did: mediator.to_string(),
        label,
        secrets,
    })
}

/// Start the DIDComm service with the given config.
pub async fn start_service(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    event_tx: mpsc::Sender<DIDCommEvent>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<Messaging, MessagingError> {
    let service = Messaging::start(event_tx);

    // Listeners are installed one at a time rather than handed over as a set: each
    // is an independent mediator connect, and one persona whose mediator is down
    // must not stop the others coming up. A failure is logged and skipped — the
    // panel reports per-listener state, so a missing one is visible rather than
    // silent, and `reconnect_persona_listener_io` is the recovery path.
    for spec in build_listener_configs(config, tdk).await {
        if let Err(e) = add_listener(&service, &spec).await {
            tracing::warn!(
                listener = %crate::display::truncate_did(&spec.id, 32),
                error = %e,
                "listener failed to come up; continuing without it"
            );
        }
    }

    // The framework owned the shutdown token; now it is ours to honour. Dropping
    // every transport on cancel is what stops a stale socket racing the next
    // process for the same DID (`duplicate-channel`).
    let on_cancel = service.clone();
    tokio::spawn(async move {
        shutdown.cancelled().await;
        on_cancel.shutdown().await;
    });

    Ok(service)
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

/// Build a relationship R-DID [`ListenerSpec`] from already-owned secrets.
///
/// Config/TDK-free, so a backgrounded relationship-creation task (R14) can build
/// the new R-DID listener from the secrets it just minted — no resolver lookup,
/// no `Config` borrow — keeping the task `'static` + `Send`.
pub fn relationship_listener_config_from_secrets(
    our_did: &str,
    remote_p_did: &str,
    mediator_did: &str,
    secrets: Vec<Secret>,
) -> ListenerSpec {
    ListenerSpec {
        id: format!("rel-{}", short_did_id(our_did)),
        did: our_did.to_string(),
        mediator_did: mediator_did.to_string(),
        label: format!(
            "R-DID for {}",
            crate::display::truncate_did(remote_p_did, 32)
        ),
        secrets,
    }
}

#[cfg(test)]
mod persona_listener_id_tests {
    use super::{PERSONA_LISTENER_ID, persona_listener_id};

    /// The contract: the id *is* the DID. Stated as a test because the doc
    /// comment previously promised a slug and the code silently did this.
    #[test]
    fn the_id_is_the_did_verbatim() {
        let did = "did:webvh:QmR6e4:webvh.storm.ws:magic-depart";
        assert_eq!(persona_listener_id(did), did);
    }

    /// The reason not to "fix" this by slugging the trailing segment. Two
    /// personas on different hosts, with different SCIDs, share a final
    /// segment — slugging would key both onto one listener.
    #[test]
    fn personas_sharing_a_trailing_segment_get_distinct_ids() {
        let a = persona_listener_id("did:webvh:ScidA:host1.example:magic-depart");
        let b = persona_listener_id("did:webvh:ScidB:host2.example:magic-depart");
        assert_ne!(a, b, "listener_id is an identity key and must not collide");
    }

    /// A State-A account with no persona still needs a listener id.
    #[test]
    fn an_empty_did_falls_back_to_the_generic_id() {
        assert_eq!(persona_listener_id(""), PERSONA_LISTENER_ID);
    }
}

#[cfg(test)]
mod catch_all_tests {
    use super::OPENVTC_CATCH_ALL_PATTERN;
    use regex::Regex;

    fn matches(uri: &str) -> bool {
        // `route_regex` anchors the whole type string, so mirror that
        // here rather than testing a substring match that would pass
        // for URIs the router would actually reject.
        Regex::new(&format!("^(?:{OPENVTC_CATCH_ALL_PATTERN})$"))
            .expect("catch-all pattern compiles")
            .is_match(uri)
    }

    /// The migration target. Without this arm, a migrated VTC's replies
    /// never reach the handler — dropped by the router, before dispatch.
    #[test]
    fn canonical_vtc_trust_tasks_are_routed() {
        for uri in [
            "https://trusttasks.org/spec/vtc/join-requests/submit/0.1",
            "https://trusttasks.org/spec/vtc/join-requests/submit/0.1#response",
            "https://trusttasks.org/spec/vtc/join-requests/status/0.1#response",
            "https://trusttasks.org/spec/vtc/members/self-remove/0.1",
        ] {
            assert!(matches(uri), "{uri} must reach the OpenVTC handler");
        }
    }

    /// The pre-migration prefix keeps working, so an unmigrated VTC is
    /// still reachable during the rollout.
    #[test]
    fn legacy_vtc_trust_tasks_still_route() {
        for uri in [
            "https://trusttasks.org/openvtc/vtc/spec/join-requests/submit/1.0",
            "https://trusttasks.org/openvtc/vtc/members/self-remove/1.0",
        ] {
            assert!(matches(uri), "{uri} must still reach the handler");
        }
    }

    #[test]
    fn the_other_arms_are_intact() {
        for uri in [
            "https://linuxfoundation.org/openvtc/anything",
            "https://firstperson.network/protocols/x",
            "https://trusttasks.org/spec/credential-exchange/offer/0.1",
            "https://didcomm.org/report-problem/2.0/problem-report",
        ] {
            assert!(matches(uri), "{uri} must reach the handler");
        }
    }

    /// The pattern is a routing gate, not a catch-everything: an
    /// unrelated canonical task must not be swept in.
    #[test]
    fn unrelated_types_are_not_routed() {
        for uri in [
            "https://trusttasks.org/spec/acl/list/0.1",
            "https://trusttasks.org/spec/policy/upsert/0.2",
            "https://example.com/whatever",
        ] {
            assert!(!matches(uri), "{uri} must NOT be routed here");
        }
    }
}
