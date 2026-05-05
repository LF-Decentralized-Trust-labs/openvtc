//! Inbound DIDComm message dispatch for the TUI.
//!
//! Messages that don't need human input are auto-processed.
//! Messages requiring user decisions are queued as tasks in the inbox.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::{TDK, didcomm::Message};
use openvtc_core::{
    MessageType,
    config::Config,
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody, RelationshipState},
    tasks::TaskType,
    vrc::VRCRequestReject,
};
use serde_json::json;
use tracing::{debug, info, warn};

/// Maximum allowed message body size in bytes (1 MB).
const MAX_MESSAGE_BODY_SIZE: usize = 1_048_576;

/// Maximum number of tasks allowed before rejecting new inbound messages.
const MAX_TASKS: usize = 10_000;

/// Maximum number of relationships allowed before rejecting new requests.
const MAX_RELATIONSHIPS: usize = 5_000;

/// Reject inbound messages whose `created_time` is older than this. The
/// outbound side stamps a 48-hour expiry, so a 48-hour replay window is
/// the same horizon — anything older is either a replay or a clock skew
/// pathology and is safer to drop.
const MAX_MESSAGE_AGE_SECS: u64 = 48 * 60 * 60;

/// How far in the future a `created_time` may be before we treat it as
/// invalid (clock skew tolerance).
const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

/// Bounded LRU of recently-seen message IDs used to deduplicate replays.
/// 1024 entries is comfortable for an active operator without bloating
/// memory; entries are O(36) bytes each (UUID).
pub struct SeenMessages {
    cap: usize,
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl SeenMessages {
    /// New LRU with the default 1024-entry capacity.
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cap,
            order: VecDeque::with_capacity(cap),
            set: HashSet::with_capacity(cap),
        }
    }

    /// Returns `true` if `id` was already present (i.e. caller should
    /// reject as a replay). Otherwise records `id` and returns `false`.
    pub fn observe(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return true;
        }
        if self.order.len() == self.cap
            && let Some(evicted) = self.order.pop_front()
        {
            self.set.remove(&evicted);
        }
        self.order.push_back(id.to_string());
        self.set.insert(id.to_string());
        false
    }
}

impl Default for SeenMessages {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str, created: Option<u64>, expires: Option<u64>) -> Message {
        let mut m =
            Message::build(id.to_string(), "test".to_string(), serde_json::json!({})).finalize();
        m.created_time = created;
        m.expires_time = expires;
        m
    }

    #[test]
    fn seen_messages_marks_first_observation_unseen() {
        let mut seen = SeenMessages::with_capacity(4);
        assert!(!seen.observe("a"));
    }

    #[test]
    fn seen_messages_detects_replay() {
        let mut seen = SeenMessages::with_capacity(4);
        assert!(!seen.observe("a"));
        assert!(seen.observe("a"));
    }

    #[test]
    fn seen_messages_evicts_oldest_at_capacity() {
        let mut seen = SeenMessages::with_capacity(2);
        assert!(!seen.observe("a"));
        assert!(!seen.observe("b"));
        // "b" still in cache.
        assert!(seen.observe("b"));
        // "c" pushes "a" out.
        assert!(!seen.observe("c"));
        // "a" was evicted — observing again should report unseen.
        assert!(!seen.observe("a"));
    }

    #[test]
    fn check_message_age_accepts_message_with_no_timestamps() {
        assert!(check_message_age(&msg("id", None, None)).is_ok());
    }

    #[test]
    fn check_message_age_rejects_old_messages() {
        let now = unix_now();
        let too_old = now - MAX_MESSAGE_AGE_SECS - 60;
        assert!(check_message_age(&msg("id", Some(too_old), None)).is_err());
    }

    #[test]
    fn check_message_age_rejects_future_messages() {
        let now = unix_now();
        let too_future = now + MAX_FUTURE_SKEW_SECS + 60;
        assert!(check_message_age(&msg("id", Some(too_future), None)).is_err());
    }

    #[test]
    fn check_message_age_accepts_within_skew() {
        let now = unix_now();
        // 1 minute in the future is fine.
        assert!(check_message_age(&msg("id", Some(now + 60), None)).is_ok());
    }

    #[test]
    fn check_message_age_rejects_expired_messages() {
        let now = unix_now();
        // expires_time in the past
        assert!(check_message_age(&msg("id", Some(now), Some(now - 60))).is_err());
    }

    #[test]
    fn validate_did_accepts_well_formed_dids() {
        assert!(validate_did("did:web:example.com").is_ok());
        assert!(validate_did("did:webvh:abcdef0123:example.com").is_ok());
        assert!(validate_did("did:peer:2.Vz6Mk-something").is_ok());
        assert!(validate_did("did:key:z6MkpzExampleKey").is_ok());
        assert!(validate_did("did:web:example.com%3A8080:path").is_ok());
    }

    #[test]
    fn validate_did_rejects_old_prefix_loophole() {
        // The previous validator accepted these — current one must not.
        assert!(validate_did("did:").is_err());
        assert!(validate_did("did:abc").is_err()); // no msi
        assert!(validate_did("did::abc").is_err()); // empty method
        assert!(validate_did("not-a-did").is_err());
        assert!(validate_did("").is_err());
    }

    #[test]
    fn validate_did_rejects_uppercase_method() {
        assert!(validate_did("did:WEB:example.com").is_err());
    }

    #[test]
    fn validate_did_rejects_msi_with_invalid_chars() {
        assert!(validate_did("did:web:exam ple.com").is_err()); // space
        assert!(validate_did("did:web:exam\u{200E}ple.com").is_err()); // LRM
    }
}

/// Validate the message timestamps. Returns `Err(reason)` if the message
/// should be dropped as too old, expired, or implausibly future-dated.
fn check_message_age(message: &Message) -> Result<(), &'static str> {
    let now = unix_now();
    if let Some(created) = message.created_time {
        if created > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err("created_time too far in future");
        }
        if now.saturating_sub(created) > MAX_MESSAGE_AGE_SECS {
            return Err("created_time older than replay window");
        }
    }
    if let Some(expires) = message.expires_time
        && expires < now
    {
        return Err("message already expired");
    }
    Ok(())
}

/// Check that a new task can be created: no ID collision and under capacity limits.
/// Returns Ok(()) or logs a warning and returns Err(()).
fn check_task_capacity(
    config: &Config,
    task_id: &Arc<String>,
    from_did: &Arc<String>,
) -> Result<(), ()> {
    if config.private.tasks.get_by_id(task_id).is_some() {
        warn!(task_id = %task_id, from = %from_did, "rejecting duplicate task ID");
        return Err(());
    }
    if config.private.tasks.tasks.len() >= MAX_TASKS {
        warn!(
            "task limit reached ({}) — rejecting inbound message",
            MAX_TASKS
        );
        return Err(());
    }
    Ok(())
}

/// Process an inbound DIDComm message.
///
/// Auto-processes messages that don't need human input (pong, accept, finalize, reject).
/// Queues interactive tasks for messages that need user decisions (inbound requests, VRCs).
///
/// Returns `true` if Config was mutated and needs saving.
pub async fn process_inbound_message(
    config: &mut Config,
    _tdk: &TDK,
    service: &DIDCommService,
    seen: &mut SeenMessages,
    message: &Message,
) -> Result<bool, anyhow::Error> {
    // Drop messages outside the replay / freshness window before doing
    // any state-mutating work. Saves us from acting on stale captures
    // and from clock-skew–induced retries.
    if let Err(reason) = check_message_age(message) {
        warn!(
            id = %message.id,
            typ = %message.typ,
            from = ?message.from,
            "dropping inbound message: {reason}",
        );
        return Ok(false);
    }

    // Drop messages whose ID we've already seen this session. The TDK
    // already guards against unpack-level duplicates, but the LRU is a
    // belt-and-braces defense for mediator pickup retries and replay
    // attempts.
    if seen.observe(&message.id) {
        debug!(id = %message.id, typ = %message.typ, "dropping replayed message ID");
        return Ok(false);
    }

    // Validate sender — trust-pong messages may omit `from` (the thid
    // linkage to our outbound ping is sufficient for task cleanup).
    let from_did = match &message.from {
        Some(did) => Arc::new(did.to_string()),
        None => {
            // Allow pong through for task cleanup even without `from`
            if message.typ == openvtc_core::protocol_urls::TRUST_PONG {
                if let Some(task_id) = &message.thid {
                    config.private.tasks.remove(&Arc::new(task_id.to_string()));
                }
                debug!("trust-pong (no from) — task cleaned up");
                return Ok(true);
            }
            warn!("anonymous inbound message rejected (no 'from' field)");
            return Ok(false);
        }
    };

    // Validate message body size to prevent DoS via oversized payloads
    let body_size = serde_json::to_string(&message.body)
        .map(|s| s.len())
        .unwrap_or(0);
    if body_size > MAX_MESSAGE_BODY_SIZE {
        warn!(
            size = body_size,
            "rejecting oversized message body ({} bytes)", body_size
        );
        return Ok(false);
    }

    let msg_type = match MessageType::try_from(message) {
        Ok(t) => t,
        Err(_) => {
            warn!(typ = %message.typ, "unknown message type — ignoring");
            return Ok(false);
        }
    };

    let thid_display = message.thid.as_deref().unwrap_or("none");
    debug!(
        msg_type = %msg_type.friendly_name(),
        from = %from_did,
        thid = %thid_display,
        id = %message.id,
        "processing inbound message"
    );

    match msg_type {
        // =====================================================================
        // Auto-processed (no user interaction needed)
        // =====================================================================
        MessageType::RelationshipRequestRejected => {
            let task_id = require_thid(message)?;
            let body: RelationshipRejectBody = serde_json::from_value(message.body.clone())?;

            // Verify sender has a relationship with us
            if config.private.relationships.get(&from_did).is_none()
                && config
                    .private
                    .relationships
                    .find_by_remote_did(&from_did)
                    .is_none()
            {
                warn!(from = %from_did, "reject from unknown party — ignoring");
                return Ok(false);
            }

            // Extract listener ID before async work to avoid holding MutexGuard across await
            let listener_to_remove = if let Some(rel_arc) =
                config.private.relationships.find_by_task_id(&task_id)
                && let Ok(lock) = rel_arc.lock()
                && *lock.our_did != *config.public.persona_did
            {
                Some(super::didcomm::listener_id_for_did(
                    &lock.our_did,
                    &config.public.persona_did,
                ))
            } else {
                None
            };
            if let Some(lid) = listener_to_remove
                && let Err(e) = service.remove_listener(&lid).await
            {
                warn!(listener = %lid, error = %e, "failed to remove R-DID listener during rejection cleanup");
            }
            let _ = config.private.relationships.remove_by_task_id(
                &task_id,
                &mut config.private.vrcs_issued,
                &mut config.private.vrcs_received,
            );
            config.private.tasks.remove(&task_id);

            config.public.logs.insert(
                LogFamily::Relationship,
                format!(
                    "Relationship request rejected by ({}). Reason: {}",
                    from_did,
                    body.reason.as_deref().unwrap_or("none")
                ),
            );
            info!(from = %from_did, "relationship request rejected (auto-processed)");
            Ok(true)
        }

        MessageType::RelationshipRequestAccepted => {
            let task_id = require_thid(message)?;
            let body: RelationshipAcceptBody = serde_json::from_value(message.body.clone())?;

            if let Err(e) = validate_did(&body.did) {
                warn!(from = %from_did, error = %e, "rejecting accept with invalid DID in body");
                return Ok(false);
            }

            // All handshake messages use persona DIDs for from/to, so from_did
            // is the remote party's persona DID. Look up by task_id first, then
            // by persona DID. Validate sender matches the expected remote party.
            let relationship = config
                .private
                .relationships
                .find_by_task_id(&task_id)
                .or_else(|| config.private.relationships.get(&from_did));

            if let Some(rel) = relationship {
                let mut lock = rel
                    .lock()
                    .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;

                // Verify sender is the party we sent the request to
                if *lock.remote_p_did != *from_did {
                    warn!(
                        from = %from_did,
                        expected = %lock.remote_p_did,
                        "accept from unexpected party"
                    );
                    return Ok(false);
                }

                lock.state = RelationshipState::Established;
                lock.remote_did = Arc::new(body.did.clone());
            } else {
                warn!(from = %from_did, task_id = %task_id, "no relationship found for accept message");
                return Ok(false);
            }

            // Send finalize using persona DIDs (same as request and accept).
            // If the send fails, still persist the Established state.
            let finalize_msg =
                create_finalize_message(&config.public.persona_did, &from_did, &task_id)?;

            if let Err(e) = super::didcomm::send_message(
                service,
                config,
                &finalize_msg,
                &config.public.persona_did,
                &from_did,
            )
            .await
            {
                warn!(to = %from_did, error = %e, "failed to send finalize — relationship established locally");
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Relationship,
                format!("Relationship established with ({})", from_did),
            );
            info!(from = %from_did, "relationship accepted + finalize sent (auto-processed)");
            Ok(true)
        }

        MessageType::RelationshipRequestFinalize => {
            let task_id = require_thid(message)?;

            // All handshake messages use persona DIDs, so from_did is the
            // remote persona DID which is the relationship HashMap key.
            let found = config
                .private
                .relationships
                .find_by_task_id(&task_id)
                .or_else(|| config.private.relationships.get(&from_did));

            if let Some(relationship) = found {
                let mut lock = relationship
                    .lock()
                    .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;

                // Verify sender matches expected remote party
                if *lock.remote_p_did != *from_did {
                    warn!(
                        from = %from_did,
                        expected = %lock.remote_p_did,
                        "finalize from unexpected party"
                    );
                    return Ok(false);
                }

                lock.state = RelationshipState::Established;
            } else {
                warn!(from = %from_did, task_id = %task_id, "no relationship found for finalize message");
                return Ok(false);
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Relationship,
                format!("Relationship finalized with ({})", from_did),
            );
            info!(from = %from_did, "relationship finalized (auto-processed)");
            Ok(true)
        }

        MessageType::TrustPong => {
            if let Some(task_id) = &message.thid {
                config.private.tasks.remove(&Arc::new(task_id.to_string()));
            }
            debug!(from = %from_did, "trust-pong received (auto-processed)");
            Ok(true)
        }

        MessageType::VRCRequestRejected => {
            let task_id = require_thid(message)?;
            let body: VRCRequestReject = serde_json::from_value(message.body.clone())?;

            // Verify sender has a relationship with us
            if config.private.relationships.get(&from_did).is_none()
                && config
                    .private
                    .relationships
                    .find_by_remote_did(&from_did)
                    .is_none()
            {
                warn!(from = %from_did, "VRC reject from unknown party — ignoring");
                return Ok(false);
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Task,
                format!(
                    "VRC request rejected by ({}). Reason: {}",
                    from_did,
                    body.reason.as_deref().unwrap_or("none")
                ),
            );
            info!(from = %from_did, "VRC request rejected (auto-processed)");
            Ok(true)
        }

        // =====================================================================
        // Queued as tasks (need user interaction)
        // =====================================================================
        MessageType::RelationshipRequest => {
            let task_id = Arc::new(message.id.clone());
            let body: openvtc_core::relationships::RelationshipRequestBody =
                serde_json::from_value(message.body.clone())?;

            if let Err(e) = validate_did(&body.did) {
                warn!(from = %from_did, error = %e, "rejecting request with invalid DID in body");
                return Ok(false);
            }

            let to_did = Arc::new(
                message
                    .to
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
            );

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            if config.private.relationships.relationships.len() >= MAX_RELATIONSHIPS {
                warn!("relationship limit reached — rejecting request");
                return Ok(false);
            }

            // Reject if we already have a relationship with this sender
            if config.private.relationships.get(&from_did).is_some()
                || config
                    .private
                    .relationships
                    .find_by_remote_did(&from_did)
                    .is_some()
            {
                warn!(from = %from_did, "relationship request from existing relationship — ignoring");
                return Ok(false);
            }

            // Reject if a pending inbound request from this sender already exists
            let has_pending = config.private.tasks.tasks.values().any(|t| {
                t.lock()
                    .map(|task| {
                        matches!(&task.type_, TaskType::RelationshipRequestInbound { from, .. } if *from == from_did)
                    })
                    .unwrap_or(false)
            });
            if has_pending {
                warn!(from = %from_did, "duplicate pending relationship request — ignoring");
                return Ok(false);
            }

            config.private.tasks.new_task(
                &task_id,
                TaskType::RelationshipRequestInbound {
                    from: from_did.clone(),
                    to: to_did,
                    request: body,
                },
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("Inbound relationship request from ({})", from_did),
            );
            info!(from = %from_did, "relationship request queued in inbox");
            Ok(true)
        }

        MessageType::VRCRequest => {
            let task_id = Arc::new(message.id.clone());
            let body = serde_json::from_value(message.body.clone())?;

            let relationship = config
                .private
                .relationships
                .find_by_remote_did(&from_did)
                .ok_or_else(|| {
                    anyhow::anyhow!("VRC request from ({}) but no relationship found", from_did)
                })?;

            // Only accept VRC requests from established relationships
            {
                let lock = relationship
                    .lock()
                    .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
                if lock.state != RelationshipState::Established {
                    warn!(from = %from_did, state = ?lock.state, "VRC request from non-established relationship");
                    return Ok(false);
                }
            }

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task(
                &task_id,
                TaskType::VRCRequestInbound {
                    request: body,
                    relationship,
                },
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("Inbound VRC request from ({})", from_did),
            );
            info!(from = %from_did, "VRC request queued in inbox");
            Ok(true)
        }

        MessageType::VRCIssued => {
            let vrc: dtg_credentials::DTGCredential = serde_json::from_value(message.body.clone())?;
            let task_id = Arc::new(message.thid.clone().unwrap_or_else(|| message.id.clone()));

            // Remove the outbound VRC request task that this issued VRC responds to.
            // The thid links the issued VRC back to the original request.
            config.private.tasks.remove(&task_id);

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config
                .private
                .tasks
                .new_task(&task_id, TaskType::VRCIssued { vrc: Box::new(vrc) });

            config.public.logs.insert(
                LogFamily::Task,
                format!("VRC issued received from ({})", from_did),
            );
            info!(from = %from_did, "VRC issued queued in inbox");
            Ok(true)
        }

        MessageType::TrustPing => {
            // Trust pings are already auto-responded to in the messaging loop.
            // Just create an informational task so the user sees it.
            let task_id = Arc::new(message.id.clone());
            let to_did = Arc::new(
                message
                    .to
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
            );

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            // Find the relationship for this ping
            if let Some(relationship) = config.private.relationships.find_by_remote_did(&from_did) {
                config.private.tasks.new_task(
                    &task_id,
                    TaskType::TrustPing {
                        from: from_did.clone(),
                        to: to_did,
                        relationship,
                    },
                );
            }
            debug!(from = %from_did, "trust-ping task created");
            Ok(true)
        }

        _ => {
            warn!(msg_type = %message.typ, "unhandled message type");
            Ok(false)
        }
    }
}

/// Extract the thread ID (`thid`) from a message, returning an error if missing.
fn require_thid(message: &Message) -> Result<Arc<String>, anyhow::Error> {
    message
        .thid
        .as_ref()
        .map(|s| Arc::new(s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("message missing required 'thid' header"))
}

/// Validate that a string conforms to the DID Core 1.0 syntax.
///
///   did = "did:" method-name ":" method-specific-id
///   method-name = 1*( %x61-7A / DIGIT )
///   method-specific-id = *( *idchar ":" ) 1*idchar
///   idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
///
/// The previous version was a `did:` prefix check, which let through
/// strings like `did:` followed by anything — including newlines and
/// zero-width characters that downstream code treated as routing
/// identities. We don't ship the full DID resolver here, but a strict
/// syntactic gate is cheap insurance against malformed payloads.
fn validate_did(did: &str) -> Result<(), anyhow::Error> {
    let bail = || -> anyhow::Error {
        anyhow::anyhow!("invalid DID format: '{}'", &did[..did.len().min(64)])
    };

    let rest = did.strip_prefix("did:").ok_or_else(bail)?;
    let (method, msi) = rest.split_once(':').ok_or_else(bail)?;
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(bail());
    }
    if msi.is_empty() {
        return Err(bail());
    }
    // method-specific-id segments separated by `:`; each segment must
    // contain only idchar (ALPHA / DIGIT / "." / "-" / "_") or
    // pct-encoded triplets, and the final segment must be non-empty.
    let mut segments = msi.split(':');
    let last_segment_nonempty = msi.split(':').next_back().is_some_and(|s| !s.is_empty());
    if !last_segment_nonempty {
        return Err(bail());
    }
    if !segments.all(|seg| seg.chars().all(is_did_msi_char)) {
        return Err(bail());
    }
    Ok(())
}

/// Returns true for any character allowed in a DID method-specific-id.
/// Pct-encoded triplets (`%XX`) are accepted as `%`+hex+hex sequences,
/// validated character-by-character — a bad sequence shows up as a `%`
/// followed by a non-hex char and gets rejected at the boundary check.
fn is_did_msi_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | '%')
}

/// Build a DIDComm finalize message for relationship establishment.
fn create_finalize_message(
    from: &str,
    to: &str,
    task_id: &Arc<String>,
) -> Result<Message, anyhow::Error> {
    super::didcomm::build_didcomm_message(
        openvtc_core::protocol_urls::RELATIONSHIP_REQUEST_FINALIZE,
        json!({}),
        from,
        to,
        Some(task_id.as_str()),
    )
}
