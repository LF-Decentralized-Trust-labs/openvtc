//! Inbound DIDComm message dispatch for the TUI.
//!
//! This is the TUI equivalent of `openvtc-cli/src/tasks/fetch.rs`.
//! Messages that don't need human input are auto-processed.
//! Messages requiring user decisions are queued as tasks in the inbox.

use std::sync::Arc;

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::{TDK, didcomm::Message};
use openvtc::{
    MessageType,
    config::Config,
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody, RelationshipState},
    tasks::TaskType,
    vrc::VRCRequestReject,
};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Maximum allowed message body size in bytes (1 MB).
const MAX_MESSAGE_BODY_SIZE: usize = 1_048_576;

/// Maximum number of tasks allowed before rejecting new inbound messages.
const MAX_TASKS: usize = 10_000;

/// Maximum number of relationships allowed before rejecting new requests.
const MAX_RELATIONSHIPS: usize = 5_000;

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
    message: &Message,
) -> Result<bool, anyhow::Error> {
    // Validate sender
    let from_did = match &message.from {
        Some(did) => Arc::new(did.to_string()),
        None => {
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

            // Clean up R-DID listener if present, then remove relationship and task
            if let Some(rel) = config.private.relationships.find_by_task_id(&task_id) {
                if let Ok(lock) = rel.lock() {
                    if *lock.our_did != *config.public.persona_did {
                        let lid = super::didcomm::listener_id_for_did(
                            &lock.our_did,
                            &config.public.persona_did,
                        );
                        if let Err(e) = service.remove_listener(&lid).await {
                            warn!(listener = %lid, error = %e, "failed to remove R-DID listener during rejection cleanup");
                        }
                    }
                }
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

            // Look up relationship by task_id (thid) — the remote party may respond
            // from an R-DID different from their persona DID, so we can't match by from_did.
            let our_did = if let Some(relationship) =
                config.private.relationships.find_by_task_id(&task_id)
            {
                let mut lock = relationship
                    .lock()
                    .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;

                // Verify the accept comes from the party we sent the request to.
                // The sender may use an R-DID, so check both persona and remote DIDs.
                if *lock.remote_p_did != *from_did && *lock.remote_did != *from_did {
                    warn!(
                        from = %from_did,
                        expected = %lock.remote_p_did,
                        "accept from unexpected party — possible spoofing"
                    );
                    return Ok(false);
                }

                lock.state = RelationshipState::Established;
                if lock.remote_did.as_str() != body.did {
                    lock.remote_did = Arc::new(body.did.clone());
                }
                lock.our_did.to_string()
            } else if let Some(relationship) = config.private.relationships.get(&from_did) {
                // Fallback: try matching by from_did (persona DID case)
                let mut lock = relationship
                    .lock()
                    .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
                lock.state = RelationshipState::Established;
                if lock.remote_did.as_str() != body.did {
                    lock.remote_did = Arc::new(body.did.clone());
                }
                lock.our_did.to_string()
            } else {
                warn!(from = %from_did, task_id = %task_id, "no relationship found for accept message");
                return Ok(false);
            };

            // Send finalize message using our relationship DID (R-DID if available).
            // If the send fails, still persist the Established state — the relationship
            // is usable on our side and the remote party will eventually time out or retry.
            let finalize_msg = create_finalize_message(&our_did, &from_did, &task_id)?;

            if let Err(e) =
                super::didcomm::send_message(service, config, &finalize_msg, &our_did, &from_did)
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

            // Look up by task_id first (handles R-DID case), fall back to from_did
            let found = config
                .private
                .relationships
                .find_by_task_id(&task_id)
                .or_else(|| config.private.relationships.find_by_remote_did(&from_did));

            if let Some(relationship) = found {
                let mut lock = relationship
                    .lock()
                    .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
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
            let body: openvtc::relationships::RelationshipRequestBody =
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

            // Prevent task ID collision/hijacking
            if config.private.tasks.get_by_id(&task_id).is_some() {
                warn!(task_id = %task_id, from = %from_did, "rejecting duplicate task ID");
                return Ok(false);
            }

            if config.private.tasks.tasks.len() >= MAX_TASKS {
                warn!(
                    "task limit reached ({}) — rejecting inbound message",
                    MAX_TASKS
                );
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

            // Prevent task ID collision/hijacking
            if config.private.tasks.get_by_id(&task_id).is_some() {
                warn!(task_id = %task_id, from = %from_did, "rejecting duplicate task ID");
                return Ok(false);
            }

            if config.private.tasks.tasks.len() >= MAX_TASKS {
                warn!(
                    "task limit reached ({}) — rejecting inbound message",
                    MAX_TASKS
                );
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

            // Prevent task ID collision/hijacking
            if config.private.tasks.get_by_id(&task_id).is_some() {
                warn!(task_id = %task_id, from = %from_did, "rejecting duplicate task ID");
                return Ok(false);
            }

            if config.private.tasks.tasks.len() >= MAX_TASKS {
                warn!(
                    "task limit reached ({}) — rejecting inbound message",
                    MAX_TASKS
                );
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

            // Prevent task ID collision/hijacking
            if config.private.tasks.get_by_id(&task_id).is_some() {
                warn!(task_id = %task_id, from = %from_did, "rejecting duplicate task ID");
                return Ok(false);
            }

            if config.private.tasks.tasks.len() >= MAX_TASKS {
                warn!(
                    "task limit reached ({}) — rejecting inbound message",
                    MAX_TASKS
                );
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

/// Basic validation that a string looks like a DID.
fn validate_did(did: &str) -> Result<(), anyhow::Error> {
    if !did.starts_with("did:") || did.len() < 8 {
        anyhow::bail!("invalid DID format: '{}'", &did[..did.len().min(32)]);
    }
    Ok(())
}

/// Build a DIDComm finalize message for relationship establishment.
fn create_finalize_message(
    from: &str,
    to: &str,
    task_id: &Arc<String>,
) -> Result<Message, anyhow::Error> {
    use std::time::SystemTime;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let message = Message::build(
        Uuid::new_v4().to_string(),
        openvtc::protocol_urls::RELATIONSHIP_REQUEST_FINALIZE.to_string(),
        json!({}),
    )
    .from(from.to_string())
    .to(to.to_string())
    .thid(task_id.to_string())
    .created_time(now)
    .expires_time(now + 60 * 60 * 48)
    .finalize();

    Ok(message)
}
