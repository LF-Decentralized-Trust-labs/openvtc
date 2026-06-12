//! Inbound DIDComm message dispatch for the TUI.
//!
//! Messages that don't need human input are auto-processed.
//! Messages requiring user decisions are queued as tasks in the inbox.
//!
//! The pure protocol logic (validators, the join-receipt / credential-issue
//! handlers, the VRC vetting + proof verification, and the replay guard) lives
//! in [`openvtc_core::messaging`] so it is testable without the TUI crate. This
//! module keeps only the async I/O orchestrator [`process_inbound_message`],
//! which imports and calls into core.

use std::sync::Arc;

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::{TDK, didcomm::Message};
use dtg_credentials::DTGCredential;
use openvtc_core::messaging::{
    SeenMessages, check_message_age, check_task_capacity, create_finalize_message,
    handle_credential_issue, handle_join_submit_receipt, require_thid, validate_did,
    verify_vrc_proof, vet_vrc_issued,
};
use openvtc_core::{
    MessageType,
    config::Config,
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody, RelationshipState},
    tasks::TaskType,
    vrc::VRCRequestReject,
};
use tracing::{debug, info, warn};
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RECEIPT_TYPE;

/// Maximum allowed message body size in bytes (1 MB).
const MAX_MESSAGE_BODY_SIZE: usize = 1_048_576;

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
    tdk: &TDK,
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

    // The persona this message was addressed to — the DID any auto-reply must be
    // sent *from*. Resolved from the envelope's `to`, falling back to the active
    // persona when `to` is absent or not one of ours. For a single-persona
    // account `to` is always that persona, so this is identical to the previous
    // `config.persona_did()` behaviour; with multiple personas it routes the
    // reply out of the right one.
    let recipient_did: String = message
        .to
        .as_ref()
        .and_then(|tos| tos.iter().find(|t| config.is_persona_did(t)))
        .cloned()
        .unwrap_or_else(|| config.persona_did().to_string());

    // The persona this message was addressed to, for D10 attribution: inbox
    // tasks created from this message are tagged with it so they scope to the
    // right community on the main page (R-C-6).
    let recipient_persona = config.account.persona_id_for_did(&recipient_did);

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

    // VTC join-requests submit-receipt: the VTC's asynchronous reply to our
    // submit, threaded (`thid`) on our submit message id. It carries the
    // authoritative VTC `requestId`; reconcile it onto the matching Pending
    // community record (which holds our submit message id as a placeholder).
    // It is a VTC Trust-Task type, not an openvtc relationship-protocol type,
    // so handle it before the `MessageType` conversion below (which rejects it).
    if message.typ == JOIN_REQUEST_SUBMIT_RECEIPT_TYPE {
        return Ok(handle_join_submit_receipt(
            &mut config.account,
            message,
            &from_did,
        ));
    }

    // VTC credential delivery: on approve, the VTC pushes the issued VMC + role
    // VEC as separate `credential-exchange/issue` messages. Store each on the
    // community and flip Pending -> Active when the membership credential lands.
    if message.typ == CREDENTIAL_ISSUE_TYPE {
        return Ok(handle_credential_issue(
            &mut config.account,
            message,
            &from_did,
        ));
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

            // Extract the listener's local DID before async work + before any
            // mutation, so the `&Relationship` borrow ends here.
            let our_did = config
                .private
                .relationships
                .find_by_task_id(&task_id)
                .map(|rel| Arc::clone(&rel.our_did))
                .filter(|our_did| !config.is_persona_did(our_did.as_str()));
            let listener_to_remove =
                our_did.map(|our_did| super::didcomm::listener_id_for_did(&our_did, config));
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
            //
            // R20: with plain values we cannot hold a `&mut` across the finalize
            // `.await` below, so resolve the map key, mutate via `get_mut` (the
            // borrow ends immediately), then await. The mutation happens before
            // the await — no re-look-up is needed.
            let key = config
                .private
                .relationships
                .find_key_by_task_id(&task_id)
                .or_else(|| {
                    config
                        .private
                        .relationships
                        .get(&from_did)
                        .map(|_| Arc::clone(&from_did))
                });

            if let Some(key) = key {
                let rel = config
                    .private
                    .relationships
                    .get_mut(&key)
                    .expect("key just resolved");

                // Verify sender is the party we sent the request to
                if *rel.remote_p_did != *from_did {
                    warn!(
                        from = %from_did,
                        expected = %rel.remote_p_did,
                        "accept from unexpected party"
                    );
                    return Ok(false);
                }

                rel.state = RelationshipState::Established;
                rel.remote_did = Arc::new(body.did.clone());
            } else {
                warn!(from = %from_did, task_id = %task_id, "no relationship found for accept message");
                return Ok(false);
            }

            // Send finalize using persona DIDs (same as request and accept).
            // If the send fails, still persist the Established state.
            let finalize_msg = create_finalize_message(&recipient_did, &from_did, &task_id)?;

            if let Err(e) = super::didcomm::send_message(
                service,
                config,
                &finalize_msg,
                &recipient_did,
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
            let key = config
                .private
                .relationships
                .find_key_by_task_id(&task_id)
                .or_else(|| {
                    config
                        .private
                        .relationships
                        .get(&from_did)
                        .map(|_| Arc::clone(&from_did))
                });

            if let Some(key) = key {
                let rel = config
                    .private
                    .relationships
                    .get_mut(&key)
                    .expect("key just resolved");

                // Verify sender matches expected remote party
                if *rel.remote_p_did != *from_did {
                    warn!(
                        from = %from_did,
                        expected = %rel.remote_p_did,
                        "finalize from unexpected party"
                    );
                    return Ok(false);
                }

                rel.state = RelationshipState::Established;
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
            let has_pending = config.private.tasks.tasks.values().any(|task| {
                matches!(&task.type_, TaskType::RelationshipRequestInbound { from, .. } if *from == from_did)
            });
            if has_pending {
                warn!(from = %from_did, "duplicate pending relationship request — ignoring");
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::RelationshipRequestInbound {
                    from: from_did.clone(),
                    to: to_did,
                    request: body,
                },
                recipient_persona,
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
            if relationship.state != RelationshipState::Established {
                warn!(from = %from_did, state = ?relationship.state, "VRC request from non-established relationship");
                return Ok(false);
            }
            let remote_p_did = Arc::clone(&relationship.remote_p_did);

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::VRCRequestInbound {
                    request: body,
                    remote_p_did,
                },
                recipient_persona,
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("Inbound VRC request from ({})", from_did),
            );
            info!(from = %from_did, "VRC request queued in inbox");
            Ok(true)
        }

        MessageType::VRCIssued => {
            let vrc: DTGCredential = serde_json::from_value(message.body.clone())?;

            // Task R2 hardening: require an established relationship, bind the
            // credential's issuer to the authenticated sender, and only let the
            // thid resolve our own pending outbound VRC request to that sender.
            let pending_request = match vet_vrc_issued(
                &config.private.relationships,
                &config.private.tasks,
                &vrc,
                &from_did,
                message.thid.as_deref(),
            ) {
                Ok(pending) => pending,
                Err(reason) => {
                    warn!(from = %from_did, issuer = %vrc.issuer(), "dropping VRC-issued message: {reason}");
                    return Ok(false);
                }
            };

            // Task R2 gate 4: the data-integrity proof must verify against the
            // issuer's resolved key before any state is touched.
            if let Err(reason) = verify_vrc_proof(tdk, &vrc).await {
                warn!(from = %from_did, issuer = %vrc.issuer(), "dropping VRC-issued message: {reason}");
                return Ok(false);
            }

            // Only a verified response may resolve our pending outbound VRC
            // request; the inbox task reuses its id so the request is replaced
            // by the issued credential. Unsolicited (or unmatched-thid) VRCs
            // are queued under the message id and leave other tasks untouched.
            let task_id = pending_request
                .clone()
                .unwrap_or_else(|| Arc::new(message.id.clone()));
            if let Some(request_id) = &pending_request {
                config.private.tasks.remove(request_id);
            }

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::VRCIssued { vrc: Box::new(vrc) },
                recipient_persona,
            );

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
            if let Some(remote_p_did) = config
                .private
                .relationships
                .find_by_remote_did(&from_did)
                .map(|rel| Arc::clone(&rel.remote_p_did))
            {
                config.private.tasks.new_task_for(
                    &task_id,
                    TaskType::TrustPing {
                        from: from_did.clone(),
                        to: to_did,
                        remote_p_did,
                    },
                    recipient_persona,
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
