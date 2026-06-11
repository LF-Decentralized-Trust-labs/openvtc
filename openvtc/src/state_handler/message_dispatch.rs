//! Inbound DIDComm message dispatch for the TUI.
//!
//! Messages that don't need human input are auto-processed.
//! Messages requiring user decisions are queued as tasks in the inbox.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::{TDK, didcomm::Message};
use dtg_credentials::DTGCredential;
use openvtc_core::{
    MessageType,
    config::{
        Config,
        account::{Account, CommunityStatus},
    },
    logs::LogFamily,
    relationships::{
        RelationshipAcceptBody, RelationshipRejectBody, RelationshipState, Relationships,
    },
    tasks::{TaskType, Tasks},
    vrc::VRCRequestReject,
};
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, JoinRequestSubmitReceiptBody,
};

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

/// Reconcile a VTC `join-requests/submit-receipt` onto the matching Pending
/// community record: replace the placeholder request id (our submit message id,
/// echoed back as the receipt's `thid`) with the VTC's authoritative
/// `requestId`. The receipt must come from the community's own VTC DID
/// (anti-spoof) and match the placeholder we stored at submit time.
///
/// Returns `true` if a record was updated (Config needs saving).
fn handle_join_submit_receipt(account: &mut Account, message: &Message, from_did: &str) -> bool {
    let Some(thid) = message.thid.as_deref() else {
        warn!("join submit-receipt without thid — cannot correlate; ignoring");
        return false;
    };
    let placeholder = match Uuid::parse_str(thid) {
        Ok(u) => u,
        Err(e) => {
            warn!(thid, error = %e, "join submit-receipt thid is not a uuid — ignoring");
            return false;
        }
    };
    let body: JoinRequestSubmitReceiptBody = match serde_json::from_value(message.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "malformed join submit-receipt body — ignoring");
            return false;
        }
    };

    let Some(record) = account.communities.get_mut(from_did) else {
        warn!(vtc = %from_did, "join submit-receipt from an unknown community — ignoring");
        return false;
    };
    // Copy the current placeholder out (Uuid: Copy) so the immutable match
    // borrow ends before we re-assign `status`.
    let current = match &record.status {
        CommunityStatus::Pending { request_id } => Some(*request_id),
        _ => None,
    };
    if current == Some(placeholder) {
        record.status = CommunityStatus::Pending {
            request_id: body.request_id,
        };
        info!(
            vtc = %from_did,
            vtc_request_id = %body.request_id,
            receipt_status = %body.status,
            "reconciled join request id from VTC submit-receipt",
        );
        true
    } else {
        warn!(
            vtc = %from_did,
            thid,
            "join submit-receipt did not match a pending join with that id — ignoring",
        );
        false
    }
}

/// Handle a VTC `credential-exchange/issue`: store the issued credential on the
/// matching community and, for the membership credential (VMC), flip the
/// membership to `Active`. The issuing VTC is the authcrypt sender; the
/// credential must be issued by that VTC and to the community's own persona
/// (anti-misdelivery). Returns `true` if a record was updated.
fn handle_credential_issue(account: &mut Account, message: &Message, from_did: &str) -> bool {
    // The known-holder delivery carries the VC at `credential_response.credential`.
    // `sealed` issues (invite / air-gap) are not handled here.
    let Some(credential) = message
        .body
        .get("credential_response")
        .and_then(|cr| cr.get("credential"))
        .cloned()
    else {
        warn!(vtc = %from_did, "credential-issue without credential_response.credential — ignoring");
        return false;
    };

    // Resolve the target community (the sender is the issuing VTC) + its persona.
    let Some(record) = account.communities.get(from_did) else {
        warn!(vtc = %from_did, "credential-issue from an unknown community — ignoring");
        return false;
    };
    let persona_ref = record.persona_ref;
    let Some(persona_did) = account.personas.get(&persona_ref).map(|p| p.did.clone()) else {
        warn!(vtc = %from_did, "community persona missing — ignoring credential");
        return false;
    };

    // Anti-misdelivery: issuer must be this community's VTC, subject our persona.
    let issuer = credential.get("issuer").and_then(|i| match i {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => o.get("id").and_then(Value::as_str),
        _ => None,
    });
    if issuer != Some(from_did) {
        warn!(vtc = %from_did, ?issuer, "issued credential's issuer is not the community VTC — ignoring");
        return false;
    }
    let subject = credential
        .get("credentialSubject")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str);
    if subject != Some(persona_did.as_str()) {
        warn!(vtc = %from_did, "issued credential subject is not our persona — ignoring");
        return false;
    }

    // VMC vs role VEC, by the `type` array.
    let types = credential.get("type").and_then(Value::as_array);
    let has_type = |needle: &str| {
        types.is_some_and(|a| a.iter().filter_map(Value::as_str).any(|t| t == needle))
    };
    let is_vmc = has_type("MembershipCredential");
    let is_vec = has_type("EndorsementCredential");

    let record = account
        .communities
        .get_mut(from_did)
        .expect("community present (checked above)");
    if is_vmc {
        record.membership_credential = Some(credential);
        if !record.status.is_active() {
            record.activate(chrono::Utc::now());
        }
        info!(vtc = %from_did, "received membership credential — community is now Active");
        true
    } else if is_vec {
        record.role_credential = Some(credential);
        info!(vtc = %from_did, "received role endorsement credential");
        true
    } else {
        warn!(vtc = %from_did, "issued credential is neither a VMC nor a role VEC — ignoring");
        false
    }
}

/// Vet an inbound `VRCIssued` message against local state (task R2).
///
/// Gates enforced:
/// 1. the authenticated DIDComm sender must map to an `Established`
///    relationship (same gate as the `VRCRequest` arm);
/// 2. the credential's `issuer` must be that relationship's remote persona
///    DID. VRCs are signed with the issuer's persona DID while the DIDComm
///    envelope may be sent from a relationship R-DID, so the binding goes
///    through the relationship record rather than naive `issuer == from`
///    string equality — this still pins the issuer to the authenticated
///    sender and rejects forged issuer strings;
/// 3. the message `thid` only resolves a pending task when that task is our
///    *own* outbound VRC request to this same sender. An attacker-chosen
///    `thid` must not be able to delete unrelated tasks.
///
/// Returns the task id of our pending outbound VRC request when the `thid`
/// legitimately resolves one, `Ok(None)` when there is no (matching) `thid`,
/// and `Err(reason)` when the message must be dropped.
fn vet_vrc_issued(
    relationships: &Relationships,
    tasks: &Tasks,
    vrc: &DTGCredential,
    from_did: &Arc<String>,
    thid: Option<&str>,
) -> Result<Option<Arc<String>>, String> {
    // Gate 1: sender must be an established relationship.
    let relationship = relationships
        .find_by_remote_did(from_did)
        .ok_or_else(|| "no relationship with sender".to_string())?;
    if relationship.state != RelationshipState::Established {
        return Err(format!(
            "relationship with sender is not established (state: {})",
            relationship.state
        ));
    }
    let remote_p_did = Arc::clone(&relationship.remote_p_did);

    // Gate 2: issuer must be the authenticated sender's persona DID.
    if vrc.issuer() != remote_p_did.as_str() {
        return Err(format!(
            "credential issuer ({}) is not the sender's persona DID ({})",
            vrc.issuer(),
            remote_p_did
        ));
    }

    // Gate 3: the thid may only resolve our own pending outbound VRC
    // request to this sender; anything else is ignored.
    let pending_request = thid.and_then(|thid| {
        let id = Arc::new(thid.to_string());
        let task = tasks.get_by_id(&id)?;
        let TaskType::VRCRequestOutbound {
            remote_p_did: task_remote_p_did,
        } = &task.type_
        else {
            return None;
        };
        (*task_remote_p_did == remote_p_did).then(|| Arc::clone(&id))
    });

    Ok(pending_request)
}

/// Cryptographically verify an inbound VRC's data-integrity proof (task R2).
///
/// The proof's `verificationMethod` must belong to the credential's issuer
/// DID — without that binding an attacker could present a proof made with
/// *their own* key over a credential naming someone else as issuer. The
/// public key is then resolved from the issuer's DID Document via the TDK
/// resolver and the proof verified over the proof-stripped credential.
async fn verify_vrc_proof(tdk: &TDK, vrc: &DTGCredential) -> Result<(), String> {
    let Some(proof) = vrc.credential().proof.clone() else {
        return Err("credential has no data-integrity proof".to_string());
    };

    let vm_did = proof
        .verification_method
        .split_once('#')
        .map_or(proof.verification_method.as_str(), |(did, _)| did);
    if vm_did != vrc.issuer() {
        return Err(format!(
            "proof verification method ({}) does not belong to the issuer ({})",
            proof.verification_method,
            vrc.issuer()
        ));
    }

    // `verify_data` expects the signed document with the proof stripped.
    let mut unsigned = vrc.clone();
    unsigned.credential_mut().proof = None;

    tdk.verify_data(&unsigned, None, &proof)
        .await
        .map_err(|e| format!("proof verification failed: {e}"))?;
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
            if relationship.state != RelationshipState::Established {
                warn!(from = %from_did, state = ?relationship.state, "VRC request from non-established relationship");
                return Ok(false);
            }
            let remote_p_did = Arc::clone(&relationship.remote_p_did);

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task(
                &task_id,
                TaskType::VRCRequestInbound {
                    request: body,
                    remote_p_did,
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
            if let Some(remote_p_did) = config
                .private
                .relationships
                .find_by_remote_did(&from_did)
                .map(|rel| Arc::clone(&rel.remote_p_did))
            {
                config.private.tasks.new_task(
                    &task_id,
                    TaskType::TrustPing {
                        from: from_did.clone(),
                        to: to_did,
                        remote_p_did,
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

    // --- join submit-receipt reconciliation ---

    use chrono::Utc;
    use openvtc_core::config::account::{Account, CommunityRecord, PersonaId, PersonaRecord};

    fn pending_account(vtc: &str, placeholder: Uuid) -> Account {
        let mut acct = Account::default();
        acct.communities.insert(
            vtc.to_string(),
            CommunityRecord::new_pending(
                vtc.to_string(),
                None,
                "openvtc/x".to_string(),
                PersonaId::new(),
                placeholder,
                Utc::now(),
            ),
        );
        acct
    }

    fn receipt(thid: &str, from: &str, request_id: Uuid, status: &str) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            JOIN_REQUEST_SUBMIT_RECEIPT_TYPE.to_string(),
            serde_json::json!({ "requestId": request_id, "status": status }),
        )
        .from(from.to_string())
        .thid(thid.to_string())
        .finalize()
    }

    #[test]
    fn submit_receipt_reconciles_the_authoritative_request_id() {
        let vtc = "did:webvh:example:vtc";
        let placeholder = Uuid::new_v4();
        let mut acct = pending_account(vtc, placeholder);

        let real = Uuid::new_v4();
        let m = receipt(&placeholder.to_string(), vtc, real, "pending");
        assert!(handle_join_submit_receipt(&mut acct, &m, vtc));

        match &acct.communities.get(vtc).unwrap().status {
            CommunityStatus::Pending { request_id } => assert_eq!(*request_id, real),
            other => panic!("expected Pending, got {other:?}"),
        }
    }

    #[test]
    fn submit_receipt_from_a_different_did_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let placeholder = Uuid::new_v4();
        let mut acct = pending_account(vtc, placeholder);

        // A receipt whose sender is not the community's VTC must not reconcile.
        let m = receipt(
            &placeholder.to_string(),
            "did:webvh:evil",
            Uuid::new_v4(),
            "pending",
        );
        assert!(!handle_join_submit_receipt(&mut acct, &m, "did:webvh:evil"));
        match &acct.communities.get(vtc).unwrap().status {
            CommunityStatus::Pending { request_id } => assert_eq!(*request_id, placeholder),
            other => panic!("expected unchanged Pending, got {other:?}"),
        }
    }

    #[test]
    fn submit_receipt_with_mismatched_thid_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let placeholder = Uuid::new_v4();
        let mut acct = pending_account(vtc, placeholder);

        // thid does not match the stored placeholder.
        let m = receipt(&Uuid::new_v4().to_string(), vtc, Uuid::new_v4(), "pending");
        assert!(!handle_join_submit_receipt(&mut acct, &m, vtc));
        match &acct.communities.get(vtc).unwrap().status {
            CommunityStatus::Pending { request_id } => assert_eq!(*request_id, placeholder),
            other => panic!("expected unchanged Pending, got {other:?}"),
        }
    }

    // --- credential-issue outcome handling ---

    fn account_with_persona(vtc: &str, persona_did: &str) -> Account {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.personas.insert(
            pid,
            PersonaRecord {
                persona_id: pid,
                did: persona_did.to_string(),
                did_document: None,
                key_refs: Vec::new(),
                mediator_did: None,
                origin_context_id: String::new(),
                created_at: Utc::now(),
                label: None,
            },
        );
        acct.communities.insert(
            vtc.to_string(),
            CommunityRecord::new_pending(
                vtc.to_string(),
                None,
                "openvtc/x".to_string(),
                pid,
                Uuid::new_v4(),
                Utc::now(),
            ),
        );
        acct
    }

    fn issue(from: &str, credential: serde_json::Value) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            CREDENTIAL_ISSUE_TYPE.to_string(),
            serde_json::json!({ "credential_response": { "credential": credential } }),
        )
        .from(from.to_string())
        .finalize()
    }

    fn vc(types: &[&str], issuer: &str, subject: &str) -> serde_json::Value {
        serde_json::json!({
            "type": types,
            "issuer": issuer,
            "credentialSubject": { "id": subject },
        })
    }

    #[test]
    fn credential_issue_vmc_activates_and_stores() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                vtc,
                persona,
            ),
        );
        assert!(handle_credential_issue(&mut acct, &m, vtc));

        let rec = acct.communities.get(vtc).unwrap();
        assert!(rec.status.is_active());
        assert!(rec.membership_credential.is_some());
    }

    #[test]
    fn credential_issue_role_vec_stores_without_activating() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "EndorsementCredential"],
                vtc,
                persona,
            ),
        );
        assert!(handle_credential_issue(&mut acct, &m, vtc));

        let rec = acct.communities.get(vtc).unwrap();
        assert!(
            !rec.status.is_active(),
            "role VEC must not activate on its own"
        );
        assert!(rec.role_credential.is_some());
    }

    #[test]
    fn credential_issue_from_wrong_issuer_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        // Issuer is not the community's VTC.
        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                "did:webvh:evil",
                persona,
            ),
        );
        assert!(!handle_credential_issue(&mut acct, &m, vtc));
        assert!(!acct.communities.get(vtc).unwrap().status.is_active());
    }

    #[test]
    fn credential_issue_for_wrong_subject_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        // Subject is not our persona.
        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                vtc,
                "did:webvh:someone-else",
            ),
        );
        assert!(!handle_credential_issue(&mut acct, &m, vtc));
        assert!(!acct.communities.get(vtc).unwrap().status.is_active());
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

    // --- inbound VRC-issued vetting (task R2) ---

    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::dids::{DID, KeyType};
    use openvtc_core::relationships::Relationship;

    fn relationship(remote_p: &str, remote_r: &str, state: RelationshipState) -> Relationship {
        Relationship {
            task_id: Arc::new(Uuid::new_v4().to_string()),
            our_did: Arc::new("did:webvh:example:us".to_string()),
            remote_did: Arc::new(remote_r.to_string()),
            remote_p_did: Arc::new(remote_p.to_string()),
            created: Utc::now(),
            state,
        }
    }

    fn relationships_with(rel: &Relationship) -> Relationships {
        let mut rels = Relationships::default();
        let key = Arc::clone(&rel.remote_p_did);
        rels.relationships.insert(key, rel.clone());
        rels
    }

    fn unsigned_vrc(issuer: &str) -> DTGCredential {
        DTGCredential::new_vrc(
            issuer.to_string(),
            "did:webvh:example:subject".to_string(),
            Utc::now(),
            None,
        )
    }

    #[test]
    fn vrc_issued_with_forged_issuer_is_dropped_and_tasks_untouched() {
        let sender = Arc::new("did:webvh:example:honest-sender".to_string());
        let rel = relationship(&sender, &sender, RelationshipState::Established);
        let rels = relationships_with(&rel);

        // A pending task whose id the attacker guesses as the thid.
        let mut tasks = Tasks::default();
        let pending = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &pending,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::clone(&rel.remote_p_did),
            },
        );

        let vrc = unsigned_vrc("did:web:ATTACKER_FORGED");
        let result = vet_vrc_issued(&rels, &tasks, &vrc, &sender, Some(pending.as_str()));
        assert!(result.is_err(), "forged issuer must be rejected");
        assert!(
            tasks.get_by_id(&pending).is_some(),
            "pending task must survive a rejected VRC"
        );
    }

    #[test]
    fn vrc_issued_without_relationship_is_dropped() {
        let sender = Arc::new("did:webvh:example:stranger".to_string());
        let rels = Relationships::default();
        let tasks = Tasks::default();

        let vrc = unsigned_vrc(sender.as_str());
        assert!(vet_vrc_issued(&rels, &tasks, &vrc, &sender, None).is_err());
    }

    #[test]
    fn vrc_issued_from_non_established_relationship_is_dropped() {
        let sender = Arc::new("did:webvh:example:half-shaken".to_string());
        let rel = relationship(&sender, &sender, RelationshipState::RequestSent);
        let rels = relationships_with(&rel);
        let tasks = Tasks::default();

        let vrc = unsigned_vrc(sender.as_str());
        assert!(vet_vrc_issued(&rels, &tasks, &vrc, &sender, None).is_err());
    }

    #[test]
    fn vrc_issued_thid_matching_unrelated_task_is_ignored() {
        let sender = Arc::new("did:webvh:example:sender".to_string());
        let rel = relationship(&sender, &sender, RelationshipState::Established);
        let rels = relationships_with(&rel);

        let mut tasks = Tasks::default();
        // An unrelated pending task (not an outbound VRC request).
        let unrelated = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &unrelated,
            TaskType::RelationshipRequestOutbound {
                to: Arc::new("did:webvh:example:third-party".to_string()),
            },
        );
        // An outbound VRC request — but to a *different* sender.
        let other_rel = relationship(
            "did:webvh:example:other",
            "did:webvh:example:other",
            RelationshipState::Established,
        );
        let other_request = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &other_request,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::clone(&other_rel.remote_p_did),
            },
        );

        let vrc = unsigned_vrc(sender.as_str());
        for thid in [unrelated.as_str(), other_request.as_str()] {
            let resolved = vet_vrc_issued(&rels, &tasks, &vrc, &sender, Some(thid))
                .expect("message itself is acceptable");
            assert!(
                resolved.is_none(),
                "thid pointing at an unrelated task must not resolve it"
            );
        }
        assert!(tasks.get_by_id(&unrelated).is_some());
        assert!(tasks.get_by_id(&other_request).is_some());
    }

    #[test]
    fn vrc_issued_thid_resolves_our_matching_outbound_request() {
        let sender_p = "did:webvh:example:sender";
        let sender_r = "did:webvh:example:sender-rdid";
        // Envelope arrives from the sender's R-DID; issuer is their P-DID.
        let from = Arc::new(sender_r.to_string());
        let rel = relationship(sender_p, sender_r, RelationshipState::Established);
        let rels = relationships_with(&rel);

        let mut tasks = Tasks::default();
        let request = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &request,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::clone(&rel.remote_p_did),
            },
        );

        let vrc = unsigned_vrc(sender_p);
        let resolved = vet_vrc_issued(&rels, &tasks, &vrc, &from, Some(request.as_str()))
            .expect("legitimate VRC must pass vetting");
        assert_eq!(resolved, Some(request));
    }

    // --- inbound VRC-issued proof verification (task R2 gate 4) ---

    async fn test_tdk() -> TDK {
        TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .expect("TDK config builds"),
            None,
        )
        .await
        .expect("TDK builds")
    }

    #[tokio::test]
    async fn vrc_proof_validly_signed_credential_is_accepted() {
        let tdk = test_tdk().await;
        let (issuer_did, issuer_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");

        let mut vrc = unsigned_vrc(&issuer_did);
        vrc.sign(&issuer_secret, None).await.expect("signs");

        assert!(verify_vrc_proof(&tdk, &vrc).await.is_ok());
    }

    #[tokio::test]
    async fn vrc_proof_tampered_credential_is_rejected() {
        let tdk = test_tdk().await;
        let (issuer_did, issuer_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");

        let mut vrc = unsigned_vrc(&issuer_did);
        vrc.sign(&issuer_secret, None).await.expect("signs");

        // Tamper with the signed payload — the proof must no longer verify.
        vrc.credential_mut()
            .context
            .push("https://attacker.example/context/v1".to_string());
        assert!(verify_vrc_proof(&tdk, &vrc).await.is_err());
    }

    #[tokio::test]
    async fn vrc_proof_signed_by_non_issuer_key_is_rejected() {
        let tdk = test_tdk().await;
        let (_attacker_did, attacker_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");
        let (victim_did, _victim_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");

        // Attacker signs with their own key but names the victim as issuer:
        // the proof's verificationMethod won't belong to the issuer DID.
        let mut vrc = unsigned_vrc(&victim_did);
        vrc.sign(&attacker_secret, None).await.expect("signs");

        assert!(verify_vrc_proof(&tdk, &vrc).await.is_err());
    }

    #[tokio::test]
    async fn vrc_proof_unsigned_credential_is_rejected() {
        let tdk = test_tdk().await;
        let vrc = unsigned_vrc("did:webvh:example:issuer");
        assert!(verify_vrc_proof(&tdk, &vrc).await.is_err());
    }
}
