//! Pure protocol logic for inbound DIDComm message handling.
//!
//! These functions are the testable heart of the message-dispatch state
//! machine: they operate only over core domain types (`Account`, `Message`,
//! `Relationships`, `Tasks`, `DTGCredential`, `TDK`) and perform no async
//! I/O orchestration. The TUI's `process_inbound_message` orchestrator
//! imports and calls them.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_tdk::{TDK, didcomm::Message};
use dtg_credentials::DTGCredential;
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;
use vta_sdk::protocols::join_requests::{
    JoinRequestStatusResponseBody, JoinRequestSubmitReceiptBody,
};

use crate::config::Config;
use crate::config::account::{Account, CommunityStatus};
use crate::relationships::{RelationshipState, Relationships};
use crate::tasks::{TaskType, Tasks};

/// Reject inbound messages whose `created_time` is older than this. The
/// outbound side stamps a 48-hour expiry, so a 48-hour replay window is
/// the same horizon — anything older is either a replay or a clock skew
/// pathology and is safer to drop.
pub const MAX_MESSAGE_AGE_SECS: u64 = 48 * 60 * 60;

/// How far in the future a `created_time` may be before we treat it as
/// invalid (clock skew tolerance).
pub const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

/// Maximum number of tasks allowed before rejecting new inbound messages.
pub const MAX_TASKS: usize = 10_000;

/// Standard message expiry: 48 hours.
pub const MESSAGE_EXPIRY_SECS: u64 = 60 * 60 * 48;

/// Build a timestamped DIDComm message with standard 48-hour expiry.
pub fn build_didcomm_message(
    type_url: &str,
    body: serde_json::Value,
    from: &str,
    to: &str,
    thid: Option<&str>,
) -> Result<Message, anyhow::Error> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut builder = Message::build(Uuid::new_v4().to_string(), type_url.to_string(), body)
        .from(from.to_string())
        .to(to.to_string())
        .created_time(now)
        .expires_time(now + MESSAGE_EXPIRY_SECS);
    if let Some(t) = thid {
        builder = builder.thid(t.to_string());
    }
    Ok(builder.finalize())
}

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

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate the message timestamps. Returns `Err(reason)` if the message
/// should be dropped as too old, expired, or implausibly future-dated.
pub fn check_message_age(message: &Message) -> Result<(), &'static str> {
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
///
/// The `Result<(), ()>` shape is intentional — the only failure signal the
/// caller needs is "don't create the task"; the reason is already logged here.
/// Preserved verbatim from the pre-R17 TUI helper (now `pub` for the
/// orchestrator), so an `allow` keeps the signature unchanged.
#[allow(clippy::result_unit_err)]
pub fn check_task_capacity(
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
pub fn handle_join_submit_receipt(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> bool {
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

/// Outcome of applying a VTC `join-requests/status-response` to a community.
pub struct StatusOutcome {
    /// The community record changed and the config needs saving.
    pub changed: bool,
    /// The community transitioned to an inactive (read-only) status, so the
    /// runtime must deregister its live session (R-S-3 / D15).
    pub inactivated: bool,
}

impl StatusOutcome {
    const NONE: StatusOutcome = StatusOutcome {
        changed: false,
        inactivated: false,
    };
}

/// Apply a VTC `join-requests/status-response` to the matching Pending community
/// (R-B-8). Correlated by the body's `request_id` against the Pending record's
/// stored id, and gated on the sender being the community's own VTC (anti-spoof).
/// Maps the protocol status onto the membership lifecycle:
///
/// - `approved` → `Active` (also reached via the issued VMC in
///   [`handle_credential_issue`]; idempotent here).
/// - `rejected` → `Rejected` (inactive — the caller deregisters the session).
/// - `deferred` → stays `Pending` ("more info required"); the content handling
///   (evaluating `needs` / presenting the DCQL) is a **D4 stub**, and a Pending
///   record already raises actions-required (R-S-2).
/// - `pending` / `withdrawn` / unknown → no transition (withdrawal is the
///   member-initiated leave, owned by T7).
pub fn handle_join_status_response(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> StatusOutcome {
    let body: JoinRequestStatusResponseBody = match serde_json::from_value(message.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "malformed join status-response body — ignoring");
            return StatusOutcome::NONE;
        }
    };
    let Some(record) = account.communities.get_mut(from_did) else {
        warn!(vtc = %from_did, "status-response from an unknown community — ignoring");
        return StatusOutcome::NONE;
    };
    // Correlate: only resolve a Pending record whose request id matches the reply.
    let matches = matches!(
        &record.status,
        CommunityStatus::Pending { request_id } if *request_id == body.request_id
    );
    if !matches {
        warn!(vtc = %from_did, "status-response did not match a pending request id — ignoring");
        return StatusOutcome::NONE;
    }

    match body.status.as_str() {
        "approved" => {
            record.activate(chrono::Utc::now());
            info!(vtc = %from_did, "join approved by VTC — now Active");
            StatusOutcome {
                changed: true,
                inactivated: false,
            }
        }
        "rejected" => {
            record.reject();
            info!(vtc = %from_did, "join rejected by VTC");
            StatusOutcome {
                changed: true,
                inactivated: true,
            }
        }
        "deferred" => {
            // "More info required" — stays Pending (still raises actions-required);
            // evaluating `needs` / presenting the DCQL is deferred to D4.
            info!(
                vtc = %from_did,
                needs = ?body.needs,
                "join deferred — more information required (handling deferred to D4)"
            );
            StatusOutcome::NONE
        }
        other => {
            debug!(vtc = %from_did, status = %other, "status-response: no transition");
            StatusOutcome::NONE
        }
    }
}

/// Handle a VTC `credential-exchange/issue`: store the issued credential on the
/// matching community and, for the membership credential (VMC), flip the
/// membership to `Active`. The issuing VTC is the authcrypt sender; the
/// credential must be issued by that VTC and to the community's own persona
/// (anti-misdelivery). Returns `true` if a record was updated.
pub fn handle_credential_issue(account: &mut Account, message: &Message, from_did: &str) -> bool {
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

    // Classify the credential against the typed registry — the one place that
    // knows credential kinds, so a new kind is handled here without edits.
    let Some(kind) = crate::CredentialKind::from_credential(&credential) else {
        warn!(vtc = %from_did, "issued credential is of no known kind — ignoring");
        return false;
    };

    let record = account
        .communities
        .get_mut(from_did)
        .expect("community present (checked above)");
    record.credentials.insert(kind, credential);
    if kind.activates_membership() && !record.status.is_active() {
        record.activate(chrono::Utc::now());
    }
    info!(
        vtc = %from_did,
        credential_kind = %kind.config_key(),
        // Whether this kind activates membership — distinct from the record's
        // resulting `status`, which may already have been active.
        activates_membership = kind.activates_membership(),
        "stored issued credential",
    );
    true
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
pub fn vet_vrc_issued(
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
pub async fn verify_vrc_proof(tdk: &TDK, vrc: &DTGCredential) -> Result<(), String> {
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

/// Extract the thread ID (`thid`) from a message, returning an error if missing.
pub fn require_thid(message: &Message) -> Result<Arc<String>, anyhow::Error> {
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
pub fn validate_did(did: &str) -> Result<(), anyhow::Error> {
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
pub fn is_did_msi_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | '%')
}

/// Build a DIDComm finalize message for relationship establishment.
pub fn create_finalize_message(
    from: &str,
    to: &str,
    task_id: &Arc<String>,
) -> Result<Message, anyhow::Error> {
    build_didcomm_message(
        crate::protocol_urls::RELATIONSHIP_REQUEST_FINALIZE,
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

    use crate::config::account::{Account, CommunityRecord, PersonaId, PersonaRecord};
    use chrono::Utc;
    use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
    use vta_sdk::protocols::join_requests::{
        JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
    };

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

    // --- status-response lifecycle resolution (R-B-8) ---

    fn status_response(from: &str, request_id: Uuid, status: &str) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            JOIN_REQUEST_STATUS_RESPONSE_TYPE.to_string(),
            serde_json::json!({ "requestId": request_id, "status": status }),
        )
        .from(from.to_string())
        .finalize()
    }

    #[test]
    fn status_response_approved_activates() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out =
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "approved"), vtc);
        assert!(out.changed);
        assert!(!out.inactivated, "approval keeps the live session");
        let rec = acct.communities.get(vtc).unwrap();
        assert!(rec.status.is_active());
        assert!(
            rec.member_since.is_some(),
            "member_since stamped on activate"
        );
    }

    #[test]
    fn status_response_rejected_inactivates_and_raises_badge() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out =
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "rejected"), vtc);
        assert!(out.changed);
        assert!(
            out.inactivated,
            "a rejection must deregister the session (R-S-3)"
        );
        let rec = acct.communities.get(vtc).unwrap();
        assert!(matches!(rec.status, CommunityStatus::Rejected));
        assert!(
            rec.needs_attention(),
            "an unacknowledged rejection nags (R-S-2)"
        );
    }

    #[test]
    fn status_response_deferred_stays_pending() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out =
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "deferred"), vtc);
        assert!(
            !out.changed,
            "more-info handling is a D4 stub — stays Pending"
        );
        assert!(!out.inactivated);
        assert!(matches!(
            acct.communities.get(vtc).unwrap().status,
            CommunityStatus::Pending { .. }
        ));
    }

    #[test]
    fn status_response_with_mismatched_request_id_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let mut acct = pending_account(vtc, Uuid::new_v4());

        // A reply correlated to a different request id must not transition us.
        let out = handle_join_status_response(
            &mut acct,
            &status_response(vtc, Uuid::new_v4(), "rejected"),
            vtc,
        );
        assert!(!out.changed);
        assert!(!out.inactivated);
        assert!(matches!(
            acct.communities.get(vtc).unwrap().status,
            CommunityStatus::Pending { .. }
        ));
    }

    #[test]
    fn status_response_from_unknown_community_is_ignored() {
        let mut acct = pending_account("did:webvh:example:vtc", Uuid::new_v4());
        let out = handle_join_status_response(
            &mut acct,
            &status_response("did:webvh:example:other", Uuid::new_v4(), "approved"),
            "did:webvh:example:other",
        );
        assert!(!out.changed);
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
        assert!(
            rec.credentials
                .contains_key(&crate::CredentialKind::Membership)
        );
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
        assert!(rec.credentials.contains_key(&crate::CredentialKind::Role));
    }

    /// The dispatch path is purely registry-driven: every kind in
    /// `CredentialKind::ALL` is classified and stored by `handle_credential_issue`
    /// with no per-kind branching, so adding a kind to the registry is the only
    /// change needed for it to be handled here (R19 acceptance criterion).
    #[test]
    fn credential_issue_handles_every_registered_kind() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";

        for kind in crate::CredentialKind::ALL {
            let mut acct = account_with_persona(vtc, persona);
            let m = issue(
                vtc,
                vc(&["VerifiableCredential", kind.vc_type()], vtc, persona),
            );
            assert!(
                handle_credential_issue(&mut acct, &m, vtc),
                "kind {kind:?} should be accepted",
            );
            let rec = acct.communities.get(vtc).unwrap();
            assert!(
                rec.credentials.contains_key(kind),
                "kind {kind:?} should be stored under its registry key",
            );
            assert_eq!(
                rec.status.is_active(),
                kind.activates_membership(),
                "activation for {kind:?} must match the registry",
            );
        }
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

    use crate::relationships::Relationship;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::dids::{DID, KeyType};

    fn relationship(remote_p: &str, remote_r: &str, state: RelationshipState) -> Relationship {
        Relationship {
            task_id: Arc::new(Uuid::new_v4().to_string()),
            our_did: Arc::new("did:webvh:example:us".to_string()),
            remote_did: Arc::new(remote_r.to_string()),
            remote_p_did: Arc::new(remote_p.to_string()),
            created: Utc::now(),
            state,
            our_persona: None,
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
