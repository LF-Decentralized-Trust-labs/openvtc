/*!
 * VTC join-ceremony client helpers.
 *
 * Sends the applicant side of the join ceremony to a VTC over DIDComm.
 * Authcrypt makes the sender (the persona DID) the authenticated
 * applicant — the VTC reads it from the envelope, so no separate
 * holder-binding signature is needed. DIDComm is also the *only* path
 * that works for a `did:webvh` persona: the VTC's REST holder-binding
 * verification accepts `did:key` applicants only.
 */

use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_SUBMIT_TYPE, JoinRequestSubmitBody, MEMBER_SELF_REMOVE_TYPE, SelfRemoveBody,
};

use crate::errors::OpenVTCError;

/// Submit a join request to a VTC (`vtc_did`) over DIDComm, presenting
/// `persona_did` as the applicant.
///
/// `vp` is the holder presentation the VTC's `join.rego` decides over.
/// The message is packed authcrypt and forwarded via the persona's
/// `mediator_did`; the VTC authenticates the applicant from the
/// envelope's `from`.
///
/// Returns the DIDComm message id. That id is the thread root the VTC's
/// `join-requests/submit-receipt/1.0` reply references (`thid`); the
/// authoritative VTC `requestId` arrives on that asynchronous receipt
/// (handled separately), so callers use the returned id as the
/// client-side correlation handle until then.
pub async fn submit_join_request(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    persona_did: &str,
    vtc_did: &str,
    mediator_did: &str,
    vp: Value,
) -> Result<Uuid, OpenVTCError> {
    let body = JoinRequestSubmitBody {
        vp,
        registry_consent: false,
        extensions: Value::Null,
    };
    let body = serde_json::to_value(&body)
        .map_err(|e| OpenVTCError::Config(format!("join submit body serialize: {e}")))?;

    let msg_id = Uuid::new_v4();
    let now = Utc::now().timestamp().max(0) as u64;
    let msg = Message::build(
        msg_id.to_string(),
        JOIN_REQUEST_SUBMIT_TYPE.to_string(),
        body,
    )
    .from(persona_did.to_string())
    .to(vtc_did.to_string())
    .created_time(now)
    .finalize();

    crate::pack_and_send(atm, profile, &msg, persona_did, vtc_did, mediator_did).await?;
    Ok(msg_id)
}

/// Send a member self-removal (`MEMBER_SELF_REMOVE`) to a VTC over DIDComm to
/// leave the community (R-L-1). `member_did` is the persona presented to the
/// community (the authcrypt sender authenticates it). `disposition` optionally
/// requests how the VTC should treat the departing member's record (purge /
/// tombstone / historical); `None` lets the VTC apply its default.
///
/// Returns the DIDComm message id — the thread root the VTC's
/// `members/self-remove-receipt/1.0` reply references. The local membership is
/// set to `Left` on send success; the receipt is advisory (logged if it
/// arrives), so callers don't block on it.
pub async fn submit_self_remove(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    member_did: &str,
    vtc_did: &str,
    mediator_did: &str,
    disposition: Option<String>,
) -> Result<Uuid, OpenVTCError> {
    let body = serde_json::to_value(SelfRemoveBody { disposition })
        .map_err(|e| OpenVTCError::Config(format!("self-remove body serialize: {e}")))?;

    let msg_id = Uuid::new_v4();
    let now = Utc::now().timestamp().max(0) as u64;
    let msg = Message::build(
        msg_id.to_string(),
        MEMBER_SELF_REMOVE_TYPE.to_string(),
        body,
    )
    .from(member_did.to_string())
    .to(vtc_did.to_string())
    .created_time(now)
    .finalize();

    crate::pack_and_send(atm, profile, &msg, member_did, vtc_did, mediator_did).await?;
    Ok(msg_id)
}
