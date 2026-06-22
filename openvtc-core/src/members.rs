//! Member → VTC reciprocal membership-credential (VMC) exchange (the `members`
//! protocol family).
//!
//! Membership between a persona and a VTC is a *pair* of VMCs: the VTC issues one
//! to the member at admission (community → member, stored on the membership via
//! [`handle_credential_issue`](crate::messaging::handle_credential_issue)), and
//! the member issues one back (member → community). This module sends the
//! member's half over DIDComm.
//!
//! The VMC is a Data-Integrity VC whose `issuer` is the member persona and whose
//! `credentialSubject.id` is the community VTC DID; the VTC verifies the proof +
//! binding and stores it (vta-sdk `protocols::members`, type `members/vmc/1.0`).

use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::members::{MEMBER_VMC_TYPE, MemberVmcBody};

use crate::errors::OpenVTCError;

/// Send a member-issued VMC to the community's VTC over DIDComm
/// (`members/vmc/1.0`). `vc` is the **signed** membership credential — `issuer`
/// = the member persona (`member_did`), `credentialSubject.id` = the community
/// (`vtc_did`). The message is packed authcrypt and forwarded via the persona's
/// mediator; the VTC reads the member from the envelope and verifies the VC's own
/// issuer proof. Returns the DIDComm message id (the thread root the VTC's
/// `#response` receipt references).
pub async fn submit_member_vmc(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    member_did: &str,
    vtc_did: &str,
    mediator_did: &str,
    vc: Value,
) -> Result<Uuid, OpenVTCError> {
    let body = serde_json::to_value(MemberVmcBody { vc })
        .map_err(|e| OpenVTCError::Config(format!("member vmc body serialize: {e}")))?;

    let msg_id = Uuid::new_v4();
    let now = Utc::now().timestamp().max(0) as u64;
    let msg = Message::build(msg_id.to_string(), MEMBER_VMC_TYPE.to_string(), body)
        .from(member_did.to_string())
        .to(vtc_did.to_string())
        .created_time(now)
        .finalize();

    crate::pack_and_send(atm, profile, &msg, member_did, vtc_did, mediator_did).await?;
    Ok(msg_id)
}
