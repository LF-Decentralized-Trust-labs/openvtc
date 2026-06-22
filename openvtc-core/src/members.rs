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
    secrets_resolver::secrets::Secret,
};
use chrono::Utc;
use dtg_credentials::DTGCredential;
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::members::{MEMBER_VMC_TYPE, MemberVmcBody};

use crate::errors::OpenVTCError;

/// Build + sign the reciprocal member VMC and send it to the community's VTC
/// (`members/vmc/1.0`), end to end. The VMC's `issuer` is the member persona
/// (`member_did`) and its `credentialSubject.id` is the community (`vtc_did`) —
/// the direction the VTC verifies. `signing_secret` is the member persona's
/// signing key (its `id` is the persona's assertionMethod VM, which becomes the
/// proof's `verificationMethod`). Used by both the manual "issue VMC" action and
/// the auto-answer to a VTC `members/request-vmc/1.0`.
///
/// Returns the DIDComm message id (the receipt's thread root).
pub async fn issue_and_send_member_vmc(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    signing_secret: &Secret,
    member_did: &str,
    vtc_did: &str,
    mediator_did: &str,
) -> Result<Uuid, OpenVTCError> {
    let mut vmc = DTGCredential::new_vmc(
        member_did.to_string(),
        vtc_did.to_string(),
        Utc::now(),
        None,
        false,
    );
    vmc.sign(signing_secret, None)
        .await
        .map_err(|e| OpenVTCError::Config(format!("sign member VMC: {e}")))?;
    let vc = serde_json::to_value(&vmc)
        .map_err(|e| OpenVTCError::Config(format!("serialize member VMC: {e}")))?;
    submit_member_vmc(atm, profile, member_did, vtc_did, mediator_did, vc).await
}

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
