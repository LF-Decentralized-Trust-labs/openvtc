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
    closes_request: Option<Uuid>,
) -> Result<Uuid, OpenVTCError> {
    let vc = build_member_vmc(signing_secret, member_did, vtc_did).await?;
    submit_member_vmc(
        atm,
        profile,
        member_did,
        vtc_did,
        mediator_did,
        vc,
        closes_request,
    )
    .await
}

/// Build + sign the reciprocal member VMC, without sending it. The signing half of
/// [`issue_and_send_member_vmc`], split out so the credential's shape can be asserted
/// without a mediator.
///
/// # The credential carries its own `id`
///
/// A community stores a member's VMC keyed by that `id`: it is what makes a re-sent
/// credential idempotent rather than a duplicate, and a *different* one a renewal rather
/// than a conflict. A VMC without one is refused, and the refusal comes back as a
/// problem-report threaded on the delivery — which is not a thread this client correlates,
/// so the rejection is invisible from here and the membership pair silently stays half
/// formed.
///
/// The id has to be set before signing: the Data Integrity proof covers the credential
/// minus its `proof`, so an id added afterwards leaves a document whose proof no longer
/// verifies. `dtg-credentials` 0.3 is the first release with somewhere to put it.
pub async fn build_member_vmc(
    signing_secret: &Secret,
    member_did: &str,
    vtc_did: &str,
) -> Result<Value, OpenVTCError> {
    let mut vmc = DTGCredential::new_vmc(
        member_did.to_string(),
        vtc_did.to_string(),
        Utc::now(),
        None,
        false,
    )
    .with_id(format!("urn:uuid:{}", Uuid::new_v4()));
    vmc.sign(signing_secret, None)
        .await
        .map_err(|e| OpenVTCError::Config(format!("sign member VMC: {e}")))?;
    serde_json::to_value(&vmc)
        .map_err(|e| OpenVTCError::Config(format!("serialize member VMC: {e}")))
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
    closes_request: Option<Uuid>,
) -> Result<Uuid, OpenVTCError> {
    // `closes_request` closes an *approved join request* as a side effect of
    // the delivery — `vtc/members/vmc/0.1`'s `requestId`, carrying the retired
    // `join-requests/accept` semantics.
    //
    // It is `Some` only on the join-time delivery, where the community is
    // still holding the request open waiting for our half. The manual "issue
    // VMC" action and the auto-answer to a `members/request-vmc` have no
    // request to close, and pass `None`.
    let body = serde_json::to_value(MemberVmcBody {
        vc,
        request_id: closes_request.map(|id| id.to_string()),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    const MEMBER: &str = "did:example:member";
    const COMMUNITY: &str = "did:example:community";

    async fn signed_vmc() -> (Secret, Value) {
        let secret = Secret::generate_ed25519(None, None);
        let vc = build_member_vmc(&secret, MEMBER, COMMUNITY)
            .await
            .expect("build the member VMC");
        (secret, vc)
    }

    /// The community keys a member's VMC by its top-level `id` and refuses one that has
    /// none. Every VMC this client ever issued lacked it, because `dtg-credentials` had no
    /// field for it — so every delivery was rejected, and the rejection arrived on a thread
    /// this client does not correlate.
    #[tokio::test]
    async fn a_member_vmc_carries_a_top_level_id() {
        let (_secret, vc) = signed_vmc().await;

        let id = vc
            .get("id")
            .and_then(Value::as_str)
            .expect("the VMC carries a top-level `id`");
        assert!(
            id.starts_with("urn:uuid:"),
            "the id should be a urn:uuid: URN, got {id}"
        );
        // `credentialSubject.id` names the *community*. It is a different property and does
        // not stand in for the credential's own identifier.
        assert_eq!(vc["credentialSubject"]["id"], COMMUNITY);
    }

    /// Two deliveries must not collide: the community treats a repeat of the same `id` as
    /// idempotent and a different one as a renewal, so a fixed id would make every
    /// re-issuance a no-op.
    #[tokio::test]
    async fn each_member_vmc_gets_a_fresh_id() {
        let (_, first) = signed_vmc().await;
        let (_, second) = signed_vmc().await;
        assert_ne!(first["id"], second["id"]);
    }

    /// The id is inside what the proof covers, which is why it has to be set before signing
    /// rather than spliced into the JSON on the way out. Parsing the delivered credential
    /// back and verifying it is what the community does; it must pass.
    #[tokio::test]
    async fn the_signed_vmc_verifies_with_its_id_in_place() {
        let (secret, vc) = signed_vmc().await;

        let parsed: DTGCredential = serde_json::from_value(vc.clone()).expect("parse back");
        parsed
            .verify_proof_with_public_key(secret.get_public_bytes())
            .expect("the delivered credential verifies as sent");

        // Tampering with the id — or adding one after the fact, the same operation — breaks
        // the proof, so there is no post-signing workaround for an issuer that omits it.
        let mut tampered = vc;
        tampered["id"] = Value::String("urn:uuid:00000000-0000-0000-0000-000000000000".into());
        let parsed: DTGCredential = serde_json::from_value(tampered).expect("parse back");
        assert!(
            parsed
                .verify_proof_with_public_key(secret.get_public_bytes())
                .is_err(),
            "a changed id must invalidate the proof"
        );
    }

    /// The issuer / subject direction is what the community verifies the pair by: the member
    /// issues, the community is the subject. Reversing it is a different credential.
    #[tokio::test]
    async fn the_member_issues_and_the_community_is_the_subject() {
        let (_secret, vc) = signed_vmc().await;
        assert_eq!(vc["issuer"], MEMBER);
        assert_eq!(vc["credentialSubject"]["id"], COMMUNITY);
        assert!(
            vc["type"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "MembershipCredential")
        );
    }
}
