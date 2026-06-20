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
use chrono::{DateTime, Utc};
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

/// Build the holder presentation (VP) for a join request.
///
/// The VTC's raw-VP submit path performs no VP-level proof check — the DIDComm
/// authcrypt sender authenticates the applicant — so the VP is a plain JSON
/// object naming the `holder`. When the applicant holds a Verifiable Invitation
/// Credential (VIC), it is embedded in the `verifiableCredential` array; the
/// VTC extracts it, verifies its issuer signature + holder-binding, and (per the
/// default `join.rego`) auto-admits on a valid, trusted, unconsumed invitation.
///
/// `invitation` is the signed VIC as received out-of-band (a Data-Integrity VC,
/// object form with its own `proof`). When `None`, the VP carries no
/// credentials and the join falls to the community's other evidence / review.
pub fn build_join_vp(
    holder_did: &str,
    invitation: Option<&Value>,
    linkage: Option<&SubjectLinkage>,
) -> Value {
    let mut vp = serde_json::json!({
        "type": "VerifiablePresentation",
        "holder": holder_did,
    });
    if let Some(vic) = invitation {
        vp["verifiableCredential"] = Value::Array(vec![vic.clone()]);
    }
    // Subject-linkage proof (#1b): present a VIC bound to a *different* DID by
    // proving that DID authorized this holder. Omitted on the join-as-subject
    // path (holder == VIC subject).
    if let Some(l) = linkage {
        vp["subjectLinkage"] = serde_json::json!({
            "verificationMethod": l.verification_method,
            "signature": l.signature_hex,
        });
    }
    vp
}

/// Domain tag the VIC subject signs over for a subject-linkage proof. **Must
/// match `vtc-service`'s `SUBJECT_LINKAGE_DOMAIN_TAG`** byte-for-byte.
pub const SUBJECT_LINKAGE_DOMAIN_TAG: &[u8] = b"vtc-invitation-subject-linkage/v1\0";

/// A subject-linkage proof: the VIC subject's key signed
/// [`subject_linkage_signing_bytes`], authorizing a different presenter to
/// redeem the invitation.
#[derive(Debug, Clone)]
pub struct SubjectLinkage {
    /// The VIC subject's verification method (`<subjectDid>#<key>`).
    pub verification_method: String,
    /// Hex-encoded Ed25519 signature over [`subject_linkage_signing_bytes`].
    pub signature_hex: String,
}

/// The exact bytes a subject-linkage proof signs:
/// `SUBJECT_LINKAGE_DOMAIN_TAG || vic_id || NUL || presenter_did`. The VTC
/// rebuilds these identically when verifying, so both sides must agree.
pub fn subject_linkage_signing_bytes(vic_id: &str, presenter_did: &str) -> Vec<u8> {
    let mut bytes = SUBJECT_LINKAGE_DOMAIN_TAG.to_vec();
    bytes.extend_from_slice(vic_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(presenter_did.as_bytes());
    bytes
}

/// Produce a subject-linkage proof: sign [`subject_linkage_signing_bytes`] with
/// the VIC subject's Ed25519 private key (`private_seed`, 32 raw bytes — e.g.
/// `Secret::get_private_bytes`), authorizing `presenter_did` to redeem the
/// invitation `vic_id`. `verification_method` is the subject's assertionMethod
/// VM id the VTC resolves to verify the signature.
///
/// Signs via the TDK's Ed25519 routine
/// ([`affinidi_tdk::affinidi_crypto::jose::signing::sign`]) — the same
/// primitive the workspace uses elsewhere — not a hand-rolled signer.
pub fn sign_subject_linkage(
    private_seed: &[u8; 32],
    verification_method: impl Into<String>,
    vic_id: &str,
    presenter_did: &str,
) -> Result<SubjectLinkage, OpenVTCError> {
    let bytes = subject_linkage_signing_bytes(vic_id, presenter_did);
    let signature = affinidi_tdk::affinidi_crypto::jose::signing::sign(&bytes, private_seed)
        .map_err(|e| OpenVTCError::Config(format!("subject-linkage signing failed: {e}")))?;
    Ok(SubjectLinkage {
        verification_method: verification_method.into(),
        signature_hex: hex::encode(signature),
    })
}

/// The DID a VIC is bound to (`credentialSubject.id`).
pub fn invitation_subject(vic: &Value) -> Option<&str> {
    vic.pointer("/credentialSubject/id").and_then(Value::as_str)
}

/// A VIC's top-level `id` (its consumption / linkage handle).
pub fn invitation_id(vic: &Value) -> Option<&str> {
    vic.get("id").and_then(Value::as_str)
}

/// The DID that issued a VIC. For an `InvitationCredential` the issuer **is** the
/// community's VTC DID (the VTC signs it with its own issuer key, so
/// `issuer = signer.issuer_did()`), which is what a presentable invitation must
/// match against the community being joined. Accepts both the string issuer form
/// and the object form (`{ "id": "did:…" }`).
pub fn invitation_issuer(vic: &Value) -> Option<&str> {
    match vic.get("issuer")? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(_) => vic.pointer("/issuer/id").and_then(Value::as_str),
        _ => None,
    }
}

/// Whether a VIC is bound to the community identified by `vtc_did` — i.e. the VIC
/// was issued by that VTC. A held/loaded VIC issued by a *different* community
/// must not be presented: the VTC would reject the mismatched binding, so it is
/// no better than presenting nothing (and worse, it looks like a failed
/// invitation rather than an open request).
pub fn invitation_matches_community(vic: &Value, vtc_did: &str) -> bool {
    invitation_issuer(vic) == Some(vtc_did)
}

/// Whether a VIC's declared validity window has elapsed as of `now`. A VIC with
/// no `validUntil` is treated as non-expiring here (the VTC re-checks validity at
/// submit). A malformed `validUntil` is treated as expired (fail closed) so a
/// broken credential is never presented.
pub fn invitation_is_expired(vic: &Value, now: DateTime<Utc>) -> bool {
    match vic.get("validUntil").and_then(Value::as_str) {
        None => false,
        Some(s) => match DateTime::parse_from_rfc3339(s) {
            Ok(t) => t.with_timezone(&Utc) <= now,
            Err(_) => true,
        },
    }
}

/// Whether a JSON value is an InvitationCredential (its `type` array carries
/// the `InvitationCredential` tag). Used to validate a pasted/loaded VIC
/// before stashing it (join flow) or storing it in the vault (VIC manager).
pub fn is_invitation_credential(value: &Value) -> bool {
    value
        .get("type")
        .and_then(|t| t.as_array())
        .is_some_and(|types| {
            types
                .iter()
                .any(|t| t.as_str() == Some("InvitationCredential"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_vic() -> Value {
        json!({
            "id": "urn:uuid:vic-1",
            "type": ["VerifiableCredential", "InvitationCredential"],
            "issuer": "did:webvh:example.com:community",
            "credentialSubject": { "id": "did:webvh:example.com:alice" },
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    #[test]
    fn is_invitation_credential_checks_the_type_tag() {
        assert!(is_invitation_credential(&sample_vic()));
        // Missing `type`.
        assert!(!is_invitation_credential(&json!({ "id": "x" })));
        // Wrong tag.
        assert!(!is_invitation_credential(
            &json!({ "type": ["VerifiableCredential", "MembershipCredential"] })
        ));
        // `type` not an array.
        assert!(!is_invitation_credential(
            &json!({ "type": "InvitationCredential" })
        ));
    }

    #[test]
    fn vp_without_invitation_is_holder_only() {
        let vp = build_join_vp("did:webvh:example.com:alice", None, None);
        assert_eq!(vp["type"], "VerifiablePresentation");
        assert_eq!(vp["holder"], "did:webvh:example.com:alice");
        assert!(
            vp.get("verifiableCredential").is_none(),
            "no invitation → no credentials array"
        );
        assert!(vp.get("subjectLinkage").is_none());
    }

    #[test]
    fn vp_with_invitation_embeds_the_vic() {
        let vic = sample_vic();
        let vp = build_join_vp("did:webvh:example.com:alice", Some(&vic), None);
        let creds = vp["verifiableCredential"]
            .as_array()
            .expect("verifiableCredential is an array");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], vic, "the VIC is embedded verbatim");
        assert!(
            vp.get("subjectLinkage").is_none(),
            "no linkage on the join-as-subject path"
        );
    }

    #[test]
    fn vp_with_linkage_embeds_the_proof() {
        let vic = sample_vic();
        let linkage = SubjectLinkage {
            verification_method: "did:webvh:example.com:alice#key-0".into(),
            signature_hex: "deadbeef".into(),
        };
        let vp = build_join_vp("did:key:zFreshB", Some(&vic), Some(&linkage));
        assert_eq!(
            vp["subjectLinkage"]["verificationMethod"],
            "did:webvh:example.com:alice#key-0"
        );
        assert_eq!(vp["subjectLinkage"]["signature"], "deadbeef");
    }

    #[test]
    fn subject_and_id_extractors() {
        let vic = sample_vic();
        assert_eq!(
            invitation_subject(&vic),
            Some("did:webvh:example.com:alice")
        );
        assert_eq!(invitation_id(&vic), Some("urn:uuid:vic-1"));
        assert_eq!(invitation_subject(&json!({})), None);
    }

    #[test]
    fn issuer_extractor_handles_string_and_object_forms() {
        // String issuer (the form the VTC emits).
        assert_eq!(
            invitation_issuer(&sample_vic()),
            Some("did:webvh:example.com:community")
        );
        // Object issuer (`{ "id": … }`).
        let obj = json!({ "issuer": { "id": "did:webvh:example.com:community" } });
        assert_eq!(
            invitation_issuer(&obj),
            Some("did:webvh:example.com:community")
        );
        // Missing / wrong-typed issuer.
        assert_eq!(invitation_issuer(&json!({})), None);
        assert_eq!(invitation_issuer(&json!({ "issuer": 42 })), None);
    }

    #[test]
    fn community_match_keys_on_the_issuer() {
        let vic = sample_vic();
        assert!(invitation_matches_community(
            &vic,
            "did:webvh:example.com:community"
        ));
        assert!(!invitation_matches_community(
            &vic,
            "did:webvh:example.com:other-community"
        ));
    }

    #[test]
    fn expiry_uses_valid_until_and_fails_closed() {
        let now = "2026-06-21T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        // No validUntil → never expired.
        assert!(!invitation_is_expired(&sample_vic(), now));
        // Future window → not expired.
        let future = json!({ "validUntil": "2027-01-01T00:00:00Z" });
        assert!(!invitation_is_expired(&future, now));
        // Past window → expired.
        let past = json!({ "validUntil": "2025-01-01T00:00:00Z" });
        assert!(invitation_is_expired(&past, now));
        // Malformed → treated as expired (fail closed).
        let bad = json!({ "validUntil": "not-a-date" });
        assert!(invitation_is_expired(&bad, now));
    }

    #[test]
    fn sign_subject_linkage_verifies_with_the_tdk_routine() {
        use affinidi_tdk::affinidi_crypto::jose::signing;
        let seed = [7u8; 32];
        let pubkey = signing::public_key_from_private(&seed);
        let linkage = sign_subject_linkage(
            &seed,
            "did:webvh:example.com:alice#key-0",
            "urn:uuid:vic-1",
            "did:key:zFreshB",
        )
        .expect("sign");
        assert_eq!(
            linkage.verification_method,
            "did:webvh:example.com:alice#key-0"
        );
        // The signature verifies over the canonical bytes — the exact check the
        // VTC performs against the subject's resolved key.
        let sig: [u8; 64] = hex::decode(&linkage.signature_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let bytes = subject_linkage_signing_bytes("urn:uuid:vic-1", "did:key:zFreshB");
        assert!(signing::verify(&bytes, &sig, &pubkey).is_ok());
        // A different presenter's bytes must NOT verify against this signature.
        let other = subject_linkage_signing_bytes("urn:uuid:vic-1", "did:key:zOther");
        assert!(signing::verify(&other, &sig, &pubkey).is_err());
    }

    #[test]
    fn linkage_signing_bytes_are_tag_id_nul_presenter() {
        let bytes = subject_linkage_signing_bytes("urn:uuid:vic-1", "did:key:zB");
        let mut expected = SUBJECT_LINKAGE_DOMAIN_TAG.to_vec();
        expected.extend_from_slice(b"urn:uuid:vic-1");
        expected.push(0);
        expected.extend_from_slice(b"did:key:zB");
        assert_eq!(bytes, expected);
    }
}
