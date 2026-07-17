//! Client side of the `governance/capability/*` Trust Task family: query and
//! manage a community's pluggable capabilities from the TUI.
//!
//! The community's governance host is the VTC itself (its registry serves the
//! capability surface), reached over DIDComm via the mediator: requests are
//! `TrustTask` documents packed inside the `trust-tasks-didcomm` binding
//! envelope, replies arrive asynchronously and are correlated by the
//! document's `threadId` (== the request document id).
//!
//! Writes (`enable`/`disable`) carry an `eddsa-jcs-2022` Data-Integrity proof
//! signed with the persona's signing key, bound to the document `issuer`.
//! NOTE: v1 signs directly in the client; routing the approval through the
//! delegated-execution consent flow is the planned upgrade
//! (`trust-task-delegation-architecture.md`).

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use crate::errors::OpenVTCError;
use crate::pack_and_send;

/// The `trust-tasks-didcomm` binding envelope type (the message type the
/// registry's DIDComm Trust Task handler listens for). Kept in sync with
/// `trust_tasks_didcomm::ENVELOPE_TYPE`; hardcoded here to avoid pulling the
/// whole binding crate for one constant.
pub const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Type URIs of the governance capability family.
pub const CAPABILITY_LIST_TYPE: &str = "https://trusttasks.org/spec/governance/capability/list/0.1";
pub const CAPABILITY_ENABLE_TYPE: &str =
    "https://trusttasks.org/spec/governance/capability/enable/0.1";
pub const CAPABILITY_DISABLE_TYPE: &str =
    "https://trusttasks.org/spec/governance/capability/disable/0.1";

/// One capability as rendered by the panel.
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilitySummary {
    pub slug: String,
    pub title: Option<String>,
    pub version: String,
    pub enabled: bool,
    pub enabled_at: Option<String>,
    pub delegate: Option<String>,
    /// The full manifest for the detail view.
    pub manifest: Value,
}

/// What a correlated capability reply means for the panel.
#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityReply {
    /// A `list` response: the community's capabilities.
    Listing(Vec<CapabilitySummary>),
    /// An `enable`/`disable` response acknowledging the toggle.
    Toggled { capability: String, enabled: bool },
    /// A `trust-task-error` document; the code is the machine-readable
    /// trust-task error code, the message its human detail.
    Rejected {
        code: String,
        message: Option<String>,
    },
}

/// Build the `governance/capability/list` request document (status `all`, so
/// the panel can offer enabling what's available).
pub fn build_list_document(persona_did: &str, vtc_did: &str) -> TrustTask<Value> {
    build_document(
        persona_did,
        vtc_did,
        CAPABILITY_LIST_TYPE,
        serde_json::json!({ "status": "all" }),
    )
}

/// Build the `enable` or `disable` request document.
///
/// For `enable`, `config.authority` defaults to the community's own DID: per
/// the governance model the community *is* the authority its capability
/// records are issued under.
pub fn build_toggle_document(
    persona_did: &str,
    vtc_did: &str,
    slug: &str,
    version: &str,
    enable: bool,
) -> TrustTask<Value> {
    if enable {
        build_document(
            persona_did,
            vtc_did,
            CAPABILITY_ENABLE_TYPE,
            serde_json::json!({
                "capability": slug,
                "version": version,
                "config": { "authority": vtc_did },
            }),
        )
    } else {
        build_document(
            persona_did,
            vtc_did,
            CAPABILITY_DISABLE_TYPE,
            serde_json::json!({ "capability": slug }),
        )
    }
}

fn build_document(
    persona_did: &str,
    vtc_did: &str,
    type_uri: &str,
    payload: Value,
) -> TrustTask<Value> {
    let mut doc = TrustTask::new(
        format!("urn:uuid:{}", Uuid::new_v4()),
        type_uri
            .parse()
            .unwrap_or_else(|_| unreachable!("static capability type URIs are valid")),
        payload,
    );
    doc.issuer = Some(persona_did.to_string());
    doc.recipient = Some(vtc_did.to_string());
    doc.issued_at = Some(chrono::Utc::now());
    doc
}

/// Attach an `eddsa-jcs-2022` Data-Integrity proof over `doc` (minus the
/// `proof` member, mirroring the verifier's canonical form), signed with the
/// persona's signing secret. The verification method is the secret's key id,
/// which must belong to the document `issuer` (the host enforces the binding).
pub async fn sign_document(
    doc: &mut TrustTask<Value>,
    signing_secret: &Secret,
) -> Result<(), OpenVTCError> {
    let mut doc_value = serde_json::to_value(&*doc)
        .map_err(|e| OpenVTCError::Config(format!("serialise capability document: {e}")))?;
    if let Some(obj) = doc_value.as_object_mut() {
        obj.remove("proof");
    }
    let proof = DataIntegrityProof::sign(&doc_value, signing_secret, SignOptions::default())
        .await
        .map_err(|e| OpenVTCError::Config(format!("sign capability document: {e}")))?;
    let proof_value = serde_json::to_value(&proof)
        .map_err(|e| OpenVTCError::Config(format!("serialise proof: {e}")))?;
    doc.proof = Some(
        serde_json::from_value(proof_value)
            .map_err(|e| OpenVTCError::Config(format!("convert proof: {e}")))?,
    );
    Ok(())
}

/// Pack `doc` in the DIDComm Trust Task envelope and send it to the VTC via
/// the mediator. Returns the document id — the `threadId` the reply will
/// carry. Sending is fire-and-forget: `Ok` means handed to the transport,
/// never that the host received it; the caller owns a reply timeout.
pub async fn send_capability_document(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    persona_did: &str,
    vtc_did: &str,
    mediator: &str,
    doc: &TrustTask<Value>,
) -> Result<String, OpenVTCError> {
    let body = serde_json::to_value(doc)
        .map_err(|e| OpenVTCError::Config(format!("serialise capability document: {e}")))?;
    let message = Message::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        TRUST_TASK_ENVELOPE_TYPE.to_string(),
        body,
    )
    .from(persona_did.to_string())
    .to(vtc_did.to_string())
    .thid(doc.id.clone())
    .finalize();
    pack_and_send(atm, profile, &message, persona_did, vtc_did, mediator).await?;
    Ok(doc.id.clone())
}

/// Parse a raw DIDComm envelope body into `(threadId, reply)` — the entry
/// point for inbound dispatch, which holds only `serde_json::Value`.
pub fn parse_envelope_reply(body: &Value) -> Option<(String, CapabilityReply)> {
    let doc: TrustTask<Value> = serde_json::from_value(body.clone()).ok()?;
    let thid = doc.thread_id.clone()?;
    let reply = parse_capability_reply(&doc)?;
    Some((thid, reply))
}

/// Interpret an inbound Trust Task envelope body as a capability reply.
/// Returns `None` when the document is not part of this family (someone
/// else's trust task riding the same envelope type).
pub fn parse_capability_reply(doc: &TrustTask<Value>) -> Option<CapabilityReply> {
    let slug = doc.type_uri.slug();
    if slug == "trust-task-error" {
        // Only classified as ours by the caller's threadId correlation.
        let code = doc
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let message = doc
            .payload
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string);
        return Some(CapabilityReply::Rejected { code, message });
    }
    if !doc.type_uri.is_response() {
        return None;
    }
    match slug {
        "governance/capability/list" => {
            let entries = doc
                .payload
                .get("capabilities")
                .and_then(Value::as_array)
                .map(|entries| entries.iter().filter_map(summary_of).collect())
                .unwrap_or_default();
            Some(CapabilityReply::Listing(entries))
        }
        "governance/capability/enable" | "governance/capability/disable" => {
            Some(CapabilityReply::Toggled {
                capability: doc
                    .payload
                    .get("capability")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                enabled: doc
                    .payload
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        }
        _ => None,
    }
}

fn summary_of(entry: &Value) -> Option<CapabilitySummary> {
    let manifest = entry.get("manifest")?.clone();
    Some(CapabilitySummary {
        slug: manifest.get("capability")?.as_str()?.to_string(),
        title: manifest
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_string),
        version: manifest
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string(),
        enabled: entry
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        enabled_at: entry
            .get("enabledAt")
            .and_then(Value::as_str)
            .map(str::to_string),
        delegate: entry
            .get("delegate")
            .and_then(Value::as_str)
            .map(str::to_string),
        manifest,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn list_document_is_addressed_and_typed() {
        let doc = build_list_document("did:example:me", "did:example:vtc");
        assert_eq!(doc.issuer.as_deref(), Some("did:example:me"));
        assert_eq!(doc.recipient.as_deref(), Some("did:example:vtc"));
        assert_eq!(doc.type_uri.slug(), "governance/capability/list");
        assert_eq!(doc.payload["status"], "all");
    }

    #[test]
    fn enable_defaults_authority_to_the_community() {
        let doc = build_toggle_document(
            "did:example:me",
            "did:example:vtc",
            "git-trust",
            "0.1",
            true,
        );
        assert_eq!(doc.payload["config"]["authority"], "did:example:vtc");
        assert_eq!(doc.payload["capability"], "git-trust");
        let doc = build_toggle_document(
            "did:example:me",
            "did:example:vtc",
            "git-trust",
            "0.1",
            false,
        );
        assert_eq!(doc.type_uri.slug(), "governance/capability/disable");
        assert!(doc.payload.get("config").is_none());
    }

    #[test]
    fn parses_a_listing_reply() {
        let request = build_list_document("did:example:me", "did:example:vtc");
        let reply = request.respond_with(
            "urn:uuid:r".to_string(),
            serde_json::json!({
                "capabilities": [{
                    "manifest": {
                        "capability": "git-trust", "version": "0.1",
                        "title": "Git Commit Trust", "specs": ["git-trust/*"]
                    },
                    "enabled": true,
                    "enabledAt": "2026-07-17T00:00:00Z"
                }]
            }),
        );
        let Some(CapabilityReply::Listing(items)) = parse_capability_reply(&reply) else {
            panic!("expected listing");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].slug, "git-trust");
        assert!(items[0].enabled);
        assert_eq!(items[0].title.as_deref(), Some("Git Commit Trust"));
    }

    #[test]
    fn parses_error_and_toggle_replies_and_ignores_foreign_tasks() {
        let request = build_toggle_document("did:example:me", "did:example:vtc", "x", "0.1", true);
        let err = request.reject_with(
            "urn:uuid:e".to_string(),
            trust_tasks_rs::RejectReason::PermissionDenied {
                reason: "nope".to_string(),
            },
        );
        let err_value: TrustTask<Value> =
            serde_json::from_value(serde_json::to_value(&err).unwrap()).unwrap();
        assert!(matches!(
            parse_capability_reply(&err_value),
            Some(CapabilityReply::Rejected { .. })
        ));

        let ok = request.respond_with(
            "urn:uuid:t".to_string(),
            serde_json::json!({ "capability": "x", "enabled": true }),
        );
        assert_eq!(
            parse_capability_reply(&ok),
            Some(CapabilityReply::Toggled {
                capability: "x".to_string(),
                enabled: true
            })
        );

        let foreign = TrustTask::new(
            "urn:uuid:f".to_string(),
            "https://trusttasks.org/spec/registry/authorization/0.1#response"
                .parse()
                .unwrap(),
            serde_json::json!({}),
        );
        assert_eq!(parse_capability_reply(&foreign), None);
    }
}
