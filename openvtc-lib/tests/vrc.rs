//! Integration tests for the Vrcs struct and VRC request types.

use openvtc::vrc::{VRCRequestReject, VrcRequest, Vrcs};
use std::sync::Arc;

#[test]
fn default_vrcs_is_empty() {
    let vrcs = Vrcs::default();
    assert_eq!(vrcs.keys().count(), 0);
    assert_eq!(vrcs.values().count(), 0);
}

#[test]
fn get_missing_key_returns_none() {
    let vrcs = Vrcs::default();
    let key = Arc::new("did:nonexistent".to_string());
    assert!(vrcs.get(&key).is_none());
}

#[test]
fn remove_relationship_on_empty_returns_false() {
    let mut vrcs = Vrcs::default();
    let key = Arc::new("did:remote:1".to_string());
    assert!(!vrcs.remove_relationship(&key));
}

// NOTE: Cannot test Vrcs::insert directly in integration tests because it
// requires a DTGCredential with a valid proof_value(), and DTGCredential
// construction depends on complex cryptographic setup that is beyond the
// scope of a unit/integration test without mocking infrastructure.

#[test]
fn vrc_request_default_has_no_reason() {
    let req = VrcRequest::default();
    assert!(req.reason.is_none());
}

#[test]
fn vrc_request_serde_roundtrip_with_reason() {
    let req = VrcRequest {
        reason: Some("I need a VRC for collaboration".to_string()),
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let restored: VrcRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        restored.reason.as_deref(),
        Some("I need a VRC for collaboration")
    );
}

#[test]
fn vrc_request_serde_roundtrip_without_reason() {
    let req = VrcRequest { reason: None };
    let json = serde_json::to_string(&req).expect("serialize");
    let restored: VrcRequest = serde_json::from_str(&json).expect("deserialize");
    assert!(restored.reason.is_none());
}

#[test]
fn vrc_request_reject_serde_roundtrip() {
    let reject = VRCRequestReject {
        reason: Some("not trusted".to_string()),
    };
    let json = serde_json::to_string(&reject).expect("serialize");
    let restored: VRCRequestReject = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.reason.as_deref(), Some("not trusted"));
}

#[test]
fn vrc_request_reject_no_reason() {
    let reject = VRCRequestReject { reason: None };
    let json = serde_json::to_string(&reject).expect("serialize");
    // With skip_serializing_if, "reason" should be absent from JSON
    assert!(
        !json.contains("reason"),
        "reason field should be omitted when None"
    );
    let restored: VRCRequestReject = serde_json::from_str(&json).expect("deserialize");
    assert!(restored.reason.is_none());
}

#[test]
fn vrc_request_json_uses_camel_case() {
    // VrcRequest uses #[serde(rename_all = "camelCase")] so field names
    // should be camelCase in JSON output.
    let req = VrcRequest {
        reason: Some("test".to_string()),
    };
    let json = serde_json::to_string(&req).expect("serialize");
    // "reason" is already camelCase-identical, but verify it deserializes from camelCase
    let from_camel: VrcRequest = serde_json::from_str(&json).expect("deserialize camelCase");
    assert_eq!(from_camel.reason.as_deref(), Some("test"));
}
