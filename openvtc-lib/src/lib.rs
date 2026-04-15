/*! Library interface for OpenVTC
 *! Allows for other applications to use the same data structures and routines
*/
#![deny(unsafe_code)]

use crate::errors::OpenVTCError;
#[cfg(feature = "openpgp-card")]
use ::openpgp_card::ocard::KeyType;
use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

pub mod bip32;
pub mod colors;
pub mod config;
pub mod errors;
pub mod logs;
pub mod maintainers;
#[cfg(feature = "openpgp-card")]
pub mod openpgp_card;
pub mod process_lock;
pub mod relationships;
pub mod tasks;
pub mod vrc;

/// Primary Linux Foundation Mediator DID.
/// Can be overridden via the `OPENVTC_MEDIATOR_DID` environment variable.
pub const LF_PUBLIC_MEDIATOR_DID: &str =
    "did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator";

/// Primary Linux Foundation Organisation DID.
/// Can be overridden via the `OPENVTC_ORG_DID` environment variable.
pub const LF_ORG_DID: &str =
    "did:webvh:QmXkYcFCbvFFcYZf2q5gNk8Vp4b4vMbVKWbbc7oivcdZHK:fpp.storm.ws";

/// Returns the mediator DID, checking the environment variable first.
///
/// If `OPENVTC_MEDIATOR_DID` is set but does not start with `"did:"`, a warning
/// is logged and the default [`LF_PUBLIC_MEDIATOR_DID`] is returned instead.
pub fn mediator_did() -> String {
    if let Ok(did) = std::env::var("OPENVTC_MEDIATOR_DID") {
        if did.starts_with("did:") {
            return did;
        }
        tracing::warn!(
            "OPENVTC_MEDIATOR_DID value '{}' is not a valid DID (must start with 'did:'), using default",
            did
        );
    }
    LF_PUBLIC_MEDIATOR_DID.to_string()
}

/// Returns the organisation DID, checking the environment variable first.
///
/// If `OPENVTC_ORG_DID` is set but does not start with `"did:"`, a warning
/// is logged and the default [`LF_ORG_DID`] is returned instead.
pub fn org_did() -> String {
    if let Ok(did) = std::env::var("OPENVTC_ORG_DID") {
        if did.starts_with("did:") {
            return did;
        }
        tracing::warn!(
            "OPENVTC_ORG_DID value '{}' is not a valid DID (must start with 'did:'), using default",
            did
        );
    }
    LF_ORG_DID.to_string()
}

/// Packs a DIDComm message with authenticated encryption and forwards it
/// through the mediator to the recipient.
///
/// This is a convenience helper that combines `ATM::pack_encrypted` and
/// `ATM::forward_and_send_message` — the two-step pattern used at every
/// DIDComm send site in the workspace.
///
/// # Errors
///
/// Returns an error if message packing or delivery fails.
pub async fn pack_and_send(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    msg: &Message,
    from: &str,
    to: &str,
    mediator: &str,
) -> Result<(), errors::OpenVTCError> {
    let (packed, _) = atm.pack_encrypted(msg, to, Some(from), None).await?;
    atm.forward_and_send_message(
        profile, false, &packed, None, mediator, to, None, None, false,
    )
    .await?;
    Ok(())
}

/// Extracts the `from` address from a DIDComm message, returning an error
/// if the field is absent.
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] if the message has no `from` address.
pub fn require_from(msg: &Message) -> Result<String, errors::OpenVTCError> {
    msg.from
        .as_deref()
        .map(String::from)
        .ok_or_else(|| errors::OpenVTCError::Config("Message has no 'from' address".to_string()))
}

/// Protocol URL constants for DIDComm message types used in OpenVTC messaging.
pub mod protocol_urls {
    /// URL for initiating a new relationship request.
    pub const RELATIONSHIP_REQUEST: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request";
    /// URL for rejecting a relationship request.
    pub const RELATIONSHIP_REQUEST_REJECT: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-reject";
    /// URL for accepting a relationship request.
    pub const RELATIONSHIP_REQUEST_ACCEPT: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-accept";
    /// URL for finalizing an accepted relationship request.
    pub const RELATIONSHIP_REQUEST_FINALIZE: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-finalize";
    /// URL for sending a DIDComm trust ping.
    pub const TRUST_PING: &str = "https://didcomm.org/trust-ping/2.0/ping";
    /// URL for responding to a DIDComm trust ping.
    pub const TRUST_PONG: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
    /// URL for requesting a Verified Relationship Credential.
    pub const VRC_REQUEST: &str = "https://firstperson.network/vrc/1.0/request";
    /// URL for rejecting a VRC request.
    pub const VRC_REJECTED: &str = "https://firstperson.network/vrc/1.0/rejected";
    /// URL for issuing a VRC.
    pub const VRC_ISSUED: &str = "https://firstperson.network/vrc/1.0/issued";
    /// URL for requesting a list of known maintainers.
    pub const MAINTAINERS_LIST_REQUEST: &str = "https://kernel.org/maintainers/1.0/list";
    /// URL for responding with a list of known maintainers.
    pub const MAINTAINERS_LIST_RESPONSE: &str = "https://kernel.org/maintainers/1.0/list/response";
    /// URL for a DIDComm MessagePickup 3.0 status message.
    pub const MESSAGEPICKUP_STATUS: &str = "https://didcomm.org/messagepickup/3.0/status";
}

/// Defined Message Types for OpenVTC DIDComm messaging protocol.
///
/// Each variant maps to a protocol URL used in DIDComm message `type` fields.
///
/// # Examples
///
/// ```
/// use openvtc::MessageType;
///
/// // Parse a protocol URL into a MessageType
/// let mt = MessageType::try_from("https://didcomm.org/trust-ping/2.0/ping").unwrap();
/// assert_eq!(mt.friendly_name(), "Trust Ping (Send)");
///
/// // Convert back to URL
/// let url: String = mt.into();
/// assert_eq!(url, "https://didcomm.org/trust-ping/2.0/ping");
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MessageType {
    /// A request to establish a new relationship with a remote party.
    RelationshipRequest,
    /// Notification that a relationship request was rejected by the remote party.
    RelationshipRequestRejected,
    /// Notification that a relationship request was accepted by the remote party.
    RelationshipRequestAccepted,
    /// Finalizes an accepted relationship, completing the handshake.
    RelationshipRequestFinalize,
    /// Sends a DIDComm trust-ping to verify connectivity with a remote party.
    TrustPing,
    /// Response to a trust-ping, confirming the remote party is reachable.
    TrustPong,
    /// A request for a Verified Relationship Credential (VRC) from a remote party.
    VRCRequest,
    /// Notification that a VRC request was rejected.
    VRCRequestRejected,
    /// A VRC has been issued and delivered.
    VRCIssued,
    /// Request for a list of known kernel maintainers.
    MaintainersListRequest,
    /// Response containing a list of known kernel maintainers.
    MaintainersListResponse,
}

impl MessageType {
    /// Returns a human-readable display name for this message type.
    pub fn friendly_name(&self) -> String {
        match self {
            MessageType::RelationshipRequest => "Relationship Request",
            MessageType::RelationshipRequestRejected => "Relationship Request Rejected",
            MessageType::RelationshipRequestAccepted => "Relationship Request Accepted",
            MessageType::RelationshipRequestFinalize => "Relationship Request Finalize",
            MessageType::TrustPing => "Trust Ping (Send)",
            MessageType::TrustPong => "Trust Pong (Receive)",
            MessageType::VRCRequest => "VRC Request",
            MessageType::VRCRequestRejected => "VRC Request Rejected",
            MessageType::VRCIssued => "VRC Issued",
            MessageType::MaintainersListRequest => "List Known Maintainers (request)",
            MessageType::MaintainersListResponse => "List Known Maintainers (response)",
        }
        .to_string()
    }
}

/// Convert MessageType to its protocol URL string.
impl From<MessageType> for String {
    fn from(value: MessageType) -> Self {
        use protocol_urls::*;
        match value {
            MessageType::RelationshipRequest => RELATIONSHIP_REQUEST,
            MessageType::RelationshipRequestRejected => RELATIONSHIP_REQUEST_REJECT,
            MessageType::RelationshipRequestAccepted => RELATIONSHIP_REQUEST_ACCEPT,
            MessageType::RelationshipRequestFinalize => RELATIONSHIP_REQUEST_FINALIZE,
            MessageType::TrustPing => TRUST_PING,
            MessageType::TrustPong => TRUST_PONG,
            MessageType::VRCRequest => VRC_REQUEST,
            MessageType::VRCRequestRejected => VRC_REJECTED,
            MessageType::VRCIssued => VRC_ISSUED,
            MessageType::MaintainersListRequest => MAINTAINERS_LIST_REQUEST,
            MessageType::MaintainersListResponse => MAINTAINERS_LIST_RESPONSE,
        }
        .to_string()
    }
}

/// Convert a protocol URL string to a MessageType.
impl TryFrom<&str> for MessageType {
    type Error = OpenVTCError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use protocol_urls::*;
        match value {
            RELATIONSHIP_REQUEST => Ok(MessageType::RelationshipRequest),
            RELATIONSHIP_REQUEST_REJECT => Ok(MessageType::RelationshipRequestRejected),
            RELATIONSHIP_REQUEST_ACCEPT => Ok(MessageType::RelationshipRequestAccepted),
            RELATIONSHIP_REQUEST_FINALIZE => Ok(MessageType::RelationshipRequestFinalize),
            TRUST_PING => Ok(MessageType::TrustPing),
            TRUST_PONG => Ok(MessageType::TrustPong),
            VRC_REQUEST => Ok(MessageType::VRCRequest),
            VRC_REJECTED => Ok(MessageType::VRCRequestRejected),
            VRC_ISSUED => Ok(MessageType::VRCIssued),
            MAINTAINERS_LIST_REQUEST => Ok(MessageType::MaintainersListRequest),
            MAINTAINERS_LIST_RESPONSE => Ok(MessageType::MaintainersListResponse),
            _ => Err(OpenVTCError::InvalidMessage(value.to_string())),
        }
    }
}

/// Convert a DIDComm message to a MessageType
impl TryFrom<&Message> for MessageType {
    type Error = OpenVTCError;

    fn try_from(value: &Message) -> Result<Self, Self::Error> {
        value.typ.as_str().try_into()
    }
}

// ****************************************************************************
// Secret Key types and conversions
// ****************************************************************************

/// Tags what a cryptographic key is used for within a DID Document.
#[derive(Default, Debug, PartialEq)]
pub enum KeyPurpose {
    /// Key used for signing assertions (assertion method).
    Signing,
    /// Key used for authentication.
    Authentication,
    /// Key used for encryption / key agreement.
    Encryption,
    /// Purpose has not been determined.
    #[default]
    Unknown,
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyPurpose::Signing => write!(f, "Signing"),
            KeyPurpose::Authentication => write!(f, "Authentication"),
            KeyPurpose::Encryption => write!(f, "Encryption"),
            KeyPurpose::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(feature = "openpgp-card")]
impl From<KeyType> for KeyPurpose {
    fn from(kt: KeyType) -> Self {
        match kt {
            KeyType::Signing => KeyPurpose::Signing,
            KeyType::Authentication => KeyPurpose::Authentication,
            KeyType::Decryption => KeyPurpose::Encryption,
            _ => KeyPurpose::Unknown,
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guards tests that mutate OPENVTC_MEDIATOR_DID / OPENVTC_ORG_DID env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn all_message_types() -> [MessageType; 11] {
        [
            MessageType::RelationshipRequest,
            MessageType::RelationshipRequestRejected,
            MessageType::RelationshipRequestAccepted,
            MessageType::RelationshipRequestFinalize,
            MessageType::TrustPing,
            MessageType::TrustPong,
            MessageType::VRCRequest,
            MessageType::VRCRequestRejected,
            MessageType::VRCIssued,
            MessageType::MaintainersListRequest,
            MessageType::MaintainersListResponse,
        ]
    }

    #[test]
    fn test_message_type_try_from_valid() {
        use protocol_urls::*;
        let cases = vec![
            (RELATIONSHIP_REQUEST, "RelationshipRequest"),
            (RELATIONSHIP_REQUEST_REJECT, "RelationshipRequestRejected"),
            (RELATIONSHIP_REQUEST_ACCEPT, "RelationshipRequestAccepted"),
            (RELATIONSHIP_REQUEST_FINALIZE, "RelationshipRequestFinalize"),
            (TRUST_PING, "TrustPing"),
            (TRUST_PONG, "TrustPong"),
            (VRC_REQUEST, "VRCRequest"),
            (VRC_REJECTED, "VRCRequestRejected"),
            (VRC_ISSUED, "VRCIssued"),
            (MAINTAINERS_LIST_REQUEST, "MaintainersListRequest"),
            (MAINTAINERS_LIST_RESPONSE, "MaintainersListResponse"),
        ];

        for (url, expected_debug_contains) in cases {
            let mt = MessageType::try_from(url);
            assert!(mt.is_ok(), "Should parse URL '{}' into a MessageType", url);
            let debug_str = format!("{:?}", mt.unwrap());
            assert_eq!(debug_str, expected_debug_contains);
        }
    }

    #[test]
    fn test_message_type_try_from_unknown_yields_invalid_message() {
        let unknown = "https://example.com/not-a-real-openvtc-type";
        let err = MessageType::try_from(unknown).unwrap_err();
        match err {
            errors::OpenVTCError::InvalidMessage(s) => assert_eq!(s, unknown),
            other => panic!("expected InvalidMessage, got {other:?}"),
        }
    }

    #[test]
    fn test_message_type_string_roundtrip_all_variants() {
        for ty in all_message_types() {
            let url: String = ty.clone().into();
            let parsed = MessageType::try_from(url.as_str()).unwrap_or_else(|e| {
                panic!("try_from failed for variant url {url:?}: {e:?}");
            });
            let again: String = parsed.into();
            assert_eq!(url, again, "From<MessageType> and TryFrom drift");
        }
    }

    #[test]
    fn test_message_type_try_from_message() {
        let msg = Message::build(
            "test-id".to_string(),
            String::from(MessageType::TrustPing),
            serde_json::json!({}),
        )
        .finalize();
        let parsed = MessageType::try_from(&msg).expect("valid message type");
        assert_eq!(String::from(parsed), String::from(MessageType::TrustPing));
    }

    #[test]
    fn test_message_type_friendly_names() {
        let cases = [
            (MessageType::RelationshipRequest, "Relationship Request"),
            (
                MessageType::RelationshipRequestRejected,
                "Relationship Request Rejected",
            ),
            (
                MessageType::RelationshipRequestAccepted,
                "Relationship Request Accepted",
            ),
            (
                MessageType::RelationshipRequestFinalize,
                "Relationship Request Finalize",
            ),
            (MessageType::TrustPing, "Trust Ping (Send)"),
            (MessageType::TrustPong, "Trust Pong (Receive)"),
            (MessageType::VRCRequest, "VRC Request"),
            (MessageType::VRCRequestRejected, "VRC Request Rejected"),
            (MessageType::VRCIssued, "VRC Issued"),
            (
                MessageType::MaintainersListRequest,
                "List Known Maintainers (request)",
            ),
            (
                MessageType::MaintainersListResponse,
                "List Known Maintainers (response)",
            ),
        ];
        for (ty, want) in cases {
            assert_eq!(ty.friendly_name(), want);
        }
    }

    #[test]
    fn test_mediator_did_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("OPENVTC_MEDIATOR_DID") };
        let did = mediator_did();
        assert_eq!(did, LF_PUBLIC_MEDIATOR_DID);
        assert!(
            did.starts_with("did:webvh:"),
            "Mediator DID should start with did:webvh:"
        );
    }

    #[test]
    fn test_org_did_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("OPENVTC_ORG_DID") };
        let did = org_did();
        assert_eq!(did, LF_ORG_DID);
        assert!(
            did.starts_with("did:webvh:"),
            "Org DID should start with did:webvh:"
        );
    }

    #[test]
    fn test_mediator_did_valid_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let custom = "did:web:example.com:mediator";
        unsafe { std::env::set_var("OPENVTC_MEDIATOR_DID", custom) };
        let did = mediator_did();
        assert_eq!(did, custom);
        unsafe { std::env::remove_var("OPENVTC_MEDIATOR_DID") };
    }

    #[test]
    fn test_mediator_did_invalid_override_falls_back() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("OPENVTC_MEDIATOR_DID", "not-a-did") };
        let did = mediator_did();
        assert_eq!(
            did, LF_PUBLIC_MEDIATOR_DID,
            "Invalid env value should fall back to default"
        );
        unsafe { std::env::remove_var("OPENVTC_MEDIATOR_DID") };
    }

    #[test]
    fn test_org_did_valid_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let custom = "did:web:example.com:org";
        unsafe { std::env::set_var("OPENVTC_ORG_DID", custom) };
        let did = org_did();
        assert_eq!(did, custom);
        unsafe { std::env::remove_var("OPENVTC_ORG_DID") };
    }

    #[test]
    fn test_org_did_invalid_override_falls_back() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("OPENVTC_ORG_DID", "bogus-value") };
        let did = org_did();
        assert_eq!(
            did, LF_ORG_DID,
            "Invalid env value should fall back to default"
        );
        unsafe { std::env::remove_var("OPENVTC_ORG_DID") };
    }

    #[test]
    fn test_key_purpose_display() {
        assert_eq!(format!("{}", KeyPurpose::Signing), "Signing");
        assert_eq!(format!("{}", KeyPurpose::Authentication), "Authentication");
        assert_eq!(format!("{}", KeyPurpose::Encryption), "Encryption");
        assert_eq!(format!("{}", KeyPurpose::Unknown), "Unknown");
    }

    #[test]
    fn test_key_purpose_default() {
        let kp = KeyPurpose::default();
        assert_eq!(kp, KeyPurpose::Unknown);
    }
}
