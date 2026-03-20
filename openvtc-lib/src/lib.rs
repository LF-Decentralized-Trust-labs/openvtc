/*! Library interface for OpenVTC
 *! Allows for other applications to use the same data structures and routines
*/

use crate::errors::OpenVTCError;
#[cfg(feature = "openpgp-card")]
use ::openpgp_card::ocard::KeyType;
use affinidi_tdk::didcomm::Message;
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod bip32;
pub mod colors;
pub mod config;
pub mod errors;
pub mod logs;
pub mod maintainers;
#[cfg(feature = "openpgp-card")]
pub mod openpgp_card;
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
pub fn mediator_did() -> String {
    std::env::var("OPENVTC_MEDIATOR_DID").unwrap_or_else(|_| LF_PUBLIC_MEDIATOR_DID.to_string())
}

/// Returns the organisation DID, checking the environment variable first.
pub fn org_did() -> String {
    std::env::var("OPENVTC_ORG_DID").unwrap_or_else(|_| LF_ORG_DID.to_string())
}

/// Protocol URL constants for DIDComm message types.
pub mod protocol_urls {
    pub const RELATIONSHIP_REQUEST: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request";
    pub const RELATIONSHIP_REQUEST_REJECT: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-reject";
    pub const RELATIONSHIP_REQUEST_ACCEPT: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-accept";
    pub const RELATIONSHIP_REQUEST_FINALIZE: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-finalize";
    pub const TRUST_PING: &str = "https://didcomm.org/trust-ping/2.0/ping";
    pub const TRUST_PONG: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
    pub const VRC_REQUEST: &str = "https://firstperson.network/vrc/1.0/request";
    pub const VRC_REJECTED: &str = "https://firstperson.network/vrc/1.0/rejected";
    pub const VRC_ISSUED: &str = "https://firstperson.network/vrc/1.0/issued";
    pub const MAINTAINERS_LIST_REQUEST: &str = "https://kernel.org/maintainers/1.0/list";
    pub const MAINTAINERS_LIST_RESPONSE: &str = "https://kernel.org/maintainers/1.0/list/response";
}

/// Defined Message Types for OpenVTC
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MessageType {
    RelationshipRequest,
    RelationshipRequestRejected,
    RelationshipRequestAccepted,
    RelationshipRequestFinalize,
    TrustPing,
    TrustPong,
    VRCRequest,
    VRCRequestRejected,
    VRCIssued,
    MaintainersListRequest,
    MaintainersListResponse,
}

impl MessageType {
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
        value.type_.as_str().try_into()
    }
}

// ****************************************************************************
// Secret Key types and conversions
// ****************************************************************************

/// Tags what the key is used for
#[derive(Default, Debug, PartialEq)]
pub enum KeyPurpose {
    Signing,
    Authentication,
    Encryption,
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
