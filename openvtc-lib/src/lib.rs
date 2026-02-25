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

/// Primary Linux Foundation Mediator DID
pub const LF_PUBLIC_MEDIATOR_DID: &str =
    "did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator";

/// Primary Linux Foundation Organisation DID
pub const LF_ORG_DID: &str =
    "did:webvh:QmXkYcFCbvFFcYZf2q5gNk8Vp4b4vMbVKWbbc7oivcdZHK:fpp.storm.ws";

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

/// Convert TaskTypes to type string
impl From<MessageType> for String {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::RelationshipRequest => {
                "https://linuxfoundation.org/openvtc/1.0/relationship-request".to_string()
            }
            MessageType::RelationshipRequestRejected => {
                "https://linuxfoundation.org/openvtc/1.0/relationship-request-reject".to_string()
            }
            MessageType::RelationshipRequestAccepted => {
                "https://linuxfoundation.org/openvtc/1.0/relationship-request-accept".to_string()
            }
            MessageType::RelationshipRequestFinalize => {
                "https://linuxfoundation.org/openvtc/1.0/relationship-request-finalize".to_string()
            }
            MessageType::TrustPing => "https://didcomm.org/trust-ping/2.0/ping".to_string(),
            MessageType::TrustPong => {
                "https://didcomm.org/trust-ping/2.0/ping-response".to_string()
            }
            MessageType::VRCRequest => "https://firstperson.network/vrc/1.0/request".to_string(),
            MessageType::VRCRequestRejected => {
                "https://firstperson.network/vrc/1.0/rejected".to_string()
            }
            MessageType::VRCIssued => "https://firstperson.network/vrc/1.0/issued".to_string(),
            MessageType::MaintainersListRequest => {
                "https://kernel.org/maintainers/1.0/list".to_string()
            }
            MessageType::MaintainersListResponse => {
                "https://kernel.org/maintainers/1.0/list/response".to_string()
            }
        }
    }
}

/// Convert &str to a MessageType based on type URL
impl TryFrom<&str> for MessageType {
    type Error = OpenVTCError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "https://linuxfoundation.org/openvtc/1.0/relationship-request" => {
                Ok(MessageType::RelationshipRequest)
            }
            "https://linuxfoundation.org/openvtc/1.0/relationship-request-reject" => {
                Ok(MessageType::RelationshipRequestRejected)
            }
            "https://linuxfoundation.org/openvtc/1.0/relationship-request-accept" => {
                Ok(MessageType::RelationshipRequestAccepted)
            }
            "https://linuxfoundation.org/openvtc/1.0/relationship-request-finalize" => {
                Ok(MessageType::RelationshipRequestFinalize)
            }
            "https://didcomm.org/trust-ping/2.0/ping" => Ok(MessageType::TrustPing),
            "https://didcomm.org/trust-ping/2.0/ping-response" => Ok(MessageType::TrustPong),
            "https://firstperson.network/vrc/1.0/request" => Ok(MessageType::VRCRequest),
            "https://firstperson.network/vrc/1.0/rejected" => Ok(MessageType::VRCRequestRejected),
            "https://firstperson.network/vrc/1.0/issued" => Ok(MessageType::VRCIssued),
            "https://kernel.org/maintainers/1.0/list" => Ok(MessageType::MaintainersListRequest),
            "https://kernel.org/maintainers/1.0/list/response" => {
                Ok(MessageType::MaintainersListResponse)
            }
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
