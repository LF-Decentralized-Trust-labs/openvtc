/*! Common error types for OpenVTC
*/

use affinidi_data_integrity::DataIntegrityError;
use affinidi_tdk::{common::errors::TDKError, didcomm, messaging::errors::ATMError};
use didwebvh_rs::DIDWebVHError;
use thiserror::Error;

/// First Person Protocol Errors
#[derive(Error, Debug)]
pub enum OpenVTCError {
    #[error("Invalid Message Type: {0}")]
    InvalidMessage(String),

    #[error("Missing Secret Key Material. Key-ID: {0}")]
    MissingSecretKeyMaterial(String),

    #[error("Serialize/Deserialize Error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("DataIntegrityProof Error: {0}")]
    DataIntegrityProof(#[from] DataIntegrityError),

    #[error("ATM Error: {0}")]
    ATM(#[from] ATMError),

    #[error("DIDComm Error: {0}")]
    DIDComm(#[from] didcomm::error::Error),

    #[error("BIP32 Error: {0}")]
    BIP32(String),

    #[error("Key Secret Error: {0}")]
    Secret(String),

    #[error("BASE64 Decode Error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("DID Resolver Error: {0}")]
    Resolver(String),

    #[error("Config Error: {0}")]
    Config(String),

    #[error("Config Not Found! path({0}")]
    ConfigNotFound(String, std::io::Error),

    #[cfg(feature = "openpgp-card")]
    #[error("Token Error: {0}")]
    Token(String),

    #[cfg(feature = "openpgp-card")]
    #[error("Token Bad Pin")]
    TokenBadPin,

    #[error("Encrypt Error: {0}")]
    Encrypt(String),

    #[error("Decrypt Error: {0}")]
    Decrypt(String),

    #[error("Contacts Error: {0}")]
    Contact(String),

    #[error("WebVH DID error: {0}")]
    WebVH(#[from] DIDWebVHError),

    #[error("TDK error: {0}")]
    TDK(#[from] TDKError),
}
