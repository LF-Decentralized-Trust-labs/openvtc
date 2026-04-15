//! Common error types for the OpenVTC library.
//!
//! All fallible operations in the crate return [`OpenVTCError`] so that callers
//! can match on specific failure categories.

use affinidi_data_integrity::DataIntegrityError;
use affinidi_tdk::{common::errors::TDKError, didcomm, messaging::errors::ATMError};
use didwebvh_rs::DIDWebVHError;
use thiserror::Error;

/// Unified error type for all OpenVTC operations.
#[derive(Error, Debug)]
pub enum OpenVTCError {
    /// An unrecognised DIDComm message type URL was encountered.
    #[error("Invalid Message Type: {0}")]
    InvalidMessage(String),

    /// A required secret key could not be found in the secrets resolver.
    #[error("Missing Secret Key Material. Key-ID: {0}")]
    MissingSecretKeyMaterial(String),

    /// JSON serialization or deserialization failed.
    #[error("Serialize/Deserialize Error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A data-integrity proof operation failed.
    #[error("DataIntegrityProof Error: {0}")]
    DataIntegrityProof(#[from] DataIntegrityError),

    /// An error from the Affinidi Trusted Messaging (ATM) layer.
    #[error("ATM Error: {0}")]
    ATM(#[from] ATMError),

    /// A DIDComm protocol-level error.
    #[error("DIDComm Error: {0}")]
    DIDComm(#[from] didcomm::DIDCommError),

    /// A BIP32 key derivation error.
    #[error("BIP32 Error: {0}")]
    BIP32(String),

    /// An error related to secret key material (creation, decoding, etc.).
    #[error("Key Secret Error: {0}")]
    Secret(String),

    /// Base64 decoding failed.
    #[error("BASE64 Decode Error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// DID resolution failed.
    #[error("DID Resolver Error: {0}")]
    Resolver(String),

    /// A general configuration error.
    #[error("Config Error: {0}")]
    Config(String),

    /// The configuration file could not be found at the expected path.
    #[error("Config Not Found! path({0}): {1}")]
    ConfigNotFound(String, std::io::Error),

    /// An error from a hardware security token (e.g. OpenPGP card / YubiKey).
    #[cfg(feature = "openpgp-card")]
    #[error("Token Error: {0}")]
    Token(String),

    /// The PIN provided to the hardware token was incorrect.
    #[cfg(feature = "openpgp-card")]
    #[error("Token Bad Pin")]
    TokenBadPin,

    /// Symmetric encryption failed.
    #[error("Encrypt Error: {0}")]
    Encrypt(String),

    /// Symmetric decryption failed.
    #[error("Decrypt Error: {0}")]
    Decrypt(String),

    /// A contacts/address-book operation failed.
    #[error("Contacts Error: {0}")]
    Contact(String),

    /// An error from the `did:webvh` DID method library.
    #[error("WebVH DID error: {0}")]
    WebVH(#[from] DIDWebVHError),

    /// An error from the TDK (Trust Development Kit) layer.
    #[error("TDK error: {0}")]
    TDK(#[from] TDKError),

    /// A `Mutex` was found in a poisoned state.
    #[error("Mutex poisoned: {0}")]
    MutexPoisoned(String),

    /// Another instance of openvtc is already running for this profile.
    #[error("Duplicate instance running for profile '{0}'")]
    DuplicateInstance(String),

    /// A process lock-file operation (create, read, or remove) failed.
    #[error("Lock file error: {0}")]
    LockFile(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages_are_meaningful() {
        let cases: Vec<Box<dyn std::fmt::Display>> = vec![
            Box::new(OpenVTCError::InvalidMessage("bad msg".into())),
            Box::new(OpenVTCError::MissingSecretKeyMaterial("key-1".into())),
            Box::new(OpenVTCError::BIP32("derivation failed".into())),
            Box::new(OpenVTCError::Secret("missing seed".into())),
            Box::new(OpenVTCError::Resolver("timeout".into())),
            Box::new(OpenVTCError::Config("not found".into())),
            Box::new(OpenVTCError::ConfigNotFound(
                "/tmp/missing".into(),
                std::io::Error::new(std::io::ErrorKind::NotFound, "no file"),
            )),
            Box::new(OpenVTCError::Encrypt("aes failure".into())),
            Box::new(OpenVTCError::Decrypt("bad key".into())),
            Box::new(OpenVTCError::Contact("unknown".into())),
            Box::new(OpenVTCError::MutexPoisoned("lock failed".into())),
        ];

        for err in &cases {
            let msg = format!("{}", err);
            assert!(!msg.is_empty(), "Error display message should not be empty");
        }
    }

    #[test]
    fn test_error_display_contains_inner_message() {
        let err = OpenVTCError::Config("something went wrong".to_string());
        let msg = format!("{}", err);
        assert!(
            msg.contains("something went wrong"),
            "Display should include the inner message, got: {}",
            msg
        );
    }

    #[test]
    fn test_error_debug_is_nonempty() {
        let err = OpenVTCError::BIP32("test".into());
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty(), "Debug output should not be empty");
    }
}
