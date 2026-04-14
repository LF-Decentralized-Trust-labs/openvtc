/*! Contains the OpenVTC CLI Tool Configuration
*
* Configuration is spread across four different contexts:
* 1. [Config]: Represents the active in-memory application config
* 2. [secured_config::SecuredConfig]: Represents [Config] info that is stored securely (key info)
* 3. [public_config::PublicConfig]: Represents [Config] info that is stored in plaintext on disk
* 4. [protected_config::ProtectedConfig]: Represents [Config] info that is encryoted and stored on disk
*
* NOTE: Secure Config information is saved item by item as needed to the secure storage
*/

use crate::{
    config::{
        protected_config::ProtectedConfig,
        secured_config::{KeyInfoConfig, KeySourceMaterial, ProtectionMethod},
    },
    errors::OpenVTCError,
};
use affinidi_tdk::{
    did_common::Document, messaging::profiles::ATMProfile, secrets_resolver::secrets::Secret,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, TimeDelta, Utc};
use dtg_credentials::DTGCredential;
use ed25519_dalek_bip32::ExtendedSigningKey;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt::Display, sync::Arc};

pub mod did;
pub mod keys;
pub mod loading;
pub mod protected_config;
pub mod public_config;
pub mod saving;
pub mod secured_config;

// Re-export from sub-modules so external import paths remain unchanged
pub use keys::secret_from_vta_response;

/// Derives a 32-byte key from a user-provided passphrase using Argon2id.
///
/// Uses Argon2id (RFC 9106) with a domain-specific salt derived from `info`.
/// This provides strong resistance against brute-force and GPU-based attacks
/// on user-chosen passphrases.
///
/// # Parameters
///
/// - `passphrase`: The user-provided passphrase bytes.
/// - `info`: A domain-separation label (e.g., `b"openvtc-unlock-code-v1"`).
///   Different labels produce different keys from the same passphrase.
///
/// # Errors
///
/// Returns an error if Argon2 key derivation fails (e.g., memory allocation).
///
/// # Examples
///
/// ```
/// use openvtc::config::derive_passphrase_key;
///
/// let key1 = derive_passphrase_key(b"my-passphrase", b"context-a").unwrap();
/// let key2 = derive_passphrase_key(b"my-passphrase", b"context-b").unwrap();
///
/// // Same passphrase with different context produces different keys
/// assert_ne!(key1, key2);
///
/// // Deterministic for the same inputs
/// let key3 = derive_passphrase_key(b"my-passphrase", b"context-a").unwrap();
/// assert_eq!(key1, key3);
/// ```
pub fn derive_passphrase_key(passphrase: &[u8], info: &[u8]) -> Result<[u8; 32], OpenVTCError> {
    // Use a deterministic salt derived from the info label.
    // This provides domain separation so the same passphrase produces different
    // keys for different purposes, while remaining deterministic for the same inputs.
    let salt = Sha256::digest(info);
    let mut key = [0u8; 32];
    // Argon2id with explicit hardened parameters (OWASP recommendations):
    // - 64 MiB memory cost (strong GPU resistance)
    // - 3 iterations (increased from default 2)
    // - 1 lane (single-threaded, acceptable for interactive use)
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| OpenVTCError::Config(format!("Invalid Argon2 parameters: {e}")))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, &salt, &mut key)
        .map_err(|e| OpenVTCError::Config(format!("Argon2 key derivation failed: {e}")))?;
    Ok(key)
}

/// Minimum passphrase length for unlock codes and export passphrases.
pub const MIN_PASSPHRASE_LENGTH: usize = 8;

/// Validates that a passphrase meets minimum strength requirements.
///
/// Returns `Ok(())` if the passphrase is at least [`MIN_PASSPHRASE_LENGTH`] characters.
pub fn validate_passphrase(passphrase: &str) -> Result<(), OpenVTCError> {
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(OpenVTCError::Config(format!(
            "Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters (got {})",
            passphrase.len()
        )));
    }
    Ok(())
}

/// A 32-byte symmetric key derived from a user-provided passphrase via Argon2id.
/// Used to encrypt/decrypt the secured configuration on disk.
pub struct UnlockCode(pub(crate) SecretBox<Vec<u8>>);

impl UnlockCode {
    /// Derives an unlock code from a plaintext passphrase string using Argon2id.
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is shorter than [`MIN_PASSPHRASE_LENGTH`].
    pub fn from_string(s: &str) -> Result<Self, OpenVTCError> {
        validate_passphrase(s)?;
        let key = derive_passphrase_key(s.as_bytes(), b"openvtc-unlock-code-v1")?;
        Ok(UnlockCode(SecretBox::new(Box::new(key.to_vec()))))
    }
}

/// Describes how the configuration secrets are protected at rest.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub enum ConfigProtectionType {
    /// Requires a hardware token with the Token ID to unlock config
    /// Will need to provide the USER PIN to the token
    Token(String),

    /// Requires an unlock passphrase to unlock config
    /// Will need to provide the unlock passphrase
    #[default]
    Encrypted,

    /// Is not encrypted in any way
    Plaintext,
}

#[cfg(feature = "openpgp-card")]
/// Callback trait for hardware token (e.g. YubiKey) user interaction.
///
/// Implementors receive notifications before and after the token may require
/// a physical touch, allowing the UI to prompt the user accordingly.
pub trait TokenInteractions: Send + Sync {
    /// Called before the token may require a physical touch from the user.
    fn touch_notify(&self);

    /// Called after the token operation has completed.
    fn touch_completed(&self);
}

/// The key backend determines how cryptographic keys are stored and managed.
///
/// Either keys are derived locally from a BIP32 seed, or they are managed
/// remotely by a Verifiable Trust Authority (VTA) service.
pub enum KeyBackend {
    /// Legacy BIP32 hierarchical-deterministic key derivation from a local seed.
    Bip32 {
        /// The BIP32 extended signing key root, derived from the seed.
        root: ExtendedSigningKey,
        /// The base64url-encoded seed material (kept in secret memory).
        seed: SecretString,
    },
    /// Keys are managed remotely by a VTA service and fetched on demand.
    Vta {
        /// Encoded VTA credential bundle for authentication.
        credential_bundle: SecretString,
        /// DID associated with the VTA credential.
        credential_did: String,
        /// Private key multibase string for signing VTA challenge-response.
        credential_private_key: SecretString,
        /// DID of the VTA service itself.
        vta_did: String,
        /// Base URL of the VTA service.
        vta_url: String,
        /// SHA-256 hash of the private key multibase, used as the encryption seed
        /// for `ProtectedConfig` (replaces BIP32 `m/0'/0'/0'` in the VTA flow).
        encryption_seed: SecretBox<Vec<u8>>,
    },
}

impl std::fmt::Debug for KeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyBackend::Bip32 { .. } => f.debug_struct("KeyBackend::Bip32").finish_non_exhaustive(),
            KeyBackend::Vta {
                credential_did,
                vta_did,
                vta_url,
                ..
            } => f
                .debug_struct("KeyBackend::Vta")
                .field("credential_did", credential_did)
                .field("vta_did", vta_did)
                .field("vta_url", vta_url)
                .finish_non_exhaustive(),
        }
    }
}

/// Configuration information for openvtc tool
/// This is the active configuration used by the application itself
/// When you want to load/save this configuration, it will become:
/// 1. [public_config::PublicConfig]: Configuration information that is saved to disk
/// 2. [secured_config::SecuredConfig]: Configuration information that is encrypted and saved to secure storage
#[derive(Debug)]
pub struct Config {
    /// Public readable config items when saved to disk
    pub public: public_config::PublicConfig,

    /// Private sensitive config items which are encrypted on disk
    pub private: ProtectedConfig,

    /// Key backend - either local BIP32 or VTA-managed
    pub key_backend: KeyBackend,

    /// Where did the key values come from? Derived or Imported?
    pub key_info: HashMap<String, KeyInfoConfig>,

    /// Persona DID and Document
    pub persona_did: PersonaDID,

    // *********************************************
    // Temporary Config values
    /// What protection method is being used for the secured config.
    pub protection_method: ProtectionMethod,

    /// Hardware token Admin PIN
    #[cfg(feature = "openpgp-card")]
    pub token_admin_pin: Option<SecretString>,

    /// Hardware token User PIN
    #[cfg(feature = "openpgp-card")]
    pub token_user_pin: SecretString,

    /// Unlock code if required
    pub unlock_code: Option<Vec<u8>>,

    /// Holds ATM profiles for relationships
    /// Key: Our local DID for the relationship
    /// NOTE: Does not hold the persona DID profile!
    pub atm_profiles: HashMap<Arc<String>, Arc<ATMProfile>>,

    /// All VRC's issued and received by VRC ID
    /// Key: VRC ID
    pub vrcs: HashMap<Arc<String>, Arc<DTGCredential>>,
}

/// Serializable bundle of public and secured config, used for import/export.
#[derive(Deserialize, Serialize)]
pub struct ExportedConfig {
    /// The public (plaintext) portion of the configuration.
    pub pc: public_config::PublicConfig,
    /// The secured (secret key material) portion of the configuration.
    pub sc: secured_config::SecuredConfig,
}

/// Our public Persona DID used to identify ourselves within the Linux Foundation ecosystem
#[derive(Clone, Debug)]
pub struct PersonaDID {
    /// Resolved DID Document for this DID
    pub document: Document,

    /// Messaging Profile representing this DID within the TDK
    pub profile: Arc<ATMProfile>,
}

impl Config {
    /// Returns the 32-byte encryption seed used to encrypt/decrypt `ProtectedConfig`.
    ///
    /// For `Bip32` backends, this derives the seed from path `m/0'/0'/0'`.
    /// For `Vta` backends, this returns the pre-computed SHA-256 hash of the private key.
    pub fn get_encryption_seed(&self) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
        match &self.key_backend {
            KeyBackend::Bip32 { root, .. } => ProtectedConfig::get_seed(root, "m/0'/0'/0'"),
            KeyBackend::Vta {
                encryption_seed, ..
            } => Ok(SecretBox::new(Box::new(
                encryption_seed.expose_secret().to_vec(),
            ))),
        }
    }
}

// ****************************************************************************
// Key Types
// ****************************************************************************

/// Classifies how a cryptographic key is used within the OpenVTC system.
#[derive(Clone, Serialize, Default, Deserialize, Debug)]
pub enum KeyTypes {
    /// Ed25519 key used for signing assertions on the persona DID.
    PersonaSigning,
    /// Ed25519 key used for authenticating the persona DID.
    PersonaAuthentication,
    /// X25519 key used for encryption on the persona DID.
    PersonaEncryption,
    /// Other persona-level key not fitting the above categories.
    PersonaOther,
    /// Ed25519 verification key bound to a specific relationship DID.
    RelationshipVerification,
    /// X25519 encryption key bound to a specific relationship DID.
    RelationshipEncryption,
    /// Key used for managing (updating) a `did:webvh` DID log.
    WebVHManagement,
    /// Key purpose has not been determined.
    #[default]
    Unknown,
}

impl Display for KeyTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyTypes::PersonaSigning => "Persona Signing Key",
            KeyTypes::PersonaAuthentication => "Persona Authentication Key",
            KeyTypes::PersonaEncryption => "Persona Encryption Key",
            KeyTypes::PersonaOther => "Persona Other Key",
            KeyTypes::RelationshipVerification => "Relationship Verification Key",
            KeyTypes::RelationshipEncryption => "Relationship Encryption Key",
            KeyTypes::WebVHManagement => "Web VH Management Key",
            KeyTypes::Unknown => "Unknown Key Type",
        };
        write!(f, "{}", s)
    }
}

/// Secrets for the Persona DID.
///
/// Implements [`Drop`] to zeroize contained key material when the struct goes out of scope.
#[derive(Clone)]
pub struct PersonaDIDKeys {
    pub signing: KeyInfo,
    pub authentication: KeyInfo,
    pub decryption: KeyInfo,
}

impl std::fmt::Debug for PersonaDIDKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersonaDIDKeys")
            .field("signing", &"[REDACTED]")
            .field("authentication", &"[REDACTED]")
            .field("decryption", &"[REDACTED]")
            .finish()
    }
}

/// Contains relevant key information required for setting up, configuring and managing keys.
///
/// Implements [`Drop`] to zeroize contained key material when the struct goes out of scope.
#[derive(Clone)]
pub struct KeyInfo {
    /// Secret Key Material that can be used within the TDK environment
    pub secret: Secret,
    /// Where did this key come from? Derived from BIP32 or Imported?
    pub source: KeySourceMaterial,

    /// Section 5.5.2 of RFC 4880 - Expiry time if set is # of days since creation
    pub expiry: Option<TimeDelta>,
    pub created: DateTime<Utc>,
}

impl std::fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyInfo")
            .field("secret", &"[REDACTED]")
            .field("source", &self.source)
            .field("expiry", &self.expiry)
            .field("created", &self.created)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_derive_passphrase_key_deterministic() {
        let key1 = derive_passphrase_key(b"my-passphrase", b"info-label").unwrap();
        let key2 = derive_passphrase_key(b"my-passphrase", b"info-label").unwrap();
        assert_eq!(key1, key2, "Same inputs must produce the same derived key");
    }

    #[test]
    fn test_derive_passphrase_key_different_info_differs() {
        let key_a = derive_passphrase_key(b"same-passphrase", b"info-a").unwrap();
        let key_b = derive_passphrase_key(b"same-passphrase", b"info-b").unwrap();
        assert_ne!(
            key_a, key_b,
            "Different info labels must produce different keys"
        );
    }

    #[test]
    fn test_derive_passphrase_key_different_passphrase_differs() {
        let key_a = derive_passphrase_key(b"passphrase-one", b"same-info").unwrap();
        let key_b = derive_passphrase_key(b"passphrase-two", b"same-info").unwrap();
        assert_ne!(
            key_a, key_b,
            "Different passphrases must produce different keys"
        );
    }

    #[test]
    fn test_unlock_code_from_string_deterministic() {
        let uc1 = UnlockCode::from_string("my-unlock-phrase").unwrap();
        let uc2 = UnlockCode::from_string("my-unlock-phrase").unwrap();
        assert_eq!(
            uc1.0.expose_secret(),
            uc2.0.expose_secret(),
            "Same input string must produce the same unlock code"
        );
    }

    #[test]
    fn test_unlock_code_from_string_different_inputs_differ() {
        let uc1 = UnlockCode::from_string("phrase-alpha-long").unwrap();
        let uc2 = UnlockCode::from_string("phrase-beta-long").unwrap();
        assert_ne!(
            uc1.0.expose_secret(),
            uc2.0.expose_secret(),
            "Different input strings must produce different unlock codes"
        );
    }

    #[test]
    fn test_unlock_code_rejects_short_passphrase() {
        assert!(
            UnlockCode::from_string("short").is_err(),
            "Passphrase shorter than MIN_PASSPHRASE_LENGTH should be rejected"
        );
    }

    #[test]
    fn test_validate_passphrase_minimum_length() {
        assert!(validate_passphrase("12345678").is_ok());
        assert!(validate_passphrase("1234567").is_err());
        assert!(validate_passphrase("").is_err());
    }
}
