/*!
*  Secured [crate::config::Config] information that is stored in the OS Secure Storage
*
*  * If using hardware tokens, then the data is encrypted/decrypted using the hardware token
*  * If no hardware token, then may be using a passphrase to protect the data
*  * If no hardware token, and no passphrase, then is in plaintext in the OS Secure Store
*
*  Must intially save bip32_seed first before any keys can be stored
*/

#[cfg(feature = "openpgp-card")]
use crate::config::TokenInteractions;
use crate::{
    config::{Config, KeyBackend, KeyTypes, UnlockCode},
    errors::OpenVTCError,
};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use keyring::Entry;
use rand::rngs::OsRng;
use rand::{SeedableRng, rngs::StdRng};
use secrecy::ExposeSecret;
use sha2::Sha256;
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constants for storing secure info in the OS Secure Store
const SERVICE: &str = "openvtc";

/// Methods of protecting [SecuredConfig]
#[derive(Clone, Debug, Default)]
pub enum ProtectionMethod {
    TokenEncrypted,
    PasswordEncrypted,
    PlainText,
    #[default]
    Unknown,
}

impl From<SecuredConfigFormat> for ProtectionMethod {
    fn from(format: SecuredConfigFormat) -> Self {
        match format {
            SecuredConfigFormat::TokenEncrypted { .. } => ProtectionMethod::TokenEncrypted,
            SecuredConfigFormat::PasswordEncrypted { .. } => ProtectionMethod::PasswordEncrypted,
            SecuredConfigFormat::PlainText { .. } => ProtectionMethod::PlainText,
        }
    }
}

/// Three possible formats to store [SecuredConfig]
/// 1. TokenEncrypted - Encrypted using a hardware token
/// 2. PasswordEncrypted - Encrypted from a derived key from a password/PIN
/// 3. PlainText - No Encryption at all - USE AT YOUR OWN RISK!
///
/// NOTE: All strings are BASE64 encoded
#[derive(Serialize, Deserialize, Debug, Zeroize)]
#[serde(untagged)]
enum SecuredConfigFormat {
    /// Hardware token encrypted data
    TokenEncrypted {
        /// Encrypted Session Key
        esk: String,
        /// Encrypted data using esk
        data: String,
    },

    /// Password/PIN Protected data
    PasswordEncrypted {
        /// Encrypted data using AES-256 from derived key
        data: String,
    },

    /// Plaintext data - dangerous!
    PlainText {
        /// Plaintext data that can be Serialized into [SecuredConfig]
        text: String,
    },
}

impl SecuredConfigFormat {
    /// Loads secret info from the OS Secure Store
    pub fn unlock(
        &self,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<SecuredConfig, OpenVTCError> {
        let raw_bytes = match self {
            SecuredConfigFormat::TokenEncrypted { esk, data } => {
                // Token Encrypted format
                if let Some(token) = token {
                    #[cfg(feature = "openpgp-card")]
                    {
                        use crate::openpgp_card::crypt::token_decrypt;

                        token_decrypt(
                            #[cfg(feature = "openpgp-card")]
                            user_pin,
                            token,
                            &BASE64_URL_SAFE_NO_PAD.decode(esk)?,
                            &BASE64_URL_SAFE_NO_PAD.decode(data)?,
                            touch_prompt,
                        )?
                    }
                    #[cfg(not(feature = "openpgp-card"))]
                    {
                        warn!(
                            "Token has been configured, but no openpgp-card feature-flag has been enabled! exiting..."
                        );
                        return Err(OpenVTCError::Config("Token has been configured, but no openpgp-card feature-flag has been enabled! exiting.".to_string()));
                    }
                } else {
                    warn!(
                        "Secured Config is Token Encrypted, but no token identifier has been provided!"
                    );
                    return Err(OpenVTCError::Config("Secured Config is Token Encrypted, but no token identifier has been provided!".to_string()));
                }
            }
            SecuredConfigFormat::PasswordEncrypted { data } => {
                // Password Encrypted format
                if let Some(unlock) = unlock {
                    unlock_code_decrypt(
                        unlock.0.expose_secret().first_chunk::<32>().unwrap(),
                        &BASE64_URL_SAFE_NO_PAD.decode(data)?,
                    )
                    .map_err(|e| {
                        OpenVTCError::Decrypt(format!(
                            "Couldn't decrypt password encrypted SecuredConfig. Reason: {e}"
                        ))
                    })?
                } else {
                    return Err(OpenVTCError::Config(
                        "Secured Config is Password Encrypted, but no unlock code has been provided!".to_string()
                    ));
                }
            }
            SecuredConfigFormat::PlainText { text } => {
                // Plaintext format - no checks needed

                BASE64_URL_SAFE_NO_PAD.decode(text)?
            }
        };

        Ok(serde_json::from_slice(raw_bytes.as_slice())?)
    }
}

/// Secured Configuration information for openvtc tool
/// Try to keep this as small as possible for ease of secure storage
#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecuredConfig {
    /// base64 encoded BIP32 private seed (legacy - present only for BIP32-based configs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bip32_seed: Option<String>,

    /// base64-encoded CredentialBundle for VTA auth
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_bundle: Option<String>,

    /// VTA service URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,

    /// VTA's DID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,

    /// Key information containing path info
    /// key is the DID VerificationMethod ID
    #[zeroize(skip)] // chrono doesn't support zeroize
    pub key_info: HashMap<String, KeyInfoConfig>,

    #[serde(skip, default)]
    #[zeroize(skip)]
    pub protection_method: ProtectionMethod,
}

impl From<&Config> for SecuredConfig {
    /// Extracts secured/private information from the full Config
    fn from(cfg: &Config) -> Self {
        match &cfg.key_backend {
            KeyBackend::Bip32 { seed, .. } => SecuredConfig {
                bip32_seed: Some(seed.expose_secret().to_owned()),
                credential_bundle: None,
                vta_url: None,
                vta_did: None,
                key_info: cfg.key_info.clone(),
                protection_method: cfg.protection_method.clone(),
            },
            KeyBackend::Vta {
                credential_bundle,
                vta_did,
                vta_url,
                ..
            } => SecuredConfig {
                bip32_seed: None,
                credential_bundle: Some(credential_bundle.expose_secret().to_owned()),
                vta_url: Some(vta_url.clone()),
                vta_did: Some(vta_did.clone()),
                key_info: cfg.key_info.clone(),
                protection_method: cfg.protection_method.clone(),
            },
        }
    }
}

impl SecuredConfig {
    /// Internal private function that saves a SecuredConfig to the OS Secure Store
    /// Encrypts the secret info as needed based on token/unlock parameters
    /// Converts to BASE64 then saves to OS Secure Store
    pub fn save(
        &self,
        profile: &str,
        token: Option<&String>,
        unlock: Option<&Vec<u8>>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &(dyn Fn() + Send + Sync),
    ) -> Result<(), OpenVTCError> {
        let entry = Entry::new(SERVICE, profile).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't open OS Secure Store for profile ({profile}). Reason: {e}"
            ))
        })?;

        // Serialize SecuredConfig to byte array
        let input = serde_json::to_vec(&self)?;

        let formatted = if let Some(token) = token {
            #[cfg(feature = "openpgp-card")]
            {
                use crate::openpgp_card::crypt::token_encrypt;

                let (esk, data) = token_encrypt(token, &input, touch_prompt)?;
                SecuredConfigFormat::TokenEncrypted {
                    esk: BASE64_URL_SAFE_NO_PAD.encode(&esk),
                    data: BASE64_URL_SAFE_NO_PAD.encode(&data),
                }
            }
            #[cfg(not(feature = "openpgp-card"))]
            return Err(OpenVTCError::Config( "Token has been configured, but no openpgp-card feature-flag has been enabled! exiting...".to_string()));
        } else if let Some(unlock) = unlock {
            SecuredConfigFormat::PasswordEncrypted {
                data: BASE64_URL_SAFE_NO_PAD.encode(unlock_code_encrypt(
                    unlock.first_chunk::<32>().unwrap(),
                    &input,
                )?),
            }
        } else {
            // Plain-text
            SecuredConfigFormat::PlainText {
                text: BASE64_URL_SAFE_NO_PAD.encode(input),
            }
        };

        // Save this to the OS Secure Store
        entry
            .set_secret(serde_json::to_string_pretty(&formatted)?.as_bytes())
            .map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't save encrypted config to the OS Secure Store. Reason: {e}"
                ))
            })?;
        Ok(())
    }

    /// Loads secret info from the OS Secure Store
    /// token: Hardware token identifier if being used
    /// unlock: Use a Password/PIN to unlock secret storage if no hardware token
    /// If token is None and unlock is false, assumes no protection apart from the OS Secure Store
    /// itself
    pub fn load(
        profile: &str,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<Self, OpenVTCError> {
        let entry = Entry::new(SERVICE, profile).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't access OS Secure Store for profile ({profile}). Reason: {e}",
            ))
        })?;

        let raw_secured_config: SecuredConfigFormat = match entry.get_secret() {
            Ok(secret) => match serde_json::from_slice(secret.as_slice()) {
                Ok(format) => format,
                Err(e) => {
                    error!(
                        "ERROR: Format of SecuredConfig in OS Secure store is invalid! Reason: {e}"
                    );
                    return Err(OpenVTCError::Config(format!(
                        "Couldn't load openvtc secured configuration. Reason: {e}"
                    )));
                }
            },
            Err(e) => {
                error!("Couldn't find Secure Config in the OS Secret Store. Fatal Error: {e}");
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find openvtc secured configuration. Reason: {e}"
                )));
            }
        };

        raw_secured_config.unlock(
            #[cfg(feature = "openpgp-card")]
            user_pin,
            token,
            unlock,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )
    }
}

/// Information that is required for each key stored
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyInfoConfig {
    /// Where did the keys being used come from?
    /// key: #key-id
    /// value: Derived Path (BIP32 or Imported)
    pub path: KeySourceMaterial,

    /// When wss this key first created?
    #[zeroize(skip)] // chrono doesn't support zeroize
    pub create_time: DateTime<Utc>,

    #[zeroize(skip)]
    #[serde(default)]
    pub purpose: KeyTypes,
}
/// Where did the source for the Key Material come from?
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub enum KeySourceMaterial {
    /// Sourced from BIP32 derivative, Path for this key
    Derived { path: String },

    /// Sourced from an external Key Import
    /// multiencoded private key
    /// Key Material will be stored in the OS Secure Store
    Imported { seed: String },

    /// Managed by VTA service - key_id is VTA's opaque identifier
    /// No derivation paths are stored in openvtc for VTA-managed keys
    VtaManaged { key_id: String },
}

/// AES-256-GCM nonce size in bytes
const NONCE_SIZE: usize = 12;
/// HKDF info label for key derivation (v2 format)
const HKDF_INFO: &[u8] = b"openvtc-key-v2";

/// Derives an AES-256-GCM key from the unlock code and nonce using HKDF-SHA256.
fn derive_key(unlock: &[u8; 32], nonce: &[u8]) -> Result<Aes256Gcm, OpenVTCError> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), unlock);
    let mut key_bytes = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("HKDF key derivation failed: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("Invalid AES key: {e}")))?;
    key_bytes.zeroize();
    Ok(cipher)
}

/// Encrypts data using AES-256-GCM with HKDF-derived key and random nonce.
///
/// Output format: `[12-byte nonce | ciphertext + auth tag]`
pub fn unlock_code_encrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = derive_key(unlock, &nonce)?;

    match cipher.encrypt(&nonce, input) {
        Ok(ciphertext) => {
            let mut result = nonce.to_vec();
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
        Err(e) => {
            error!("Couldn't encrypt data. Reason: {e}");
            Err(OpenVTCError::Encrypt(format!(
                "Couldn't encrypt data. Reason: {e}"
            )))
        }
    }
}

/// Decrypts data using AES-256-GCM with HKDF-derived key.
///
/// Accepts both the new format (`[nonce | ciphertext]`) and the legacy
/// deterministic format for backward compatibility. Existing configs
/// encrypted with the old format will be transparently decrypted and
/// re-encrypted with the secure format on the next save.
pub fn unlock_code_decrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    // Try new format first: first 12 bytes are the random nonce
    if input.len() > NONCE_SIZE {
        let (nonce_bytes, ciphertext) = input.split_at(NONCE_SIZE);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        let cipher = derive_key(unlock, nonce_bytes)?;

        if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext) {
            return Ok(decrypted);
        }
    }

    // Fall back to legacy deterministic format
    legacy_unlock_code_decrypt(unlock, input)
}

/// Legacy decryption using the old deterministic PRNG-based key/nonce derivation.
/// Retained only for backward compatibility with existing encrypted configs.
fn legacy_unlock_code_decrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    let mut rng = StdRng::from_seed(*unlock);
    let key = Aes256Gcm::generate_key(&mut rng);
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    let cipher = Aes256Gcm::new(&key);

    match cipher.decrypt(&nonce, input) {
        Ok(decrypted) => Ok(decrypted),
        Err(e) => {
            error!("Couldn't decrypt data. Likely due to incorrect unlock code! Reason: {e}");
            Err(OpenVTCError::Decrypt(format!(
                "Couldn't decrypt data, likely due to incorrect unlock code! Reason: {e}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let unlock = [42u8; 32];
        let plaintext = b"sensitive data here";

        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_is_non_deterministic() {
        let unlock = [42u8; 32];
        let plaintext = b"same data";

        let cipher1 = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let cipher2 = unlock_code_encrypt(&unlock, plaintext).unwrap();

        assert_ne!(cipher1, cipher2, "Encryption must be non-deterministic");
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let unlock = [42u8; 32];
        let wrong_unlock = [99u8; 32];
        let plaintext = b"secret";

        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        assert!(unlock_code_decrypt(&wrong_unlock, &encrypted).is_err());
    }

    #[test]
    fn test_encrypt_empty_data() {
        let unlock = [42u8; 32];
        let encrypted = unlock_code_encrypt(&unlock, b"").unwrap();
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_large_data() {
        let unlock = [42u8; 32];
        let plaintext = vec![0xABu8; 10_000];

        let encrypted = unlock_code_encrypt(&unlock, &plaintext).unwrap();
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_legacy_format_backward_compatibility() {
        // Encrypt with the legacy deterministic method
        let unlock = [42u8; 32];
        let plaintext = b"legacy data";

        let mut rng = StdRng::from_seed(unlock);
        let key = Aes256Gcm::generate_key(&mut rng);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        let cipher = Aes256Gcm::new(&key);
        let legacy_ciphertext = cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();

        // New decrypt should handle legacy format via fallback
        let decrypted = unlock_code_decrypt(&unlock, &legacy_ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_output_contains_nonce_prefix() {
        let unlock = [42u8; 32];
        let plaintext = b"test";

        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        // Output should be: 12 bytes nonce + ciphertext (plaintext len + 16 byte auth tag)
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + 16);
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let unlock = [42u8; 32];
        let plaintext = b"test data";

        let mut encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        // Corrupt a byte in the ciphertext (after the nonce)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        assert!(unlock_code_decrypt(&unlock, &encrypted).is_err());
    }
}
