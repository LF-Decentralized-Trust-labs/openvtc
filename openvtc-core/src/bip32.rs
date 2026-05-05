//! BIP32 hierarchical deterministic key derivation.
//!
//! Provides helpers for creating a BIP32 master key from a seed and deriving
//! DIDComm-compatible secrets at arbitrary derivation paths.

use crate::{KeyPurpose, errors::OpenVTCError};
use affinidi_tdk::{
    affinidi_crypto::ed25519::ed25519_private_to_x25519, secrets_resolver::secrets::Secret,
};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

/// Creates a BIP32 master (root) key from the given seed bytes.
///
/// # Errors
///
/// Returns [`OpenVTCError::BIP32`] if the seed is invalid or cannot produce a master key.
pub fn get_bip32_root(seed: &[u8]) -> Result<ExtendedSigningKey, OpenVTCError> {
    ExtendedSigningKey::from_seed(seed).map_err(|e| {
        OpenVTCError::BIP32(format!("Couldn't create BIP32 Master Key from seed: {}", e))
    })
}

/// Extension trait for deriving DIDComm secrets from a BIP32 extended signing key.
pub trait Bip32Extension {
    /// Derives a [`Secret`] at the given BIP32 derivation path for the specified key purpose.
    ///
    /// - For [`KeyPurpose::Signing`] or [`KeyPurpose::Authentication`], produces an Ed25519 secret.
    /// - For [`KeyPurpose::Encryption`], converts the derived Ed25519 key to X25519.
    ///
    /// # Errors
    ///
    /// Returns [`OpenVTCError::BIP32`] if the path is invalid or derivation fails,
    /// or [`OpenVTCError::Secret`] if the key purpose is unsupported or X25519 conversion fails.
    fn get_secret_from_path(&self, path: &str, kp: KeyPurpose) -> Result<Secret, OpenVTCError>;
}

impl Bip32Extension for ExtendedSigningKey {
    fn get_secret_from_path(&self, path: &str, kp: KeyPurpose) -> Result<Secret, OpenVTCError> {
        let key = self
            .derive(&path.parse::<DerivationPath>().map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Invalid path ({}) for BIP32 key deriviation: {}",
                    path, e
                ))
            })?)
            .map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Failed to create ed25519 key material from BIP32: {}",
                    e
                ))
            })?;

        let secret = match kp {
            KeyPurpose::Signing | KeyPurpose::Authentication => {
                Secret::generate_ed25519(None, Some(key.signing_key.as_bytes()))
            }
            KeyPurpose::Encryption => {
                let x25519_seed = ed25519_private_to_x25519(key.signing_key.as_bytes());
                Secret::generate_x25519(None, Some(&x25519_seed)).map_err(|e| {
                    OpenVTCError::Secret(format!("Failed to create derived encryption key: {}", e))
                })?
            }
            _ => {
                return Err(OpenVTCError::Secret(format!(
                    "Invalid key purpose used to generate key material ({})",
                    kp
                )));
            }
        };

        Ok(secret)
    }
}

// ****************************************************************************
// Tests
// ****************************************************************************

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;

    const ENTROPY_BYTES: [u8; 32] = [
        7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196, 246,
        58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
    ];

    const MNEMONIC_WORDS: [&str; 24] = [
        "alpha", "stamp", "ridge", "live", "forward", "force", "invite", "charge", "total",
        "smooth", "woman", "hold", "night", "tiny", "suggest", "drum", "goose", "magic", "shell",
        "demise", "icon", "furnace", "hello", "manual",
    ];

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic =
            Mnemonic::from_entropy(&ENTROPY_BYTES).expect("Couldn't create mnemonic from entropy");

        for (index, word) in mnemonic.words().enumerate() {
            assert_eq!(MNEMONIC_WORDS[index], word);
        }
    }

    #[test]
    fn test_recover_mnemonic() {
        let words = MNEMONIC_WORDS.join(" ");
        let mnemonic = Mnemonic::parse_normalized(&words).unwrap();

        assert_eq!(mnemonic.to_entropy(), ENTROPY_BYTES);
    }
}
