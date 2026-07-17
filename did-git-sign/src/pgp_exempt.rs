//! Exemption keyring for platform-signed commits.
//!
//! GitHub signs the commits it creates itself — web-UI merge and squash
//! commits, Dependabot commits — with **PGP** (its `web-flow` key), not with
//! a contributor's sshsig. Those commits can never carry a DID signature, so
//! a repository that wants `verify-trust` as a required check needs a policy
//! for them.
//!
//! The policy here is cryptographic, never name-based: the repository commits
//! an armored keyring of explicitly trusted platform keys (e.g. the key from
//! <https://github.com/web-flow.gpg>), and a PGP-signed commit passes only if
//! its signature verifies against one of those keys. Committer names and
//! emails are attacker-chosen strings and play no part. With no keyring
//! configured, every PGP-signed commit fails — absence of configuration is
//! the most restrictive interpretation.
//!
//! Verification is pure Rust (rPGP); no `gpg` binary is involved.

use anyhow::{Context, Result, bail};
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;
use std::path::Path;

/// An armored set of platform keys whose signatures exempt a commit from the
/// DID-signature requirement.
pub struct ExemptKeyring {
    keys: Vec<SignedPublicKey>,
}

impl ExemptKeyring {
    /// Parse an armored keyring: either one armor block holding several keys
    /// (`gpg --export --armor keyA keyB`) or several armor blocks
    /// concatenated (`cat a.asc b.asc`).
    pub fn from_armored(text: &str) -> Result<Self> {
        const BLOCK_START: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
        let mut keys = Vec::new();
        for block in text.split(BLOCK_START).skip(1) {
            let block = format!("{BLOCK_START}{block}");
            let (parsed, _headers) = SignedPublicKey::from_string_many(&block)
                .context("exempt keyring did not parse")?;
            keys.extend(
                parsed
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("exempt keyring contains an invalid key")?,
            );
        }
        if keys.is_empty() {
            bail!("exempt keyring contains no keys");
        }
        Ok(Self { keys })
    }

    /// Load a keyring file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read exempt keyring {}", path.display()))?;
        Self::from_armored(&text)
    }

    /// Verify a detached, armored PGP signature over `payload` against the
    /// keyring. Returns the hex fingerprint of the matching primary key, or a
    /// description of why nothing matched.
    pub fn verify(&self, armored_signature: &str, payload: &[u8]) -> Result<String, String> {
        let (signature, _headers) = DetachedSignature::from_string(armored_signature)
            .map_err(|e| format!("PGP signature did not parse: {e}"))?;

        for key in &self.keys {
            let fingerprint = hex::encode(key.primary_key.fingerprint().as_bytes());
            if signature.verify(key, payload).is_ok() {
                return Ok(fingerprint);
            }
            for subkey in &key.public_subkeys {
                if signature.verify(subkey, payload).is_ok() {
                    return Ok(fingerprint);
                }
            }
        }
        Err("signature matches no key in the exempt keyring".to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use pgp::composed::{ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedSecretKey};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::types::Password;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn test_key(seed: u64, user: &str) -> SignedSecretKey {
        let mut rng = StdRng::seed_from_u64(seed);
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .primary_user_id(user.to_string())
            .build()
            .unwrap()
            .generate(&mut rng)
            .unwrap()
    }

    fn armored_public(key: &SignedSecretKey) -> String {
        SignedPublicKey::from(key.clone())
            .to_armored_string(ArmorOptions::default())
            .unwrap()
    }

    fn sign(key: &SignedSecretKey, payload: &[u8]) -> String {
        let mut rng = StdRng::seed_from_u64(42);
        DetachedSignature::sign_binary_data(
            &mut rng,
            &key.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            payload,
        )
        .unwrap()
        .to_armored_string(ArmorOptions::default())
        .unwrap()
    }

    #[test]
    fn signature_by_a_keyring_key_is_exempt() {
        let key = test_key(1, "platform@example.com");
        let keyring = ExemptKeyring::from_armored(&armored_public(&key)).unwrap();
        let payload = b"tree abc\n\nmerge commit";

        let fingerprint = keyring.verify(&sign(&key, payload), payload).unwrap();
        assert_eq!(
            fingerprint,
            hex::encode(key.primary_key.fingerprint().as_bytes())
        );
    }

    #[test]
    fn signature_by_an_unknown_key_is_rejected() {
        let trusted = test_key(1, "platform@example.com");
        let attacker = test_key(2, "attacker@example.com");
        let keyring = ExemptKeyring::from_armored(&armored_public(&trusted)).unwrap();
        let payload = b"tree abc\n\nmerge commit";

        assert!(keyring.verify(&sign(&attacker, payload), payload).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = test_key(1, "platform@example.com");
        let keyring = ExemptKeyring::from_armored(&armored_public(&key)).unwrap();
        let signature = sign(&key, b"original payload");

        assert!(keyring.verify(&signature, b"tampered payload").is_err());
    }

    #[test]
    fn multi_key_keyring_matches_any_member() {
        let a = test_key(1, "a@example.com");
        let b = test_key(2, "b@example.com");
        let both = format!("{}{}", armored_public(&a), armored_public(&b));
        let keyring = ExemptKeyring::from_armored(&both).unwrap();
        let payload = b"payload";

        assert!(keyring.verify(&sign(&b, payload), payload).is_ok());
    }

    #[test]
    fn empty_or_garbage_keyring_is_a_hard_error() {
        assert!(ExemptKeyring::from_armored("").is_err());
        assert!(ExemptKeyring::from_armored("not a keyring").is_err());
    }
}
