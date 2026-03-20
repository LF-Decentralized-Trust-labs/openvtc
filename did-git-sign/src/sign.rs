use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};
use std::io::Read;
use std::path::Path;

use crate::config::SigningConfig;
use crate::vta;

/// Magic preamble for SSH signatures (PROTOCOL.sshsig)
const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";

/// Handle the signing invocation from git.
/// Git calls: did-git-sign -Y sign -f <config_path> -n <namespace>
/// Data to sign comes on stdin; armored SSH signature goes to stdout.
pub async fn handle_sign(config_path: &Path, namespace: &str) -> Result<()> {
    // Read data to sign from stdin
    let mut data = Vec::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .context("failed to read data from stdin")?;

    // Load config
    let cfg = SigningConfig::load(config_path)?;

    // Authenticate with VTA and fetch signing key
    let (client, creds) = vta::authenticate(&cfg).await?;
    let seed = vta::get_signing_key(&client, &creds.key_id).await?;

    // Create Ed25519 signing key from seed
    let signing_key = SigningKey::from_bytes(seed.as_bytes());
    let verifying_key = signing_key.verifying_key();

    // Build the SSH signature
    let signature = create_ssh_signature(&signing_key, &verifying_key, namespace, &data)?;

    // Output armored signature to stdout
    print!("{signature}");

    Ok(())
}

/// Create an armored SSH signature following the PROTOCOL.sshsig format.
///
/// The signed data structure is:
///   MAGIC_PREAMBLE (6 bytes: "SSHSIG")
///   namespace (string)
///   reserved (empty string)
///   hash_algorithm (string: "sha512")
///   H(message) (string: SHA-512 hash of the message)
///
/// The signature blob structure is:
///   MAGIC_PREAMBLE
///   version (uint32: 1)
///   publickey (SSH wire format)
///   namespace (string)
///   reserved (empty string)
///   hash_algorithm (string)
///   signature (SSH wire format)
fn create_ssh_signature(
    signing_key: &SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    namespace: &str,
    message: &[u8],
) -> Result<String> {
    use ed25519_dalek::Signer;

    // Hash the message with SHA-512
    let message_hash = Sha512::digest(message);

    // Build the data to sign (PROTOCOL.sshsig §4)
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(SSHSIG_MAGIC);
    write_ssh_string(&mut signed_data, namespace.as_bytes());
    write_ssh_string(&mut signed_data, b""); // reserved
    write_ssh_string(&mut signed_data, b"sha512");
    write_ssh_string(&mut signed_data, &message_hash);

    // Sign the structured data
    let sig = signing_key.sign(&signed_data);

    // Build the public key in SSH wire format
    let pubkey_blob = encode_ssh_ed25519_pubkey(verifying_key);

    // Build the signature blob in SSH wire format
    let sig_blob = encode_ssh_ed25519_signature(&sig);

    // Build the full SSHSIG blob
    let mut sshsig_blob = Vec::new();
    sshsig_blob.extend_from_slice(SSHSIG_MAGIC);
    write_u32(&mut sshsig_blob, 1); // version
    write_ssh_string(&mut sshsig_blob, &pubkey_blob); // publickey
    write_ssh_string(&mut sshsig_blob, namespace.as_bytes()); // namespace
    write_ssh_string(&mut sshsig_blob, b""); // reserved
    write_ssh_string(&mut sshsig_blob, b"sha512"); // hash algorithm
    write_ssh_string(&mut sshsig_blob, &sig_blob); // signature

    // Armor with PEM-style headers
    // Note: base64 output is always valid ASCII/UTF-8, so from_utf8 cannot fail here.
    let b64 = base64_encode(&sshsig_blob);
    let mut armored = String::new();
    armored.push_str("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(76) {
        armored.push_str(
            std::str::from_utf8(chunk).expect("base64 output is always valid UTF-8"),
        );
        armored.push('\n');
    }
    armored.push_str("-----END SSH SIGNATURE-----\n");

    Ok(armored)
}

/// Encode an Ed25519 public key in SSH wire format:
///   string "ssh-ed25519"
///   string <32-byte public key>
fn encode_ssh_ed25519_pubkey(key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let mut buf = Vec::new();
    write_ssh_string(&mut buf, b"ssh-ed25519");
    write_ssh_string(&mut buf, key.as_bytes());
    buf
}

/// Encode an Ed25519 signature in SSH wire format:
///   string "ssh-ed25519"
///   string <64-byte signature>
fn encode_ssh_ed25519_signature(sig: &ed25519_dalek::Signature) -> Vec<u8> {
    let mut buf = Vec::new();
    write_ssh_string(&mut buf, b"ssh-ed25519");
    write_ssh_string(&mut buf, &sig.to_bytes());
    buf
}

/// Write a uint32 in big-endian.
fn write_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Write an SSH "string" (uint32 length prefix + raw bytes).
fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    write_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

/// Test that signing works by creating a signature and verifying the output format.
/// Used by the `verify` subcommand.
pub fn test_sign(
    signing_key: &SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    data: &[u8],
) -> Result<()> {
    let signature = create_ssh_signature(signing_key, verifying_key, "git", data)?;
    if !signature.starts_with("-----BEGIN SSH SIGNATURE-----") {
        anyhow::bail!("signature output has invalid format");
    }
    Ok(())
}

/// Base64-encode without line wrapping (we handle wrapping separately).
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_string_encoding() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"ssh-ed25519");
        assert_eq!(buf.len(), 4 + 11);
        assert_eq!(&buf[..4], &[0, 0, 0, 11]);
        assert_eq!(&buf[4..], b"ssh-ed25519");
    }

    #[test]
    fn test_pubkey_blob_format() {
        let seed = [0u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let blob = encode_ssh_ed25519_pubkey(&verifying_key);
        // "ssh-ed25519" (4+11) + pubkey (4+32) = 51 bytes
        assert_eq!(blob.len(), 51);
    }

    #[test]
    fn test_signature_is_valid_sshsig() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let result = create_ssh_signature(&signing_key, &verifying_key, "git", b"test commit data");
        assert!(result.is_ok());
        let armored = result.unwrap();
        assert!(armored.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
        assert!(armored.ends_with("-----END SSH SIGNATURE-----\n"));
    }
}
