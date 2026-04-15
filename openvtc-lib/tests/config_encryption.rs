//! Integration tests for configuration encryption/decryption lifecycle.
//!
//! These tests verify the full round-trip of encrypting and decrypting
//! configuration data using the Argon2id KDF and AES-256-GCM.

use openvtc::config::{
    derive_passphrase_key,
    secured_config::{unlock_code_decrypt, unlock_code_encrypt},
};

#[test]
fn encrypt_decrypt_roundtrip_with_argon2_key() {
    let passphrase = b"integration-test-passphrase-2026";
    let key = derive_passphrase_key(passphrase, b"test-info").unwrap();

    let plaintext = b"sensitive configuration data with unicode: \xc3\xa9\xc3\xa0\xc3\xbc";
    let encrypted = unlock_code_encrypt(&key, plaintext).expect("encryption should succeed");

    assert_ne!(encrypted.as_slice(), plaintext.as_slice());
    assert!(
        encrypted.len() > plaintext.len(),
        "ciphertext includes nonce + auth tag"
    );

    let decrypted = unlock_code_decrypt(&key, &encrypted).expect("decryption should succeed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_passphrase_fails_decryption() {
    let correct_key = derive_passphrase_key(b"correct-passphrase", b"info").unwrap();
    let wrong_key = derive_passphrase_key(b"wrong-passphrase", b"info").unwrap();

    let plaintext = b"secret data";
    let encrypted =
        unlock_code_encrypt(&correct_key, plaintext).expect("encryption should succeed");

    let result = unlock_code_decrypt(&wrong_key, &encrypted);
    assert!(result.is_err(), "Wrong passphrase should fail decryption");
}

#[test]
fn domain_separation_prevents_cross_context_decryption() {
    let passphrase = b"same-passphrase";
    let unlock_key = derive_passphrase_key(passphrase, b"openvtc-unlock-code-v1").unwrap();
    let export_key = derive_passphrase_key(passphrase, b"openvtc-export-v1").unwrap();

    assert_ne!(
        unlock_key, export_key,
        "Different info labels must produce different keys"
    );

    let plaintext = b"config data";
    let encrypted = unlock_code_encrypt(&unlock_key, plaintext).expect("encryption should succeed");

    let result = unlock_code_decrypt(&export_key, &encrypted);
    assert!(
        result.is_err(),
        "Export key should not decrypt data encrypted with unlock key"
    );
}

#[test]
fn encryption_is_non_deterministic() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let plaintext = b"same data";

    let enc1 = unlock_code_encrypt(&key, plaintext).expect("encrypt 1");
    let enc2 = unlock_code_encrypt(&key, plaintext).expect("encrypt 2");

    assert_ne!(
        enc1, enc2,
        "Two encryptions of the same data must differ (random nonce)"
    );

    // But both must decrypt to the same plaintext
    let dec1 = unlock_code_decrypt(&key, &enc1).expect("decrypt 1");
    let dec2 = unlock_code_decrypt(&key, &enc2).expect("decrypt 2");
    assert_eq!(dec1, dec2);
    assert_eq!(dec1.as_slice(), plaintext);
}

#[test]
fn empty_plaintext_roundtrip() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let plaintext = b"";

    let encrypted = unlock_code_encrypt(&key, plaintext).expect("encrypt empty");
    let decrypted = unlock_code_decrypt(&key, &encrypted).expect("decrypt empty");
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

#[test]
fn large_payload_roundtrip() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    let encrypted = unlock_code_encrypt(&key, &plaintext).expect("encrypt large");
    let decrypted = unlock_code_decrypt(&key, &encrypted).expect("decrypt large");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn too_short_ciphertext_fails() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    assert!(
        unlock_code_decrypt(&key, &[0u8; 5]).is_err(),
        "Input shorter than nonce should fail"
    );
    assert!(
        unlock_code_decrypt(&key, &[]).is_err(),
        "Empty input should fail"
    );
}
