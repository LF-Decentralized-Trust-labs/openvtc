//! Integration tests for configuration encryption/decryption lifecycle.
//!
//! These tests verify the full round-trip of encrypting and decrypting
//! configuration data using the Argon2id KDF and AES-256-GCM.

use openvtc_core::config::{
    derive_passphrase_key,
    secured_config::{
        passphrase_decrypt, passphrase_encrypt_v2, unlock_code_decrypt, unlock_code_encrypt,
    },
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

// ---------------------------------------------------------------------------
// Tampering tests — the AEAD must reject any modification to the stored
// ciphertext, including bit-flips in the nonce, ciphertext body, and
// authentication tag. These are the cheap-and-loud failure modes that
// catch silent corruption / on-disk-data-edit attacks.
// ---------------------------------------------------------------------------

#[test]
fn tamper_with_nonce_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"my secret").expect("encrypt");
    // First 12 bytes are the AES-GCM nonce.
    encrypted[0] ^= 0x01;
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "flipping a nonce byte must fail decryption"
    );
}

#[test]
fn tamper_with_ciphertext_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"my secret payload").expect("encrypt");
    // Flip a byte in the middle of the ciphertext (skip 12-byte nonce).
    let mid = 12 + (encrypted.len() - 12) / 2;
    encrypted[mid] ^= 0x80;
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "flipping a ciphertext byte must fail authentication"
    );
}

#[test]
fn tamper_with_tag_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"x").expect("encrypt");
    // Last 16 bytes are the GCM tag.
    let tag_idx = encrypted.len() - 1;
    encrypted[tag_idx] ^= 0xFF;
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "flipping the GCM tag must fail authentication"
    );
}

#[test]
fn truncated_tag_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let encrypted = unlock_code_encrypt(&key, b"y").expect("encrypt");
    // Drop one byte off the end — partial tag.
    let truncated = &encrypted[..encrypted.len() - 1];
    assert!(
        unlock_code_decrypt(&key, truncated).is_err(),
        "truncating any byte off the ciphertext must fail"
    );
}

#[test]
fn appended_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"z").expect("encrypt");
    encrypted.push(0x42);
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "appending an extra byte must fail authentication"
    );
}

#[test]
fn swapped_ciphertexts_fail_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let enc1 = unlock_code_encrypt(&key, b"first message").expect("encrypt 1");
    let enc2 = unlock_code_encrypt(&key, b"second message").expect("encrypt 2");
    // Splice the nonce of #1 onto the body+tag of #2 — must fail; the
    // (key, nonce) pair won't authenticate the substituted body.
    let mut frankenstein = enc1[..12].to_vec();
    frankenstein.extend_from_slice(&enc2[12..]);
    assert!(
        unlock_code_decrypt(&key, &frankenstein).is_err(),
        "splicing nonce from one ciphertext onto another's body must fail"
    );
}

// ---------------------------------------------------------------------------
// v2 passphrase-AEAD format with per-entry random Argon2 salt.
//
// Behavioural contract:
//   * `passphrase_encrypt_v2` always writes a v2 blob (magic prefix + salt).
//   * `passphrase_decrypt` auto-detects format and decrypts both v1 and v2.
//   * Two encrypts of the same plaintext under the same passphrase produce
//     different ciphertexts (random salt + random nonce).
//   * Two operators with the same passphrase produce independent blobs —
//     the deterministic-salt cross-user correlation in v1 is gone.
// ---------------------------------------------------------------------------

const V2_MAGIC: &[u8; 4] = b"OPV2";

#[test]
fn v2_roundtrip_succeeds() {
    let pass = b"my-passphrase-2026";
    let info = b"openvtc-export-v1";
    let plaintext = b"sensitive config blob";
    let blob = passphrase_encrypt_v2(pass, info, plaintext).expect("encrypt v2");
    assert_eq!(&blob[..4], V2_MAGIC, "v2 blob must begin with OPV2 magic");
    let recovered = passphrase_decrypt(pass, info, &blob).expect("decrypt v2");
    assert_eq!(recovered, plaintext);
}

#[test]
fn v2_two_encrypts_produce_distinct_blobs() {
    let pass = b"same-passphrase";
    let info = b"context";
    let plaintext = b"same plaintext";
    let blob_a = passphrase_encrypt_v2(pass, info, plaintext).unwrap();
    let blob_b = passphrase_encrypt_v2(pass, info, plaintext).unwrap();
    // Random salt + random nonce mean even identical inputs produce
    // unrelated ciphertext bytes — no determinism leak.
    assert_ne!(blob_a, blob_b);
    // First byte after the magic+salt header is the AES-GCM nonce; both
    // halves must differ.
    assert_ne!(&blob_a[..20], &blob_b[..20]);
}

#[test]
fn v1_legacy_blob_decrypts_through_passphrase_decrypt() {
    let pass = b"legacy-passphrase";
    let info = b"openvtc-export-v1";
    let plaintext = b"legacy-encrypted payload";
    // Reproduce the v1 path: derive key with deterministic info-salt,
    // run unlock_code_encrypt to produce the [nonce | ct+tag] blob.
    let key = derive_passphrase_key(pass, info).unwrap();
    let v1_blob = unlock_code_encrypt(&key, plaintext).unwrap();
    assert_ne!(&v1_blob[..4], V2_MAGIC);
    // The new auto-detecting decrypt must read it back.
    let recovered = passphrase_decrypt(pass, info, &v1_blob).expect("decrypt v1 via new API");
    assert_eq!(recovered, plaintext);
}

#[test]
fn v2_decrypt_with_wrong_passphrase_fails() {
    let blob = passphrase_encrypt_v2(b"correct", b"context", b"secret").expect("encrypt");
    assert!(passphrase_decrypt(b"wrong", b"context", &blob).is_err());
}

#[test]
fn v2_decrypt_with_wrong_info_for_v1_blob_fails() {
    // For v1 blobs the info-label is part of the (deterministic) salt.
    // Decrypting a v1 blob under a different info must fail because the
    // derived key won't match.
    let pass = b"pass";
    let v1_blob =
        unlock_code_encrypt(&derive_passphrase_key(pass, b"info-a").unwrap(), b"data").unwrap();
    assert!(passphrase_decrypt(pass, b"info-b", &v1_blob).is_err());
}

#[test]
fn v2_decrypt_with_wrong_info_for_v2_blob_still_succeeds() {
    // For v2 the info label is no longer part of the salt — the salt is
    // random and stored alongside the ciphertext. So as long as the
    // passphrase is right, the info argument is currently advisory.
    // (It's preserved in the API for future domain-separation use.)
    let pass = b"pass";
    let blob = passphrase_encrypt_v2(pass, b"info-a", b"data").unwrap();
    let recovered = passphrase_decrypt(pass, b"info-b", &blob).expect("v2 ignores info");
    assert_eq!(recovered, b"data");
}

#[test]
fn v2_blob_tampering_fails_decrypt() {
    let mut blob = passphrase_encrypt_v2(b"pass", b"info", b"plaintext").expect("encrypt");
    // Flip a byte in the salt portion.
    blob[8] ^= 0x01;
    assert!(passphrase_decrypt(b"pass", b"info", &blob).is_err());
}
