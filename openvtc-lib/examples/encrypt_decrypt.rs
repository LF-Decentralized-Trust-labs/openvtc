//! Example: Encrypt and decrypt data using OpenVTC's configuration encryption.
//!
//! This demonstrates the core encryption primitives used to protect
//! sensitive configuration data at rest.
//!
//! Run with: `cargo run --example encrypt_decrypt`

use openvtc::config::{
    derive_passphrase_key,
    secured_config::{unlock_code_decrypt, unlock_code_encrypt},
};

fn main() {
    // Derive a 32-byte encryption key from a passphrase.
    // The info label provides domain separation — the same passphrase
    // produces different keys for different contexts.
    let key = derive_passphrase_key(b"my-secure-passphrase", b"example-context-v1")
        .expect("Key derivation should succeed");

    println!("Derived 32-byte key from passphrase (Argon2id)");
    println!("Key (hex): {}", hex::encode(key));

    // Encrypt some sensitive data
    let plaintext = b"Hello from OpenVTC! This is sensitive configuration data.";
    let ciphertext = unlock_code_encrypt(&key, plaintext).expect("Encryption should succeed");

    println!(
        "\nPlaintext ({} bytes): {:?}",
        plaintext.len(),
        std::str::from_utf8(plaintext).unwrap()
    );
    println!(
        "Ciphertext ({} bytes): [nonce(12) + encrypted + auth_tag(16)]",
        ciphertext.len()
    );

    // Decrypt it back
    let decrypted = unlock_code_decrypt(&key, &ciphertext).expect("Decryption should succeed");

    assert_eq!(decrypted, plaintext);
    println!(
        "\nDecrypted successfully: {:?}",
        std::str::from_utf8(&decrypted).unwrap()
    );

    // Demonstrate that encryption is non-deterministic (random nonce)
    let ciphertext2 = unlock_code_encrypt(&key, plaintext).expect("Encryption should succeed");
    assert_ne!(ciphertext, ciphertext2);
    println!("\nSecond encryption of same data produces different ciphertext (random nonce)");

    // Demonstrate domain separation
    let key_a = derive_passphrase_key(b"same-passphrase", b"context-a")
        .expect("Key derivation should succeed");
    let key_b = derive_passphrase_key(b"same-passphrase", b"context-b")
        .expect("Key derivation should succeed");
    assert_ne!(key_a, key_b);
    println!("Domain separation: same passphrase + different context = different keys");
}
