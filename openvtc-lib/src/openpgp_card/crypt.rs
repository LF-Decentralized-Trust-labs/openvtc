/*! Encrypt/Decrypt functions using the openpgp-card
*/

use crate::{
    config::{
        TokenInteractions,
        secured_config::{unlock_code_decrypt, unlock_code_encrypt},
    },
    errors::OpenVTCError,
    openpgp_card::open_card,
};
use byteorder::{BigEndian, ByteOrder};
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::{
    crypto::public_key::PublicKeyAlgorithm,
    ser::Serialize,
    types::{EskType, PkeskBytes},
};
use rand::Rng;
use secrecy::SecretString;
use std::io::BufReader;
use tracing::{info, warn};
use zeroize::Zeroize;

// Creates a simple 2-byte checksum over an array of bytes
fn generate_checksum(bytes: &[u8]) -> [u8; 2] {
    let sum = (bytes.iter().map(|v| u32::from(*v)).sum::<u32>() & 0xffff) as u16;

    let mut res = [0u8; 2];
    BigEndian::write_u16(&mut res[..], sum);

    res
}

/// Uses the decrypt public key on the token to encrypt a random Session Key (ESK)
/// Then encrypts the data with the session key using AES-GCM
///
/// Returns (ESK, encrypted data)
pub fn token_encrypt(
    token_id: &str,
    data: &[u8],
    touch_prompt: &(dyn Fn() + Send + Sync),
) -> Result<(Vec<u8>, Vec<u8>), OpenVTCError> {
    let mut card = open_card(token_id)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't use hardware token ({token_id}): {e}")))?;
    let mut card = card.transaction().map_err(|e| {
        OpenVTCError::Token(format!(
            "Couldn't create hardware token transaction - encrypt: {e}"
        ))
    })?;

    let cs = CardSlot::init_from_card(&mut card, KeyType::Decryption, touch_prompt)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't init decryption key from token: {e}")))?;

    // Create random 32 byte seed
    let mut seed: [u8; 32] = [0; 32];
    let mut rng = rand::thread_rng();
    rng.fill(&mut seed);

    // Augment the seed with Algo type (PlainText) and a 2-byte Checksum
    let mut seed_augmented: [u8; 35] = [0; 35];
    let cksum = generate_checksum(&seed);
    seed_augmented[1..33].copy_from_slice(&seed);
    seed_augmented[33] = cksum[0];
    seed_augmented[34] = cksum[1];

    // Get the public_key from the hardware token
    let pk = cs.public_key();
    let esk = pk
        .encrypt(rng, &seed_augmented, EskType::V6)
        .map_err(|e| OpenVTCError::Encrypt(format!("Couldn't encrypt config data: {e}")))?;

    // Encrypt the data payload using AES-GCM with the seed
    let encrypted = unlock_code_encrypt(&seed, data)?;

    // Get rid of raw secrets
    seed.zeroize();
    seed_augmented.zeroize();

    Ok((
        esk.to_bytes().map_err(|e| {
            OpenVTCError::Encrypt(format!("Couldn't convert encrypted ESK to bytes: {e}"))
        })?,
        encrypted,
    ))
}

/// Uses the decrypt key on the token to decrypt ESK
/// Then the secret seed from the ESK is used to decrypt the data payload using AES-GCM
pub fn token_decrypt<T>(
    user_pin: &SecretString,
    token_id: &str,
    esk: &[u8],
    data: &[u8],
    touch_prompt: &T,
) -> Result<Vec<u8>, OpenVTCError>
where
    T: TokenInteractions + Send + Sync,
{
    info!("Unlocking hardware token");

    let mut card = open_card(token_id)?;
    let mut card = card.transaction().map_err(|e| {
        OpenVTCError::Token(format!(
            "Couldn't create hardware token transaction - decrypt: {e}"
        ))
    })?;

    card.verify_user_pin(user_pin.to_owned())
        .map_err(|_| OpenVTCError::TokenBadPin)?;
    card.to_user_card(None)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't unlock user mode on token: {e}")))?;

    let binding = || touch_prompt.touch_notify();
    let cs = CardSlot::init_from_card(&mut card, KeyType::Decryption, &binding)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't init decryption key from token: {e}")))?;
    touch_prompt.touch_completed();

    // Convert the raw ESK bytes back into a Public Key Encrypted Session Key
    let raw_br = BufReader::new(esk);
    let pk_esk = PkeskBytes::try_from_reader(&PublicKeyAlgorithm::ECDH, 6, raw_br)
        .map_err(|e| OpenVTCError::Decrypt(format!("Couldn't convert public-key ESK. Reason: {e}")))?;
    let (decrypted_esk, _) = cs
        .decrypt(&pk_esk)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't decrypt data, reason: {e}")))?;

    if decrypted_esk.len() != 32 {
        warn!(
            "Invalid ESK length ({}) received! Expected 32",
            decrypted_esk.len()
        );
        return Err(OpenVTCError::Decrypt(format!(
            "Decrypted ESK has invalid length ({})! Expected 32",
            decrypted_esk.len()
        )));
    }

    // Can now decrypt the data payload using the ESK
    unlock_code_decrypt(decrypted_esk.first_chunk::<32>().unwrap(), data)
}
