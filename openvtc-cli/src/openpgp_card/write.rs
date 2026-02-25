/*!
*   Handles writing of data to the OpenPGP Card
*/

use crate::{CLI_BLUE, CLI_GREEN};
use anyhow::{bail, Result};
use chrono::Utc;
use console::{style, Term};
use ed25519_dalek_bip32::VerifyingKey;
use openvtc::{
    config::{KeyInfo, PersonaDIDKeys},
    KeyPurpose,
};
use openpgp_card::{ocard::KeyType, state::Open, Card};
use openpgp_card_rpgp::UploadableKey;
use pgp::{
    crypto::{self, ed25519::Mode, public_key::PublicKeyAlgorithm},
    packet::{PacketHeader, PublicKey, SecretKey},
    types::{
        EcdhKdfType, EcdhPublicParams, EddsaLegacyPublicParams, KeyVersion, PlainSecretParams,
        PublicParams, SecretParams, Tag,
    },
};
use secrecy::SecretString;
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Writes keys to the card
pub fn write_keys_to_card(
    term: &Term,
    card: &mut Arc<Mutex<Card<Open>>>,
    keys: &PersonaDIDKeys,
    admin_pin: &SecretString,
) -> Result<()> {
    // Try unlocking the card with the admin PIN
    let mut lock = card.try_lock().unwrap();
    let mut open_card = lock.transaction()?;
    open_card.verify_admin_pin(admin_pin.clone())?;
    let mut card = open_card.to_admin_card(None)?;

    // Create a PGP secret key packet
    print!("{}", style("Writing Signing key...").color256(CLI_BLUE));
    term.flush()?;
    term.hide_cursor()?;
    let uk = create_pgp_secret_packet(&keys.signing, KeyPurpose::Signing)?;
    card.import_key(Box::new(uk), KeyType::Signing)?;
    term.hide_cursor()?;
    println!(" {}", style("Success").color256(CLI_GREEN));

    print!(
        "{}",
        style("Writing Authentication key...").color256(CLI_BLUE)
    );
    term.flush()?;
    term.hide_cursor()?;
    let uk = create_pgp_secret_packet(&keys.authentication, KeyPurpose::Authentication)?;
    card.import_key(Box::new(uk), KeyType::Authentication)?;
    term.show_cursor()?;
    println!(" {}", style("Success").color256(CLI_GREEN));

    print!("{}", style("Writing Encryption key...").color256(CLI_BLUE));
    term.flush()?;
    term.hide_cursor()?;
    let uk = create_pgp_secret_packet(&keys.decryption, KeyPurpose::Encryption)?;
    card.import_key(Box::new(uk), KeyType::Decryption)?;
    term.show_cursor()?;
    println!(" {}", style("Success").color256(CLI_GREEN));

    Ok(())
}

/// Creates a PGP secret key packet from key details
fn create_pgp_secret_packet(key: &KeyInfo, kp: KeyPurpose) -> Result<UploadableKey> {
    let (pk, sp) = match kp {
        KeyPurpose::Signing => {
            // Packet Length is 51 octets for EdDSA Legacy Keys (which is what is most supported)
            let packet_header = PacketHeader::new_fixed(Tag::PublicKey, 51);

            let pk = PublicKey::new_with_header(
                packet_header,
                KeyVersion::V4,
                PublicKeyAlgorithm::EdDSALegacy,
                Utc::now(),
                key.expiry.map(|e| e.num_days() as u16),
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 {
                    key: VerifyingKey::from_bytes(
                        key.secret.get_public_bytes().first_chunk::<32>().unwrap(),
                    )?,
                }),
            )?;

            // Create SecretParams
            let sp = SecretParams::Plain(PlainSecretParams::Ed25519Legacy(
                crypto::ed25519::SecretKey::try_from_bytes(
                    *key.secret.get_private_bytes().first_chunk::<32>().unwrap(),
                    Mode::EdDSALegacy,
                )?,
            ));

            (pk, sp)
        }
        KeyPurpose::Authentication => {
            // Packet Length is 51 octets for EdDSA Legacy Keys (which is what is most supported)
            let packet_header = PacketHeader::new_fixed(Tag::PublicKey, 51);

            let pk = PublicKey::new_with_header(
                packet_header,
                KeyVersion::V4,
                PublicKeyAlgorithm::EdDSALegacy,
                Utc::now(),
                key.expiry.map(|e| e.num_days() as u16),
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 {
                    key: VerifyingKey::from_bytes(
                        key.secret.get_public_bytes().first_chunk::<32>().unwrap(),
                    )?,
                }),
            )?;

            // Create SecretParams
            let sp = SecretParams::Plain(PlainSecretParams::Ed25519Legacy(
                crypto::ed25519::SecretKey::try_from_bytes(
                    *key.secret.get_private_bytes().first_chunk::<32>().unwrap(),
                    Mode::EdDSALegacy,
                )?,
            ));

            (pk, sp)
        }
        KeyPurpose::Encryption => {
            // Packet Length is 56 octets for ECDH
            let packet_header = PacketHeader::new_fixed(Tag::PublicKey, 56);

            let x25519_sk =
                StaticSecret::from(*key.secret.get_private_bytes().first_chunk::<32>().unwrap());
            let x25519_pk = X25519PublicKey::from(&x25519_sk);

            let pk = PublicKey::new_with_header(
                packet_header,
                KeyVersion::V4,
                PublicKeyAlgorithm::ECDH,
                Utc::now(),
                key.expiry.map(|e| e.num_days() as u16),
                PublicParams::ECDH(EcdhPublicParams::Curve25519 {
                    p: x25519_pk,
                    hash: crypto::hash::HashAlgorithm::Sha256,
                    alg_sym: crypto::sym::SymmetricKeyAlgorithm::AES256,
                    ecdh_kdf_type: EcdhKdfType::Native,
                }),
            )?;

            // Create SecretParams
            let sp = SecretParams::Plain(PlainSecretParams::ECDH(
                crypto::ecdh::SecretKey::Curve25519(x25519_sk.into()),
            ));

            (pk, sp)
        }
        _ => bail!("Invalid Key Purpose being used to import secret key to hardware token"),
    };

    // Convert to uploadable key
    Ok(SecretKey::new(pk, sp)?.into())
}
