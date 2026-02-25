/*!
*   Handles everything todo with openpgp-card tokens
*/

use crate::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED};
use affinidi_tdk::secrets_resolver::multicodec::{MultiEncodedBuf, ED25519_PUB, X25519_PUB};
use anyhow::Result;
use chrono::{DateTime, Utc};
use console::{style, Term};
use openvtc::KeyPurpose;
use openpgp_card::{
    ocard::{
        algorithm::{self, AlgorithmAttributes},
        crypto::PublicKeyMaterial,
        data::{Features, Fingerprint, KeyGenerationTime, KeySet, KeyStatus, TouchPolicy},
        KeyType,
    },
    state::{Open, Transaction},
    Card,
};
use secrecy::SecretString;
use std::{fmt, sync::Arc};
use tokio::sync::Mutex;

pub mod write;

pub struct KeySlotInfo {
    /// Purpose for this key (signing/authentication/encryption)
    purpose: KeyPurpose,
    /// PGP Public Key Fingerprint
    fingerprint: Option<String>,
    /// Time that this key was generated
    /// 2025-10-02 03:21:06 UTC
    creation_time: Option<String>,
    /// Time that this key will expire
    /// 2025-10-02 03:21:06 UTC
    expiry_time: Option<String>,
    /// Algorithm used for this key
    algorithm: Option<AlgorithmAttributes>,
    /// Does this key require touch to use?
    touch_policy: TouchPolicy,
    /// Additional info relating to the touch policy
    touch_features: Features,
    /// Status of the key
    status: Option<KeyStatus>,
    /// Public key material
    public_key_material: Option<Vec<u8>>,
    /// Number of Digital Signatures created with this key
    signature_count: Option<u32>,
}

impl Default for KeySlotInfo {
    fn default() -> Self {
        KeySlotInfo {
            purpose: KeyPurpose::Unknown,
            fingerprint: None,
            creation_time: None,
            expiry_time: None,
            algorithm: None,
            touch_policy: TouchPolicy::Off,
            touch_features: Features::from(0_u8),
            status: None,
            public_key_material: None,
            signature_count: None,
        }
    }
}

impl fmt::Debug for KeySlotInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Key Purpose: {:?}", self.purpose)?;
        writeln!(f, "Key Slot Info {{")?;
        if let Some(fp) = &self.fingerprint {
            writeln!(f, "  Fingerprint: {}", fp)?;
        }
        if let Some(ct) = &self.creation_time {
            writeln!(f, "  Creation Time: {}", ct)?;
        }
        if let Some(et) = &self.expiry_time {
            writeln!(f, "  Expiry Time: {}", et)?;
        }
        if let Some(alg) = &self.algorithm {
            writeln!(f, "  Algorithm: {}", alg)?;
        }
        writeln!(f, "  Touch Policy: {:?}", self.touch_policy)?;
        writeln!(f, "  Touch Features: {:?}", self.touch_features.to_string())?;
        if let Some(status) = &self.status {
            writeln!(f, "  Status: {:?}", status)?;
        }
        if let Some(pk) = &self.public_key_material {
            writeln!(f, "  Public Key Material: {:02X?}", pk)?;
        }
        if let Some(sc) = &self.signature_count {
            writeln!(f, "  Signature Count: {}", sc)?;
        }
        writeln!(f, "}}")
    }
}

/// Formats the cardholder name
/// Returns None if the name is empty
pub fn format_cardholder_name(card_holder: &str) -> Option<String> {
    if card_holder.is_empty() {
        None
    } else {
        // cardholder name format is LAST_NAME<<FIRST_NAME<OTHER
        // NOTE: May not always contains the << Filler
        // See  ISO/IEC 7501-1 for more info

        if card_holder.contains("<<") {
            let parts: Vec<&str> = card_holder.split("<<").collect();
            let last_name = parts
                .first()
                .unwrap_or(&"")
                .replace("<", " ")
                .trim()
                .to_string();
            let first_names = parts
                .get(1)
                .unwrap_or(&"")
                .replace("<", " ")
                .trim()
                .to_string();
            Some(format!("{} {}", first_names, last_name))
        } else {
            Some(card_holder.replace("<", " ").trim().to_string())
        }
    }
}

pub fn print_cards(cards: &mut [Arc<Mutex<Card<Open>>>]) -> Result<()> {
    print!("{}", style("Cards found:").color256(CLI_BLUE),);
    if cards.is_empty() {
        println!(" {}", style(cards.len()).color256(CLI_ORANGE));
    } else {
        println!(" {}", style(cards.len()).color256(CLI_GREEN));
    }

    for card in cards.iter_mut() {
        let mut card_lock = card.try_lock().unwrap();
        let mut open_card = card_lock.transaction()?;
        let app_identifier = open_card.application_identifier()?;
        print!(
            "{} {} {} {}",
            style("Card Identifier:").color256(CLI_BLUE),
            style(app_identifier.ident()).color256(CLI_GREEN),
            style("Found token from manufacturer:").color256(CLI_BLUE),
            style(app_identifier.manufacturer_name()).color256(CLI_GREEN),
        );

        print!(" {}", style("Cardholder Name: ").color256(CLI_BLUE));
        if let Some(cardholder) = format_cardholder_name(&open_card.cardholder_name()?) {
            println!("{}", style(cardholder).color256(CLI_GREEN));
        } else {
            println!("{}", style("<NOT SET>").color256(CLI_ORANGE));
        }

        // Check key status for this hardware token
        let fps = open_card.fingerprints()?;
        let kgt = open_card.key_generation_times()?;

        let sign_info = get_key_info(&mut open_card, &fps, &kgt, KeyType::Signing)?;
        print_key_info(&sign_info);

        let auth_info = get_key_info(&mut open_card, &fps, &kgt, KeyType::Authentication)?;
        print_key_info(&auth_info);

        let enc_info = get_key_info(&mut open_card, &fps, &kgt, KeyType::Decryption)?;
        print_key_info(&enc_info);
    }

    Ok(())
}

/// Retrieves key slot information from a hardware token
pub fn get_key_info(
    card: &mut Card<Transaction>,
    fps: &KeySet<Fingerprint>,
    kgt: &KeySet<KeyGenerationTime>,
    key_type: KeyType,
) -> Result<KeySlotInfo> {
    let mut key_info = KeySlotInfo {
        purpose: key_type.into(),
        ..Default::default()
    };
    let ki = card.key_information().ok().flatten();

    key_info.algorithm = Some(card.algorithm_attributes(key_type)?);

    if let Some(uif) = card.user_interaction_flag(key_type)? {
        key_info.touch_policy = uif.touch_policy();
        key_info.touch_features = uif.features();
    }

    if let Ok(PublicKeyMaterial::E(pkm)) = card.public_key_material(key_type) {
        key_info.public_key_material = Some(pkm.data().to_vec());
    }

    match key_type {
        KeyType::Signing => {
            if let Some(kgt) = kgt.signature() {
                key_info.creation_time = Some(format!("{}", DateTime::<Utc>::from(kgt)));
            }
            key_info.status = ki.map(|ki| ki.sig_status());
            key_info.signature_count = Some(card.digital_signature_count()?);
            if let Some(fp) = fps.signature() {
                key_info.fingerprint = Some(fp.to_hex());
            }
        }
        KeyType::Authentication => {
            if let Some(kgt) = kgt.authentication() {
                key_info.creation_time = Some(format!("{}", DateTime::<Utc>::from(kgt)));
            }
            key_info.status = ki.map(|ki| ki.aut_status());
            if let Some(fp) = fps.authentication() {
                key_info.fingerprint = Some(fp.to_hex());
            }
        }
        KeyType::Decryption => {
            if let Some(kgt) = kgt.decryption() {
                key_info.creation_time = Some(format!("{}", DateTime::<Utc>::from(kgt)));
            }
            key_info.status = ki.map(|ki| ki.dec_status());
            if let Some(fp) = fps.decryption() {
                key_info.fingerprint = Some(fp.to_hex());
            }
        }
        _ => {}
    }
    Ok(key_info)
}

/// Prints a hardware token key details to the console
pub fn print_key_info(ki: &KeySlotInfo) {
    if let Some(KeyStatus::NotPresent) = &ki.status {
        println!(
            "  {}{}{}{}",
            style("Keyslot (").color256(CLI_BLUE),
            style(&ki.purpose).color256(CLI_ORANGE),
            style(") is").color256(CLI_BLUE),
            style(" NOT_SET").color256(CLI_RED)
        );
        return;
    }

    let algo = match (&ki.purpose, &ki.algorithm) {
        (KeyPurpose::Signing, Some(algo)) | (KeyPurpose::Authentication, Some(algo)) => {
            if let AlgorithmAttributes::Ecc(attr) = algo {
                if attr.curve() == &algorithm::Curve::Ed25519 {
                    print!(
                        "  {}{}{}{}{}",
                        style("Keyslot (").color256(CLI_BLUE),
                        style(&ki.purpose).color256(CLI_ORANGE),
                        style(") Algorithm (").color256(CLI_BLUE),
                        style("Ed25519").color256(CLI_GREEN),
                        style(")").color256(CLI_BLUE),
                    );
                    ED25519_PUB
                } else {
                    println!(
                        "  {}{}{}{}",
                        style("Keyslot (").color256(CLI_BLUE),
                        style(&ki.purpose).color256(CLI_ORANGE),
                        style(") expected crypto algorithm Ed25519, this is an ECC algo but not of type Ed25519. Instead it is: ")
                            .color256(CLI_BLUE),
                        style(format!("{:?}", attr.curve())).color256(CLI_RED)
                    );
                    return;
                }
            } else {
                println!(
                    "  {}{}{}{}",
                    style("Keyslot (").color256(CLI_BLUE),
                    style(&ki.purpose).color256(CLI_ORANGE),
                    style(") expected crypto algorithm Ed25519, instead this key is: ")
                        .color256(CLI_BLUE),
                    style(algo).color256(CLI_RED)
                );
                return;
            }
        }
        (KeyPurpose::Encryption, Some(algo)) => {
            if let AlgorithmAttributes::Ecc(attr) = algo {
                if attr.curve() == &algorithm::Curve::Curve25519 {
                    print!(
                        "  {}{}{}{}{}",
                        style("Keyslot (").color256(CLI_BLUE),
                        style(&ki.purpose).color256(CLI_ORANGE),
                        style(") Algorithm (").color256(CLI_BLUE),
                        style("X25519").color256(CLI_GREEN),
                        style(")").color256(CLI_BLUE),
                    );
                    X25519_PUB
                } else {
                    println!(
                        "  {}{}{}{}",
                        style("Keyslot (").color256(CLI_BLUE),
                        style(&ki.purpose).color256(CLI_ORANGE),
                        style(") expected crypto algorithm X25519, this is an ECC algo but not of type X25519. Instead it is: ")
                            .color256(CLI_BLUE),
                        style(format!("{:?}", attr.curve())).color256(CLI_RED)
                    );
                    return;
                }
            } else {
                println!(
                    "  {}{}{}{}",
                    style("Keyslot (").color256(CLI_BLUE),
                    style(&ki.purpose).color256(CLI_ORANGE),
                    style(") expected crypto algorithm X25519, instead this key is: ")
                        .color256(CLI_BLUE),
                    style(algo).color256(CLI_RED)
                );
                return;
            }
        }
        _ => {
            println!("{ki:#?}");
            return;
        }
    };

    if let Some(fp) = &ki.fingerprint {
        print!(
            " {}{}{}",
            style("Fingerprint (").color256(CLI_BLUE),
            style(fp).color256(CLI_GREEN),
            style(")").color256(CLI_BLUE)
        );
    } else {
        print!(
            " {}{}{}",
            style("Fingerprint (").color256(CLI_BLUE),
            style("<NOT SET>").color256(CLI_RED),
            style(")").color256(CLI_BLUE)
        );
    }

    // How to unlock the token
    if ki.purpose == KeyPurpose::Signing {
        // Best practice for Signing key is for it to require some form of user interface
        if ki.touch_policy == TouchPolicy::Off {
            print!(
                " {}{}{}{}{}",
                style("Touch Policy (").color256(CLI_BLUE),
                style(ki.touch_policy).color256(CLI_RED).blink(),
                style(" :: ").color256(CLI_BLUE),
                style(&ki.touch_features).color256(CLI_GREEN),
                style(")").color256(CLI_BLUE)
            );
        } else {
            print!(
                " {}{}{}{}{}",
                style("Touch Policy (").color256(CLI_BLUE),
                style(ki.touch_policy).color256(CLI_GREEN),
                style(" :: ").color256(CLI_BLUE),
                style(&ki.touch_features).color256(CLI_GREEN),
                style(")").color256(CLI_BLUE)
            );
        }
    } else {
        print!(
            " {}{}{}{}{}",
            style("Touch Policy (").color256(CLI_BLUE),
            style(ki.touch_policy).color256(CLI_GREEN),
            style(" :: ").color256(CLI_BLUE),
            style(&ki.touch_features).color256(CLI_GREEN),
            style(")").color256(CLI_BLUE)
        );
    }

    // Status of the key
    if let Some(status) = &ki.status {
        print!(" {}", style("Key Status (").color256(CLI_BLUE));
        match status {
            KeyStatus::Imported => print!("{}", style(status).color256(CLI_GREEN)),
            KeyStatus::Generated => print!("{}", style(status).color256(CLI_ORANGE)),
            KeyStatus::NotPresent => {
                print!("{}", style(status).color256(CLI_RED))
            }
            KeyStatus::Unknown(_) => {
                print!("{}", style(status).color256(CLI_RED))
            }
        }
        print!("{}", style(")").color256(CLI_BLUE));
    }

    if let Some(ct) = &ki.creation_time {
        print!(
            " {}{}{}",
            style("Creation Time (").color256(CLI_BLUE),
            style(ct).color256(CLI_GREEN),
            style(")").color256(CLI_BLUE)
        );
    }

    //show the public key info as base58 multi-encoded
    if let Some(pk) = &ki.public_key_material {
        let pk_mb = multibase::encode(
            multibase::Base::Base58Btc,
            MultiEncodedBuf::encode_bytes(algo, pk.as_slice()).into_bytes(),
        );
        println!(
            "\n  {} {}",
            style("Public Key Multibase Encoded:").color256(CLI_BLUE),
            style(pk_mb).color256(CLI_GREEN),
        );
    } else {
        println!();
    }
}

/// Performs a factory reset on the card, erasing all keys and data
pub fn factory_reset(term: &Term, card: &mut Arc<Mutex<Card<Open>>>) -> Result<()> {
    print!("{}", style("Factory resetting card...").color256(CLI_BLUE));
    term.hide_cursor()?;
    term.flush()?;
    let mut lock = card.try_lock().unwrap();
    let mut card = lock.transaction()?;
    card.factory_reset()?;
    term.show_cursor()?;
    println!(" {}", style("Success!").color256(CLI_GREEN));

    Ok(())
}

pub fn set_signing_touch_policy(
    term: &Term,
    card: &mut Arc<Mutex<Card<Open>>>,
    admin_pin: &SecretString,
) -> Result<()> {
    let mut lock = card.try_lock().unwrap();
    let mut open_card = lock.transaction()?;
    open_card.verify_admin_pin(admin_pin.clone())?;
    let mut card = open_card.to_admin_card(None)?;

    print!(
        "{}",
        style("Set the Signing key to require touch").color256(CLI_BLUE)
    );
    term.flush()?;
    term.hide_cursor()?;

    card.set_touch_policy(KeyType::Signing, TouchPolicy::On)?;
    term.show_cursor()?;
    println!(" {}", style("Success").color256(CLI_GREEN));

    Ok(())
}

/// Sets the cardholder name
/// name: Max length is 39 characters
pub fn set_cardholder_name(
    term: &Term,
    card: &mut Arc<Mutex<Card<Open>>>,
    admin_pin: &SecretString,
    name: &str,
) -> Result<()> {
    let mut lock = card.try_lock().unwrap();
    let mut open_card = lock.transaction()?;
    open_card.verify_admin_pin(admin_pin.clone())?;
    let mut card = open_card.to_admin_card(None)?;

    print!(
        "{}{}{}",
        style("Setting cardholder name to (").color256(CLI_BLUE),
        style(name).color256(CLI_PURPLE),
        style(")...").color256(CLI_BLUE),
    );
    term.flush()?;
    term.hide_cursor()?;
    card.set_cardholder_name(name)?;

    term.show_cursor()?;
    println!(" {}", style("Success").color256(CLI_GREEN));

    Ok(())
}
