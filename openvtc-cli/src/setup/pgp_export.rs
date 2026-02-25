/*!
*   As openvtc is designed to work alongside legacy PGP environments, exporting your persona DID
*   keys can be useful
*/

use crate::{setup::PersonaDIDKeys, CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED};
use anyhow::Result;
use chrono::Utc;
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use ed25519_dalek_bip32::VerifyingKey;
use pgp::{
    composed::{ArmorOptions, SignedKeyDetails, SignedSecretKey, SignedSecretSubKey},
    crypto::{self, ed25519::Mode, public_key::PublicKeyAlgorithm},
    packet::{
        KeyFlags, PacketHeader, PublicKey, PublicSubkey, SecretKey, SecretSubkey, SignatureConfig,
        SignatureType, Subpacket, SubpacketData, UserId,
    },
    types::{
        self, EcdhKdfType, EcdhPublicParams, EddsaLegacyPublicParams, KeyDetails, KeyVersion,
        PlainSecretParams, PublicParams, SecretParams, SignedUser, Tag,
    },
};
use secrecy::{ExposeSecret, SecretString};
use x25519_dalek::StaticSecret;

/// Prompts the user if they want to export their persona DID keys for PGP Use
/// term: Terminal Console to help with formatting
/// keys: Persona DID Keys struct
/// user_id: Optional PGP User ID String (name <email address>)
///            - if not provided, then user is promoted for it
/// passphrase: Optional passphrase to unlock PGP Armor export
///            - if not provided, then user is promoted for it
/// wizard: True if this is called from the setup wizard (shows extra help)
pub fn ask_export_persona_did_keys(
    term: &Term,
    keys: &PersonaDIDKeys,
    user_id: Option<&str>,
    passphrase: Option<SecretString>,
    wizard: bool,
) {
    if wizard {
        println!();
        println!(
            "{}",
            style("You can export your Persona DID keys for use in PGP-compatible applications.")
                .color256(CLI_BLUE)
        );
        println!(
            "{}\n",
            style("NOTE: You can export these keys at any point in the future.").color256(CLI_BLUE)
        );

        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Export private key info for PGP use?")
            .default(false)
            .interact()
            .unwrap()
        {
            return;
        }
    }

    let passphrase = if let Some(passphrase) = passphrase {
        passphrase
    } else {
        let passphrase: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter a passphrase to protect your exported keys:")
            .with_confirmation(
                "Confirm your passphrase:",
                "The passphrases do not match.\n",
            )
            .interact()
            .unwrap();
        SecretString::new(passphrase)
    };

    let user_id = if let Some(user_id) = user_id {
        user_id.to_string()
    } else {
        println!(
                "\n{} {}\n",
                style("You must specify a PGP User ID to which these keys are attached.\nRecommended Format: ")
                    .color256(CLI_BLUE),
                style("FirstName LastName <email@domain>").color256(CLI_PURPLE)
            );
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter your PGP User ID: ")
            .interact()
            .unwrap()
    };

    // Export the keys
    match export_persona_did_keys(term, keys, &user_id, passphrase, wizard) {
        Ok(ssk) => {
            // Display to screen
            let ssk_str = ssk.to_armored_string(ArmorOptions::default()).unwrap();
            println!("\n{}", style(ssk_str).color256(CLI_GREEN));
            println!();
        }
        Err(e) => {
            println!(
                "{} {}",
                style("ERROR: Unable to create PGP export of Persona DID keys. Reason:")
                    .color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
        }
    }
}

/// Exports the persona DID keys in a PGP Armored ASCII payload
/// Signing Key is the primary key
/// Inputs:
/// - term: Console Terminal manipulation
/// - keys: Keys that will be exported
/// - user_id: PGP User ID string (name <email address>)
/// - wizard: If true, will print status to STDIO
pub fn export_persona_did_keys(
    term: &Term,
    keys: &PersonaDIDKeys,
    user_id: &str,
    passphrase: SecretString,
    wizard: bool,
) -> Result<SignedSecretKey> {
    let password = types::Password::from(passphrase.expose_secret().as_str());
    let mut rng = rand::thread_rng();

    if wizard {
        print!("  {}", style("Exporting Signing key...").color256(CLI_BLUE));
        term.hide_cursor()?;
        term.flush()?;
    }
    // Signing key
    let sk_pk = PublicKey::new_with_header(
        PacketHeader::new_fixed(Tag::PublicKey, 51),
        KeyVersion::V4,
        PublicKeyAlgorithm::EdDSALegacy,
        Utc::now(),
        None,
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 {
            key: VerifyingKey::from_bytes(
                keys.signing
                    .secret
                    .get_public_bytes()
                    .first_chunk::<32>()
                    .unwrap(),
            )?,
        }),
    )?;

    let mut signing_key = SecretKey::new(
        sk_pk.clone(),
        SecretParams::Plain(PlainSecretParams::Ed25519Legacy(
            crypto::ed25519::SecretKey::try_from_bytes(
                *keys
                    .signing
                    .secret
                    .get_private_bytes()
                    .first_chunk::<32>()
                    .unwrap(),
                Mode::EdDSALegacy,
            )?,
        )),
    )?;

    let mut config =
        SignatureConfig::from_key(&mut rng, &signing_key, SignatureType::CertPositive)?;

    let mut kf = KeyFlags::default();
    kf.set_sign(true);
    kf.set_certify(true);
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(signing_key.fingerprint()))?,
        Subpacket::critical(SubpacketData::SignatureCreationTime(Utc::now()))?,
        Subpacket::critical(SubpacketData::KeyFlags(kf))?,
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(
        signing_key.key_id(),
    ))?];

    let user_id = UserId::from_str(types::PacketHeaderVersion::New, user_id)?;
    let signature = config.sign_certification(
        &signing_key,
        &sk_pk,
        &types::Password::empty(),
        Tag::UserId,
        &user_id,
    )?;

    let signed_user = SignedUser::new(user_id, vec![signature]);
    let details = SignedKeyDetails::new(vec![], vec![], vec![signed_user], vec![]);

    if wizard {
        term.show_cursor()?;
        println!(" {}", style("Success").color256(CLI_GREEN));
    }

    // Create subkeys

    // Authentication
    if wizard {
        print!(
            "  {}",
            style("Exporting Authentiction key...").color256(CLI_BLUE)
        );
        term.hide_cursor()?;
        term.flush()?;
    }
    let ak_pk = PublicSubkey::new_with_header(
        PacketHeader::new_fixed(Tag::PublicSubkey, 51),
        KeyVersion::V4,
        PublicKeyAlgorithm::EdDSALegacy,
        Utc::now(),
        None,
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 {
            key: VerifyingKey::from_bytes(
                keys.authentication
                    .secret
                    .get_public_bytes()
                    .first_chunk::<32>()
                    .unwrap(),
            )?,
        }),
    )?;

    let mut auth_key = SecretSubkey::new(
        ak_pk.clone(),
        SecretParams::Plain(PlainSecretParams::Ed25519Legacy(
            crypto::ed25519::SecretKey::try_from_bytes(
                *keys
                    .authentication
                    .secret
                    .get_private_bytes()
                    .first_chunk::<32>()
                    .unwrap(),
                Mode::EdDSALegacy,
            )?,
        )),
    )?;

    let mut auth_kf = KeyFlags::default();
    auth_kf.set_authentication(true);
    let auth_sig = auth_key.sign(rng.clone(), &signing_key, &sk_pk, &password, auth_kf, None)?;

    auth_key.set_password(rng.clone(), &password)?;
    let auth_ssk = SignedSecretSubKey::new(auth_key, vec![auth_sig]);

    if wizard {
        term.show_cursor()?;
        println!(" {}", style("Success").color256(CLI_GREEN));
    }

    // Decryption
    if wizard {
        print!(
            "  {}",
            style("Exporting Decryption key...").color256(CLI_BLUE)
        );
        term.hide_cursor()?;
        term.flush()?;
    }

    let dk_pk = PublicSubkey::new_with_header(
        PacketHeader::new_fixed(Tag::PublicSubkey, 56),
        KeyVersion::V4,
        PublicKeyAlgorithm::ECDH,
        Utc::now(),
        None,
        PublicParams::ECDH(EcdhPublicParams::Curve25519 {
            p: x25519_dalek::PublicKey::from(
                *keys
                    .decryption
                    .secret
                    .get_public_bytes()
                    .first_chunk::<32>()
                    .unwrap(),
            ),
            hash: crypto::hash::HashAlgorithm::Sha256,
            alg_sym: crypto::sym::SymmetricKeyAlgorithm::AES256,
            ecdh_kdf_type: EcdhKdfType::Native,
        }),
    )?;

    let mut dec_key = SecretSubkey::new(
        dk_pk.clone(),
        SecretParams::Plain(PlainSecretParams::ECDH(
            crypto::ecdh::SecretKey::Curve25519(
                StaticSecret::from(
                    *keys
                        .decryption
                        .secret
                        .get_private_bytes()
                        .first_chunk::<32>()
                        .unwrap(),
                )
                .into(),
            ),
        )),
    )?;

    let mut dec_kf = KeyFlags::default();
    dec_kf.set_encrypt_comms(true);
    dec_kf.set_encrypt_storage(true);
    let dec_sig = dec_key.sign(rng.clone(), &signing_key, &sk_pk, &password, dec_kf, None)?;

    dec_key.set_password(rng.clone(), &password)?;
    let dec_ssk = SignedSecretSubKey::new(dec_key, vec![dec_sig]);

    if wizard {
        term.show_cursor()?;
        println!(" {}", style("Success").color256(CLI_GREEN));
    }

    // This must be signed last
    if wizard {
        print!(
            "  {}",
            style("Securing exported keys...").color256(CLI_BLUE)
        );
        term.hide_cursor()?;
        term.flush()?;
    }
    signing_key.set_password(rng.clone(), &password)?;
    if wizard {
        term.show_cursor()?;
        println!(" {}", style("Success").color256(CLI_GREEN));
    }

    Ok(SignedSecretKey::new(
        signing_key,
        details,
        vec![],
        vec![auth_ssk, dec_ssk],
    ))
}
