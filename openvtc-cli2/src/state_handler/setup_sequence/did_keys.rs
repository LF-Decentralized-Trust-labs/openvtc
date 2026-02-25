use anyhow::{Result, bail};
use chrono::Utc;
use ed25519_dalek_bip32::VerifyingKey;
use pgp::{
    composed::{SignedKeyDetails, SignedSecretKey, SignedSecretSubKey},
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
use tokio::sync::mpsc::UnboundedSender;
use x25519_dalek::StaticSecret;

use crate::state_handler::state::State;

/// Exports the persona DID keys in a PGP Armored ASCII payload
/// Signing Key is the primary key
/// Inputs:
/// - state: Application state
/// - state_tx: State update channel
/// - user_id: PGP User ID string (name <email address>)
/// - passphrase: Passphrase to protect the exported keys
pub fn export_persona_did_keys(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    user_id: &str,
    passphrase: SecretString,
) -> Result<SignedSecretKey> {
    let Some(keys) = &state.setup.did_keys else {
        bail!("DID Persona keys don't exist!");
    };

    let password = types::Password::from(passphrase.expose_secret().as_str());
    let mut rng = rand::thread_rng();

    // Signing key
    state
        .setup
        .did_keys_export
        .messages
        .push("Converting Signing key...".to_string());
    state_tx.send(state.clone())?;

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

    // Create subkeys

    // Authentication
    if let Some(last_entry) = state.setup.did_keys_export.messages.last_mut() {
        *last_entry = "✓ Converted Signing Key".to_string();
    }
    state
        .setup
        .did_keys_export
        .messages
        .push("Converting Authentication key...".to_string());
    state_tx.send(state.clone())?;
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

    if let Some(last_entry) = state.setup.did_keys_export.messages.last_mut() {
        *last_entry = "✓ Converted Authentication Key".to_string();
    }
    state
        .setup
        .did_keys_export
        .messages
        .push("Converting Decryption key...".to_string());
    state_tx.send(state.clone())?;
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

    // This must be signed last
    if let Some(last_entry) = state.setup.did_keys_export.messages.last_mut() {
        *last_entry = "✓ Converted Decryption Key".to_string();
    }
    state
        .setup
        .did_keys_export
        .messages
        .push("Securing exported keys...".to_string());
    state_tx.send(state.clone())?;
    signing_key.set_password(rng.clone(), &password)?;
    if let Some(last_entry) = state.setup.did_keys_export.messages.last_mut() {
        *last_entry = "✓ Keys Secured and exported".to_string();
    }

    Ok(SignedSecretKey::new(
        signing_key,
        details,
        vec![],
        vec![auth_ssk, dec_ssk],
    ))
}
