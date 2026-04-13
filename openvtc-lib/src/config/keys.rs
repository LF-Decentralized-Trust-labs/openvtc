//! Key resolution and regeneration logic for persona and relationship DIDs.

use secrecy::ExposeSecret;

use crate::{
    KeyPurpose,
    bip32::Bip32Extension,
    config::{
        Config, KeyBackend, KeyInfo, PersonaDIDKeys,
        secured_config::{KeyInfoConfig, KeySourceMaterial, SecuredConfig},
    },
    errors::OpenVTCError,
};
use affinidi_tdk::{
    TDK,
    did_common::{Document, document::DocumentExt, verification_method::VerificationRelationship},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use std::collections::HashMap;
use tracing::warn;

/// Resolves a single key from a DID document verification relationship field.
async fn resolve_key_from_document(
    doc_field: &[VerificationRelationship],
    field_name: &str,
    tdk: &TDK,
    key_info: &HashMap<String, KeyInfoConfig>,
) -> Result<KeyInfo, OpenVTCError> {
    let vm = doc_field.first().ok_or_else(|| {
        OpenVTCError::Config(format!("DID Document does not contain any {field_name}!"))
    })?;
    let secret = tdk
        .get_shared_state()
        .secrets_resolver
        .get_secret(vm.get_id())
        .await
        .ok_or_else(|| {
            OpenVTCError::Config(format!("Couldn't find secret in TDK for ({})", vm.get_id()))
        })?;
    let ki = key_info.get(vm.get_id()).ok_or_else(|| {
        OpenVTCError::Config(format!(
            "Couldn't find key info in openvtc Config for ({})",
            vm.get_id()
        ))
    })?;
    Ok(KeyInfo {
        secret,
        source: ki.path.clone(),
        created: ki.create_time,
        expiry: None,
    })
}

impl Config {
    /// Returns the first matching set of keys for the persona DID.
    ///
    /// Resolves one key of each type from the DID document:
    /// - Signing (assertion method)
    /// - Authentication
    /// - Encryption (key agreement)
    ///
    /// # Errors
    ///
    /// Returns an error if the DID document is missing any required verification
    /// method, or if the corresponding secret or key info cannot be found.
    pub async fn get_persona_keys(&self, tdk: &TDK) -> Result<PersonaDIDKeys, OpenVTCError> {
        let doc = &self.persona_did.document;
        let signing = resolve_key_from_document(
            &doc.assertion_method,
            "assertion methods",
            tdk,
            &self.key_info,
        )
        .await?;
        let authentication = resolve_key_from_document(
            &doc.authentication,
            "authentication methods",
            tdk,
            &self.key_info,
        )
        .await?;
        let decryption =
            resolve_key_from_document(&doc.key_agreement, "key agreements", tdk, &self.key_info)
                .await?;
        Ok(PersonaDIDKeys {
            signing,
            authentication,
            decryption,
        })
    }

    /// Regenerates the persona DID keys from secured config and loads them into the TDK.
    ///
    /// # Errors
    ///
    /// Returns an error if a verification method key path is missing from config,
    /// key derivation or import fails, or VTA secret retrieval fails.
    pub(crate) async fn regenerate_persona_keys(
        tdk: &mut TDK,
        sc: &SecuredConfig,
        key_backend: &KeyBackend,
        doc: &Document,
        vta_client: Option<&vta_sdk::client::VtaClient>,
    ) -> Result<(), OpenVTCError> {
        // Rehydrate DID keys referenced by Verification Methods in the DID Document
        for vm in &doc.verification_method {
            let Some(kp) = sc.key_info.get(vm.id.as_str()) else {
                warn!(
                    "Couldn't find DID Verification method key path ({}) in config.",
                    vm.id
                );
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find DID Verification method key path ({}) in config.",
                    vm.id
                )));
            };

            // need to match this to VM purpose
            let k_purpose = if doc.contains_key_agreement(vm.id.as_str()) {
                KeyPurpose::Encryption
            } else if doc.contains_authentication(vm.id.as_str()) {
                KeyPurpose::Authentication
            } else if doc.contains_assertion_method(vm.id.as_str()) {
                KeyPurpose::Signing
            } else {
                warn!("Unknown DID VM ({}) found", vm.id);
                continue;
            };

            let mut secret = match &kp.path {
                KeySourceMaterial::Derived { path } => {
                    let KeyBackend::Bip32 { root, .. } = key_backend else {
                        return Err(OpenVTCError::Config(
                            "KeySourceMaterial::Derived requires KeyBackend::Bip32".to_string(),
                        ));
                    };
                    root.get_secret_from_path(path, k_purpose)?
                }
                KeySourceMaterial::Imported { seed } => {
                    Secret::from_multibase(seed.expose_secret(), None).map_err(|e| {
                        OpenVTCError::Secret(format!(
                            "Couldn't create secret from multibase for key id. Reason: {e}"
                        ))
                    })?
                },
                KeySourceMaterial::VtaManaged { key_id } => {
                    // Use pre-authenticated VTA client
                    let client = vta_client.ok_or_else(|| {
                        OpenVTCError::Config("VtaManaged key requires VTA client".to_string())
                    })?;

                    let key_secret = client.get_key_secret(key_id).await.map_err(|e| {
                        OpenVTCError::Config(format!(
                            "Failed to get key secret from VTA for key_id {key_id}: {e}"
                        ))
                    })?;

                    secret_from_vta_response(&key_secret, k_purpose)?
                }
            };

            // Set the Secret key ID correctly
            secret.id = vm.id.to_string();

            // Load the secret into the TDK Secrets resolver
            tdk.get_shared_state().secrets_resolver.insert(secret).await;
        }
        Ok(())
    }
}

/// Converts a VTA `GetKeySecretResponse` into a TDK `Secret`.
///
/// Supports Ed25519 (signing/authentication) and X25519 (encryption) key types.
///
/// # Errors
///
/// Returns [`OpenVTCError::Secret`] if the private key multibase cannot be decoded
/// or the secret cannot be constructed from the decoded material.
pub fn secret_from_vta_response(
    resp: &vta_sdk::client::GetKeySecretResponse,
    _purpose: KeyPurpose,
) -> Result<Secret, OpenVTCError> {
    match resp.key_type {
        vta_sdk::keys::KeyType::Ed25519 => {
            let seed = vta_sdk::did_key::decode_private_key_multibase(&resp.private_key_multibase)
                .map_err(|e| {
                    OpenVTCError::Secret(format!(
                        "Failed to decode Ed25519 private key multibase: {:?}",
                        e
                    ))
                })?;
            Ok(Secret::generate_ed25519(None, Some(&seed)))
        }
        vta_sdk::keys::KeyType::X25519 => Secret::from_multibase(&resp.private_key_multibase, None)
            .map_err(|e| {
                OpenVTCError::Secret(format!(
                    "Failed to create X25519 secret from multibase: {e}"
                ))
            }),
        vta_sdk::keys::KeyType::P256 => Err(OpenVTCError::Secret(
            "P256 key type is not supported for OpenVTC secrets".to_string(),
        )),
    }
}
