//! Key resolution and regeneration logic for persona and relationship DIDs.

use crate::{
    KeyPurpose,
    bip32::Bip32Extension,
    config::{
        Config, KeyBackend, KeyInfo, PersonaDIDKeys,
        secured_config::{KeySourceMaterial, SecuredConfig},
    },
    errors::OpenVTCError,
};
use affinidi_tdk::{
    TDK,
    did_common::{Document, document::DocumentExt},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use tracing::warn;

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
        let signing = if let Some(signing) = self.persona_did.document.assertion_method.first() {
            let Some(secret) = tdk
                .get_shared_state()
                .secrets_resolver
                .get_secret(signing.get_id())
                .await
            else {
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find secret in TDK for ({})",
                    signing.get_id()
                )));
            };
            let Some(ki) = self.key_info.get(signing.get_id()) else {
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find key info in openvtc Config for ({})",
                    signing.get_id()
                )));
            };
            KeyInfo {
                secret,
                source: ki.path.clone(),
                created: ki.create_time,
                expiry: None,
            }
        } else {
            return Err(OpenVTCError::Config(
                "DID Document does not contain any assertion methods!".to_string(),
            ));
        };

        let authentication =
            if let Some(authentication) = self.persona_did.document.authentication.first() {
                let Some(secret) = tdk
                    .get_shared_state()
                    .secrets_resolver
                    .get_secret(authentication.get_id())
                    .await
                else {
                    return Err(OpenVTCError::Config(format!(
                        "Couldn't find secret in TDK for ({})",
                        authentication.get_id()
                    )));
                };
                let Some(ki) = self.key_info.get(authentication.get_id()) else {
                    return Err(OpenVTCError::Config(format!(
                        "Couldn't find key info in openvtc Config for ({})",
                        authentication.get_id()
                    )));
                };
                KeyInfo {
                    secret,
                    source: ki.path.clone(),
                    created: ki.create_time,
                    expiry: None,
                }
            } else {
                return Err(OpenVTCError::Config(
                    "DID Document does not contain any authentication methods!".to_string(),
                ));
            };

        let decryption = if let Some(decryption) = self.persona_did.document.key_agreement.first() {
            let Some(secret) = tdk
                .get_shared_state()
                .secrets_resolver
                .get_secret(decryption.get_id())
                .await
            else {
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find secret in TDK for ({})",
                    decryption.get_id()
                )));
            };
            let Some(ki) = self.key_info.get(decryption.get_id()) else {
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find key info in openvtc Config for ({})",
                    decryption.get_id()
                )));
            };
            KeyInfo {
                secret,
                source: ki.path.clone(),
                created: ki.create_time,
                expiry: None,
            }
        } else {
            return Err(OpenVTCError::Config(
                "DID Document does not contain any key agreements!".to_string(),
            ));
        };
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
                KeySourceMaterial::Imported { seed } => Secret::from_multibase(seed, None)
                    .map_err(|e| {
                        OpenVTCError::Secret(format!(
                            "Couldn't create secret from multibase for key id. Reason: {e}"
                        ))
                    })?,
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
    }
}
