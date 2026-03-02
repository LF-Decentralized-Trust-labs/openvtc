/*! VTA client wrapper functions for the setup flow */

use affinidi_tdk::TDK;
use affinidi_tdk::did_common::Document;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use anyhow::Result;
use chrono::Utc;
use openvtc::config::{
    KeyInfo, PersonaDIDKeys,
    secured_config::KeySourceMaterial,
};
use vta_sdk::{
    client::{CreateDidWebvhRequest, CreateKeyRequest, VtaClient},
    credentials::CredentialBundle,
    keys::KeyType,
    session::{TokenResult, challenge_response},
    webvh::WebvhServerRecord,
};

/// Decode a base64url credential bundle string
pub fn decode_credential(input: &str) -> Result<CredentialBundle> {
    CredentialBundle::decode(input)
        .map_err(|e| anyhow::anyhow!("Failed to decode credential bundle: {:?}", e))
}

/// Authenticate with VTA using challenge-response
pub async fn authenticate(
    vta_url: &str,
    credential_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult> {
    challenge_response(vta_url, credential_did, private_key_multibase, vta_did)
        .await
        .map_err(|e| anyhow::anyhow!("VTA authentication failed: {e}"))
}

/// Create persona keys via VTA service
/// Creates 3 keys: Ed25519 signing, Ed25519 auth, X25519 encryption
/// Returns PersonaDIDKeys with VtaManaged source
pub async fn create_persona_keys(client: &VtaClient, context_id: Option<&str>) -> Result<PersonaDIDKeys> {
    let created = Utc::now();

    // Signing key (Ed25519)
    let sign_resp = client
        .create_key(CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona-signing".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create signing key: {e}"))?;

    let sign_secret_resp = client
        .get_key_secret(&sign_resp.key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get signing key secret: {e}"))?;

    let mut sign_secret = vta_sdk::did_key::secret_from_key_response(&sign_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    sign_secret.id = sign_secret.get_public_keymultibase()?;

    let signing = KeyInfo {
        secret: sign_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: sign_resp.key_id,
        },
        expiry: None,
        created,
    };

    // Authentication key (Ed25519)
    let auth_resp = client
        .create_key(CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona-authentication".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create authentication key: {e}"))?;

    let auth_secret_resp = client
        .get_key_secret(&auth_resp.key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get authentication key secret: {e}"))?;

    let mut auth_secret = vta_sdk::did_key::secret_from_key_response(&auth_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    auth_secret.id = auth_secret.get_public_keymultibase()?;

    let authentication = KeyInfo {
        secret: auth_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: auth_resp.key_id,
        },
        expiry: None,
        created,
    };

    // Encryption key (X25519)
    let enc_resp = client
        .create_key(CreateKeyRequest {
            key_type: KeyType::X25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona-encryption".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create encryption key: {e}"))?;

    let enc_secret_resp = client
        .get_key_secret(&enc_resp.key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get encryption key secret: {e}"))?;

    let mut enc_secret = vta_sdk::did_key::secret_from_key_response(&enc_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    enc_secret.id = enc_secret.get_public_keymultibase()?;

    let decryption = KeyInfo {
        secret: enc_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: enc_resp.key_id,
        },
        expiry: None,
        created,
    };

    Ok(PersonaDIDKeys {
        signing,
        authentication,
        decryption,
    })
}

/// Create WebVH update keys via VTA service
/// Returns (update_secret, next_update_secret)
pub async fn create_update_keys(client: &VtaClient, context_id: Option<&str>) -> Result<(Secret, Secret)> {
    // Update key (Ed25519)
    let update_resp = client
        .create_key(CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("webvh-update".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create WebVH update key: {e}"))?;

    let update_secret_resp = client
        .get_key_secret(&update_resp.key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get WebVH update key secret: {e}"))?;

    let update_secret = vta_sdk::did_key::secret_from_key_response(&update_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Next update key (Ed25519)
    let next_update_resp = client
        .create_key(CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("webvh-next-update".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create WebVH next update key: {e}"))?;

    let next_update_secret_resp = client
        .get_key_secret(&next_update_resp.key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get WebVH next update key secret: {e}"))?;

    let next_update_secret = vta_sdk::did_key::secret_from_key_response(&next_update_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    Ok((update_secret, next_update_secret))
}

/// List WebVH servers available from the VTA
pub async fn list_webvh_servers(client: &VtaClient) -> Result<Vec<WebvhServerRecord>> {
    let result = client
        .list_webvh_servers()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list WebVH servers: {e}"))?;
    Ok(result.servers)
}

/// Create a DID via a WebVH server
/// Returns (PersonaDIDKeys, did, Document, mnemonic)
pub async fn create_did_via_server(
    client: &VtaClient,
    tdk: &TDK,
    context_id: &str,
    server_id: &str,
    path: Option<String>,
) -> Result<(PersonaDIDKeys, String, Document, String)> {
    let created = Utc::now();

    // Use the VTA's built-in mediator service rather than additional_services,
    // because the VTA formats the service ID as a full DID URL (e.g. "did:...#vta-didcomm")
    // which the TDK resolver requires. A relative fragment like "#public-didcomm" is rejected.
    let req = CreateDidWebvhRequest {
        context_id: context_id.to_string(),
        server_id: server_id.to_string(),
        path,
        label: None,
        portable: true,
        add_mediator_service: true,
        additional_services: None,
        pre_rotation_count: 1,
    };

    let result = client
        .create_did_webvh(req)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create DID via WebVH server: {e}"))?;

    let did = result.did.clone();
    let mnemonic = result.mnemonic.clone();

    // Fetch signing key secret (#key-0 = Ed25519)
    let sign_secret_resp = client
        .get_key_secret(&result.signing_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get signing key secret: {e}"))?;

    let mut sign_secret = vta_sdk::did_key::secret_from_key_response(&sign_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    // Set the secret ID to the DID verification method ID
    sign_secret.id = format!("{}#key-0", &did);

    let signing = KeyInfo {
        secret: sign_secret.clone(),
        source: KeySourceMaterial::VtaManaged {
            key_id: result.signing_key_id.clone(),
        },
        expiry: None,
        created,
    };

    // Authentication uses the same Ed25519 key (#key-0)
    let authentication = KeyInfo {
        secret: sign_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: result.signing_key_id,
        },
        expiry: None,
        created,
    };

    // Fetch KA key secret (#key-1 = X25519)
    let ka_secret_resp = client
        .get_key_secret(&result.ka_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get KA key secret: {e}"))?;

    let mut ka_secret = vta_sdk::did_key::secret_from_key_response(&ka_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    ka_secret.id = format!("{}#key-1", &did);

    let decryption = KeyInfo {
        secret: ka_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: result.ka_key_id,
        },
        expiry: None,
        created,
    };

    let persona_keys = PersonaDIDKeys {
        signing,
        authentication,
        decryption,
    };

    // Resolve the DID to get the document
    let resolved = tdk
        .did_resolver()
        .resolve(&did)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve created DID: {e}"))?;

    Ok((persona_keys, did, resolved.doc, mnemonic))
}
