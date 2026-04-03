use affinidi_tdk::{
    did_common::{
        Document,
        service::{Endpoint, Service},
        verification_method::{VerificationMethod, VerificationRelationship},
    },
    secrets_resolver::secrets::Secret,
};
use didwebvh_rs::{
    DIDWebVHError,
    create::{CreateDIDConfig, create_did},
    log_entry::LogEntryMethods,
    parameters::Parameters,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use url::Url;

use crate::{config::PersonaDIDKeys, errors::OpenVTCError};

/// Creates a new `did:webvh` DID with key pre-rotation enabled.
///
/// This builds a full DID Document containing three verification methods:
/// - `#key-1` (Ed25519) -- assertion method (signing)
/// - `#key-2` (Ed25519) -- authentication
/// - `#key-3` (X25519) -- key agreement (encryption)
///
/// A DIDComm messaging service endpoint pointing to the given `mediator_did` is
/// also added to the document.
///
/// # Parameters
/// - `raw_url`: The WebVH server URL where the DID log will be hosted (e.g. `https://fpp.storm.ws`).
/// - `keys`: Mutable persona keys whose secret IDs are updated to match the created DID.
/// - `mediator_did`: The DID of the mediator used as the DIDComm service endpoint.
/// - `update_secret`: The Ed25519 secret used to authorize this initial DID log entry.
/// - `next_update_secret`: The Ed25519 secret whose hash is committed for key pre-rotation.
///
/// # Returns
/// A tuple of `(did_id, Document)` where `did_id` is the fully-qualified `did:webvh:...`
/// string and `Document` is the resolved DID Document produced by the creation process.
/// The DID log is also saved to `did.jsonl` in the current working directory.
pub async fn create_initial_webvh_did(
    raw_url: &str,
    keys: &mut PersonaDIDKeys,
    mediator_did: &str,
    update_secret: Secret,
    next_update_secret: Secret,
) -> Result<(String, Document), OpenVTCError> {
    // Build the DID Document with a placeholder DID (create_did will replace with SCID)
    let placeholder_did = format!("did:webvh:{{SCID}}:{}", extract_domain(raw_url)?);
    let mut did_document = Document::new(&placeholder_did)
        .map_err(|e| OpenVTCError::Config(format!("Invalid DID URL: {e}")))?;

    // Add the verification methods to the DID Document
    let mut property_set: HashMap<String, Value> = HashMap::new();

    // Signing Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(keys.signing.secret.get_public_keymultibase().map_err(|e| {
            DIDWebVHError::InvalidMethodIdentifier(format!(
                "Couldn't set signing verificationMethod publicKeybase: {e}"
            ))
        })?),
    );
    let key_id = Url::parse(&[&placeholder_did, "#key-1"].concat()).map_err(|e| {
        DIDWebVHError::InvalidMethodIdentifier(format!(
            "Couldn't set verificationMethod Key ID for #key-1: {e}"
        ))
    })?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: did_document.id.clone(),
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .assertion_method
        .push(VerificationRelationship::Reference(key_id.clone()));

    // Authentication Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(
            keys.authentication
                .secret
                .get_public_keymultibase()
                .map_err(|e| {
                    DIDWebVHError::InvalidMethodIdentifier(format!(
                        "Couldn't set authentication verificationMethod publicKeybase: {e}"
                    ))
                })?,
        ),
    );
    let key_id = Url::parse(&[&placeholder_did, "#key-2"].concat()).map_err(|e| {
        DIDWebVHError::InvalidMethodIdentifier(format!(
            "Couldn't set verificationMethod key ID for #key-2: {e}"
        ))
    })?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: did_document.id.clone(),
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .authentication
        .push(VerificationRelationship::Reference(key_id.clone()));

    // Decryption Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(
            keys.decryption
                .secret
                .get_public_keymultibase()
                .map_err(|e| {
                    DIDWebVHError::InvalidMethodIdentifier(format!(
                        "Couldn't set decryption verificationMethod publicKeybase: {e}"
                    ))
                })?,
        ),
    );
    let key_id = Url::parse(&[&placeholder_did, "#key-3"].concat()).map_err(|e| {
        DIDWebVHError::InvalidMethodIdentifier(format!(
            "Couldn't set verificationMethod key ID for #key-3: {e}"
        ))
    })?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: did_document.id.clone(),
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .key_agreement
        .push(VerificationRelationship::Reference(key_id.clone()));

    // Add a service endpoint for this persona
    let endpoint = Endpoint::Map(json!([{"accept": ["didcomm/v2"], "uri": mediator_did}]));
    did_document.service.push(Service {
        id: Some(
            Url::parse(&[&placeholder_did, "#public-didcomm"].concat()).map_err(|e| {
                DIDWebVHError::InvalidMethodIdentifier(format!(
                    "Couldn't set Service Endpoint for #public-didcomm: {e}"
                ))
            })?,
        ),
        type_: vec!["DIDCommMessaging".to_string()],
        property_set: HashMap::new(),
        service_endpoint: endpoint,
    });

    // Prepare the update secret with proper did:key ID
    let mut update_secret = update_secret;
    update_secret.id = [
        "did:key:",
        &update_secret.get_public_keymultibase().map_err(|e| {
            OpenVTCError::Secret(format!(
                "update Secret Key was missing public key information! {e}"
            ))
        })?,
        "#",
        &update_secret.get_public_keymultibase().map_err(|e| {
            OpenVTCError::Secret(format!(
                "update Secret Key was missing public key information! {e}"
            ))
        })?,
    ]
    .concat();

    let parameters = Parameters::new()
        .with_key_pre_rotation(true)
        .with_update_keys(vec![update_secret.get_public_keymultibase().map_err(
            |e| {
                OpenVTCError::Secret(format!(
                    "update Secret Key was missing public key information! {e}"
                ))
            },
        )?])
        .with_next_key_hashes(vec![
            next_update_secret
                .get_public_keymultibase_hash()
                .map_err(|e| {
                    OpenVTCError::Secret(format!(
                        "next_update Secret Key was missing public key information! {e}"
                    ))
                })?,
        ])
        .with_portable(true)
        .build();

    // Use the new create_did API
    let config = CreateDIDConfig::builder()
        .address(raw_url)
        .authorization_key(update_secret)
        .did_document(serde_json::to_value(&did_document)?)
        .parameters(parameters)
        .build()?;

    let result = create_did(config).await?;

    let did_id = result.did();

    // Change the key ID's to match the DID VM ID's
    keys.signing.secret.id = [did_id, "#key-1"].concat();
    keys.authentication.secret.id = [did_id, "#key-2"].concat();
    keys.decryption.secret.id = [did_id, "#key-3"].concat();

    // Save the DID to local file
    result.log_entry().save_to_file("did.jsonl")?;

    Ok((
        did_id.to_string(),
        serde_json::from_value(result.log_entry().get_did_document()?)?,
    ))
}

/// Extract domain and path from a URL for building placeholder DIDs.
fn extract_domain(raw_url: &str) -> Result<String, OpenVTCError> {
    let url = Url::parse(raw_url)
        .map_err(|e| OpenVTCError::Config(format!("Invalid URL ({raw_url}): {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| OpenVTCError::Config(format!("URL has no host: {raw_url}")))?;
    let path = url.path().trim_end_matches('/');
    if path.is_empty() || path == "/" {
        Ok(host.to_string())
    } else {
        Ok(format!("{host}{path}"))
    }
}
