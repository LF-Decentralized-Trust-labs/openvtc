use affinidi_tdk::{
    did_common::{
        Document,
        service::{Endpoint, Service},
        verification_method::{VerificationMethod, VerificationRelationship},
    },
    secrets_resolver::secrets::Secret,
};
use didwebvh_rs::{DIDWebVHError, DIDWebVHState, parameters::Parameters, url::WebVHURL};
use serde_json::{Value, json};
use std::collections::HashMap;
use url::Url;

use crate::{config::PersonaDIDKeys, errors::OpenVTCError};

pub fn create_initial_webvh_did(
    raw_url: &str,
    keys: &mut PersonaDIDKeys,
    mediator_did: &str,
    update_secret: Secret,
    next_update_secret: Secret,
) -> Result<(String, Document), OpenVTCError> {
    let did_url = WebVHURL::parse_url(&Url::parse(raw_url).map_err(|e| {
        OpenVTCError::WebVH(DIDWebVHError::ValidationError(format!(
            "Invalid URL ({raw_url}). {e}"
        )))
    })?)?;

    // Create the basic DID Document Structure
    let mut did_document = Document::new(&did_url.to_string())
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
    let key_id =
        Url::parse(&[did_url.to_string(), "#key-1".to_string()].concat()).map_err(|e| {
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
    let key_id =
        Url::parse(&[did_url.to_string(), "#key-2".to_string()].concat()).map_err(|e| {
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
    let key_id =
        Url::parse(&[did_url.to_string(), "#key-3".to_string()].concat()).map_err(|e| {
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
    // NOTE: This will use the public mediator

    let endpoint = Endpoint::Map(json!([{"accept": ["didcomm/v2"], "uri": mediator_did}]));
    did_document.service.push(Service {
        id: Some(
            Url::parse(&[did_url.to_string(), "#public-didcomm".to_string()].concat()).map_err(
                |e| {
                    DIDWebVHError::InvalidMethodIdentifier(format!(
                        "Couldn't set Service Endpoint for #public-didcomm: {e}"
                    ))
                },
            )?,
        ),
        type_: vec!["DIDCommMessaging".to_string()],
        property_set: HashMap::new(),
        service_endpoint: endpoint,
    });

    // Create the WebVH Parameters using the provided update keys
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
                    "next_update Secret Key was missing public key information! {e}"
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

    // Create the WebVH DID
    let mut didwebvh = DIDWebVHState::default();
    let log_entry = didwebvh.create_log_entry(
        None,
        &serde_json::to_value(&did_document)?,
        &parameters,
        &update_secret,
    )?;

    let did_id = log_entry.get_state().get("id").unwrap().as_str().unwrap();

    // Change the key ID's to match the DID VM ID's
    keys.signing.secret.id = [did_id, "#key-1"].concat();
    keys.authentication.secret.id = [did_id, "#key-2"].concat();
    keys.decryption.secret.id = [did_id, "#key-3"].concat();

    // Save the DID to local file
    log_entry.log_entry.save_to_file("did.jsonl")?;

    Ok((
        did_id.to_string(),
        serde_json::from_value(log_entry.get_did_document()?)?,
    ))
}
