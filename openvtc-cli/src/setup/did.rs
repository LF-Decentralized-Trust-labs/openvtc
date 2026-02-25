/*!
*   DID Setup methods
*/

use crate::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED};
use affinidi_tdk::{
    TDK,
    common::config::TDKConfigBuilder,
    did_common::{
        Document,
        service::{Endpoint, Service},
        verification_method::{VerificationMethod, VerificationRelationship},
    },
    secrets_resolver::secrets::Secret,
};
use anyhow::{Context, Result};
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHState, parameters::Parameters, url::WebVHURL};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use openvtc::config::PersonaDIDKeys;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use url::Url;

/// Contains configuration info relating to the DID Setup
pub struct DIDConfig {
    /// DID identifier
    pub did: Arc<String>,
    /// DID Document
    pub document: Document,
}

/// Creates an initial DID representing the Persona DID
/// bip32_root: BIP32 root node for derived keys
/// keys: Persona Keys that will be used in the DID (Mutable as key ID's get updated)
/// mediator_did: What mediator to use for this DID?
/// imported_keys: True if keys have been imported
///   - True: Ask if you want to reuse an existing DID
///   - False: Create a new DID
pub async fn did_setup(
    bip32_root: ExtendedSigningKey,
    keys: &mut PersonaDIDKeys,
    mediator_did: &str,
    imported_keys: bool,
) -> Result<DIDConfig> {
    println!();
    println!("{}", style("Persona DID Setup").color256(CLI_BLUE));
    println!("{}", style("========================").color256(CLI_BLUE));

    if imported_keys {
        println!(
            "{}",
            style("As you have imported keys, would you like to reuse an existing DID?")
                .color256(CLI_BLUE)
        );
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Use pre-existing DID?")
            .default(true)
            .interact()
            .unwrap()
        {
            println!(
                "{}",
                style("Must be a WebVH DID Method!")
                    .bold()
                    .color256(CLI_BLUE)
            );
            loop {
                let did_id: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter existing DID")
                    .interact()
                    .unwrap();

                // Try to resolve the DID
                let tdk = TDK::new(
                    TDKConfigBuilder::new()
                        .with_load_environment(false)
                        .build()?,
                    None,
                )
                .await?;

                match tdk.did_resolver().resolve(&did_id).await {
                    Ok(response) => {
                        // Change the key ID's to match the DID VM ID's
                        keys.signing.secret.id = [&did_id, "#key-1"].concat();
                        keys.authentication.secret.id = [&did_id, "#key-2"].concat();
                        keys.decryption.secret.id = [&did_id, "#key-3"].concat();
                        return Ok(DIDConfig {
                            did: Arc::new(did_id),
                            document: response.doc,
                        });
                    }
                    Err(e) => {
                        println!(
                            "{}{}",
                            style("ERROR: Couldn't resolve DID. Reason: ").color256(CLI_RED),
                            style(e).color256(CLI_ORANGE)
                        );
                        if Confirm::with_theme(&ColorfulTheme::default())
                            .with_prompt("Would you like to try a different DID?")
                            .default(true)
                            .interact()
                            .unwrap()
                        {
                            continue;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    println!(
        "{}\n",
        style("A WebVH DID method will be created to represent your Persona DID.")
            .color256(CLI_BLUE)
    );
    println!(
        "{}\n{}\n",
        style("The WebVH method (`did:webvh`) extends `did:web` by adding verifiable history and")
            .color256(CLI_BLUE),
        style("stronger security - without relying on blockchain.").color256(CLI_BLUE)
    );
    println!(
        "{}\n{}\n",
        style("Your DID document must be publicly hosted.").color256(CLI_BLUE),
        style("GitHub pages or a similar platform is a simple place to start.").color256(CLI_BLUE)
    );

    let raw_url: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(
            "Enter the URL that will host your DID document (e.g., https://<your-domain>.com)",
        )
        .validate_with(|url: &String| {
            if Url::parse(url).is_ok() {
                Ok(())
            } else {
                Err("The URL provided is invalid. Please try again.\n")
            }
        })
        .interact()
        .unwrap();

    let did_url = WebVHURL::parse_url(&Url::parse(&raw_url)?)?;

    println!(
        "\n{}\n",
        style("Creating WebVH DID method for your Persona DID...").color256(CLI_BLUE)
    );
    println!(
        "{} {}",
        style("WebVH starting DID:").color256(CLI_BLUE),
        style(&did_url).color256(CLI_GREEN)
    );

    // Create the basic DID Document Structure
    let mut did_document = Document::new(&did_url.to_string())?;

    // Add the verification methods to the DID Document
    let mut property_set: HashMap<String, Value> = HashMap::new();

    // Signing Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(keys.signing.secret.get_public_keymultibase()?),
    );
    let key_id = Url::parse(&[did_url.to_string(), "#key-1".to_string()].concat())?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: Url::parse(&did_url.to_string())?,
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
        Value::String(keys.authentication.secret.get_public_keymultibase()?),
    );
    let key_id = Url::parse(&[did_url.to_string(), "#key-2".to_string()].concat())?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: Url::parse(&did_url.to_string())?,
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
        Value::String(keys.decryption.secret.get_public_keymultibase()?),
    );
    let key_id = Url::parse(&[did_url.to_string(), "#key-3".to_string()].concat())?;
    did_document.verification_method.push(VerificationMethod {
        id: key_id.clone(),
        type_: "Multikey".to_string(),
        controller: Url::parse(&did_url.to_string())?,
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
        id: Some(Url::parse(
            &[did_url.to_string(), "#public-didcomm".to_string()].concat(),
        )?),
        type_: vec!["DIDCommMessaging".to_string()],
        property_set: HashMap::new(),
        service_endpoint: endpoint,
    });

    // Create the WebVH Parameters
    let update_key = bip32_root
        .derive(&"m/2'/1'/0'".parse::<DerivationPath>().unwrap())
        .context("Failed to create an Ed25519 signing key.")?;
    let mut update_secret = Secret::generate_ed25519(None, Some(update_key.signing_key.as_bytes()));
    update_secret.id = [
        "did:key:",
        &update_secret.get_public_keymultibase()?,
        "#",
        &update_secret.get_public_keymultibase()?,
    ]
    .concat();

    let next_update_key = bip32_root
        .derive(&"m/2'/1'/1'".parse::<DerivationPath>().unwrap())
        .context("Failed to create an Ed25519 signing key.")?;
    let next_update_secret =
        Secret::generate_ed25519(None, Some(next_update_key.signing_key.as_bytes()));

    let parameters = Parameters::new()
        .with_key_pre_rotation(true)
        .with_update_keys(vec![update_secret.get_public_keymultibase()?])
        .with_next_key_hashes(vec![next_update_secret.get_public_keymultibase_hash()?])
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

    println!(
        "{}",
        style("WebVH Log Entry successfully created.").color256(CLI_BLUE)
    );
    let did_id = log_entry.get_state().get("id").unwrap().as_str().unwrap();

    println!(
        "{} {}",
        style("WebVH final DID:").color256(CLI_BLUE),
        style(did_id).color256(CLI_PURPLE)
    );

    // save to disk
    log_entry.log_entry.save_to_file("did.jsonl")?;
    println!(
        "{} {}",
        style("DID document saved:").color256(CLI_BLUE),
        style("did.jsonl").color256(CLI_GREEN)
    );

    // Change the key ID's to match the DID VM ID's
    keys.signing.secret.id = [did_id, "#key-1"].concat();
    keys.authentication.secret.id = [did_id, "#key-2"].concat();
    keys.decryption.secret.id = [did_id, "#key-3"].concat();

    println!();
    println!(
        "{} {} {}\n",
        style("To make your DID publicly resolvable, you'll need to host the").color256(CLI_BLUE),
        style("did.jsonl").color256(CLI_PURPLE),
        style("file at:").color256(CLI_BLUE),
    );
    println!(
        "{}\n",
        style(&did_url.get_http_url(None)?).color256(CLI_PURPLE),
    );
    println!(
        "{}\n",
        style("This file must be accessible at the specified URL before your DID can be resolved by others.").color256(CLI_BLUE),
    );

    Ok(DIDConfig {
        did: Arc::new(did_id.to_string()),
        document: serde_json::from_value(
            log_entry
                .get_did_document()
                .context("Couldn't get initial DID document state.")?,
        )
        .context("Serializing initial DID document state failed.")?,
    })
}
