/*!
*   Relationship Management
*/

use std::sync::Arc;

use crate::{
    CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED,
    relationships::messages::create_send_request,
};
use affinidi_tdk::{
    TDK,
    affinidi_crypto::ed25519::ed25519_private_to_x25519,
    didcomm::PackEncryptedOptions,
    dids::{DID, PeerKeyRole},
    messaging::protocols::Protocols,
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use anyhow::{Result, bail};
use chrono::Utc;
use clap::ArgMatches;
use console::style;
use ed25519_dalek_bip32::DerivationPath;
use openvtc::{
    config::{
        Config, KeyBackend, KeyTypes,
        protected_config::Contacts,
        secured_config::{KeyInfoConfig, KeySourceMaterial},
    },
    logs::LogFamily,
    relationships::{RelationshipState, Relationships},
    tasks::TaskType,
    vrc::Vrcs,
};

pub mod inbound;
pub mod messages;

// ****************************************************************************
// Relationships
// ****************************************************************************

pub trait RelationshipsExtension {
    fn status(
        &self,
        contacts: &Contacts,
        our_p_did: &Arc<String>,
        vrcs_sent: &Vrcs,
        vrcs_received: &Vrcs,
    );
    fn print_relationships(
        &self,
        contacts: &Contacts,
        our_p_did: &Arc<String>,
        vrcs_sent: &Vrcs,
        vrcs_received: &Vrcs,
    );
}

impl RelationshipsExtension for Relationships {
    /// Prints Relationship status to the console
    fn status(
        &self,
        contacts: &Contacts,
        our_p_did: &Arc<String>,
        vrcs_sent: &Vrcs,
        vrcs_received: &Vrcs,
    ) {
        println!("{}", style("Relationships").bold().color256(CLI_BLUE));
        println!("{}", style("=============").bold().color256(CLI_BLUE));

        println!(
            "{} {}",
            style("Relationships path pointer: ").color256(CLI_BLUE),
            style(self.path_pointer).color256(CLI_GREEN)
        );

        if self.relationships.is_empty() {
            println!(
                "{}",
                style("No relationships established yet.").color256(CLI_ORANGE)
            );
            return;
        }

        println!("{}", style("Relationships").color256(CLI_BLUE));
        self.print_relationships(contacts, our_p_did, vrcs_sent, vrcs_received);
    }

    fn print_relationships(
        &self,
        contacts: &Contacts,
        our_p_did: &Arc<String>,
        vrcs_sent: &Vrcs,
        vrcs_received: &Vrcs,
    ) {
        if self.relationships.is_empty() {
            println!("{}", style("No relationships exist").color256(CLI_ORANGE));
        } else {
            for r in self.relationships.values() {
                let r = r.lock().unwrap();
                let remote_p_did_alias = if let Some(contact) =
                    contacts.find_contact(&r.remote_p_did)
                    && let Some(alias) = &contact.alias
                {
                    style(alias.to_string()).color256(CLI_GREEN)
                } else {
                    style("N/A".to_string()).color256(CLI_ORANGE)
                };

                println!(
                    "  {}{}{}{}",
                    style("Remote DID: Alias: ").color256(CLI_BLUE),
                    remote_p_did_alias,
                    style(" Persona DID: ").color256(CLI_BLUE),
                    style(&r.remote_p_did).color256(CLI_GREEN),
                );

                if &r.our_did != our_p_did {
                    println!(
                        "    {}{}",
                        style("Using local r-did: ").color256(CLI_BLUE),
                        style(&r.our_did).color256(CLI_PURPLE)
                    );
                }

                if r.remote_did != r.remote_p_did {
                    println!(
                        "    {}{}",
                        style("Using remote r-did: ").color256(CLI_BLUE),
                        style(&r.remote_did).color256(CLI_PURPLE)
                    );
                }
                println!(
                    "    {}{}{}{}{}{}",
                    style("State: ").color256(CLI_BLUE),
                    style(&r.state).color256(CLI_GREEN),
                    style(" Created: ").color256(CLI_BLUE),
                    style(r.created).color256(CLI_GREEN),
                    style(" Task ID: ").color256(CLI_BLUE),
                    style(&r.task_id).color256(CLI_GREEN)
                );

                // Show VRC's
                println!(
                    "    {}{} {}{}",
                    style("VRCs Sent: ").color256(CLI_BLUE).bold(),
                    if let Some(vrcs) = vrcs_sent.get(&r.remote_p_did) {
                        if vrcs.is_empty() {
                            style("0".to_string()).color256(CLI_ORANGE)
                        } else {
                            style(vrcs.len().to_string()).color256(CLI_GREEN)
                        }
                    } else {
                        style("N/A".to_string()).color256(CLI_ORANGE)
                    },
                    style("VRCs Received: ").color256(CLI_BLUE).bold(),
                    if let Some(vrcs) = vrcs_received.get(&r.remote_p_did) {
                        if vrcs.is_empty() {
                            style("0".to_string()).color256(CLI_ORANGE)
                        } else {
                            style(vrcs.len().to_string()).color256(CLI_GREEN)
                        }
                    } else {
                        style("N/A".to_string()).color256(CLI_ORANGE)
                    },
                );
                println!();
            }
        }
    }
}

// ****************************************************************************
// Primary entry point for Relationships from the CLI
// ****************************************************************************

/// Primary entry point for the Relationships module from the CLI
pub async fn relationships_entry(
    tdk: TDK,
    config: &mut Config,
    profile: &str,
    args: &ArgMatches,
) -> Result<()> {
    match args.subcommand() {
        Some(("list", _)) => {
            config.private.relationships.print_relationships(
                &config.private.contacts,
                &config.public.persona_did,
                &config.private.vrcs_issued,
                &config.private.vrcs_received,
            );
        }
        Some(("request", sub_args)) => {
            let respondent = if let Some(respondent) = sub_args.get_one::<String>("respondent") {
                respondent.to_string()
            } else {
                println!(
                        "{}",
                        style("ERROR: You must specify the respondent alias or DID! Otherwise you are going to be lonely..").color256(CLI_RED)
                    );
                bail!("Respondent alias or DID is required");
            };
            let alias = if let Some(alias) = sub_args.get_one::<String>("alias") {
                alias.to_string()
            } else {
                println!(
                    "{}",
                    style("ERROR: Alias must be specified when requesting a Relationship!")
                        .color256(CLI_RED)
                );
                bail!("Missing alias argument!");
            };
            let reason = sub_args.get_one::<String>("reason");
            let generate_did = sub_args.get_flag("generate-did");

            create_send_request(
                &tdk,
                config,
                &respondent,
                alias,
                reason.map(|s| s.as_str()),
                generate_did,
            )
            .await?;

            config.save(
                profile,
                #[cfg(feature = "openpgp-card")]
                &|| {
                    eprintln!("Touch confirmation needed for decryption");
                },
            )?;
        }
        Some(("ping", sub_args)) => {
            let remote_did = if let Some(did) = sub_args.get_one::<String>("remote") {
                did.to_string()
            } else {
                println!(
                    "{}",
                    style("ERROR: You must specify the remote alias or DID!").color256(CLI_RED)
                );
                bail!("Remote alias or DID is required");
            };

            remote_ping(&tdk, config, &remote_did).await?;

            config.save(
                profile,
                #[cfg(feature = "openpgp-card")]
                &|| {
                    eprintln!("Touch confirmation needed for decryption");
                },
            )?;
        }
        Some(("remove", sub_args)) => {
            let remote_did = if let Some(did) = sub_args.get_one::<String>("remote") {
                did.to_string()
            } else {
                println!(
                    "{}",
                    style("ERROR: You must specify the remote alias or DID!").color256(CLI_RED)
                );
                bail!("Remote Alias or DID is required");
            };

            let Some(contact) = config.private.contacts.find_contact(&remote_did) else {
                println!(
                    "{}{}",
                    style("ERROR: Couldn't find a contact for: ").color256(CLI_RED),
                    style(remote_did).color256(CLI_ORANGE)
                );
                bail!("Couldn't find contact");
            };

            let relationship = if let Some(r) = config
                .private
                .relationships
                .find_by_remote_did(&contact.did)
            {
                r
            } else {
                println!(
                    "{} {}",
                    style("ERROR: No relationship found for remote DID/alias:").color256(CLI_RED),
                    style(remote_did).color256(CLI_ORANGE)
                );
                bail!("No relationship found for remote DID/alias");
            };

            let remote_p_did = {
                let lock = relationship.lock().unwrap();
                lock.remote_p_did.clone()
            };

            config.private.relationships.remove(
                &remote_p_did,
                &mut config.private.vrcs_issued,
                &mut config.private.vrcs_received,
            );

            println!(
                "{} {}",
                style("✅ Relationship with remote DID removed:").color256(CLI_GREEN),
                style(remote_p_did).color256(CLI_GREEN)
            );

            config.save(
                profile,
                #[cfg(feature = "openpgp-card")]
                &|| {
                    eprintln!("Touch confirmation needed for decryption");
                },
            )?;
        }
        _ => {
            println!(
                "{} {}",
                style("ERROR:").color256(CLI_RED),
                style(
                    "No valid relationships subcommand was used. Use --help for more information."
                )
                .color256(CLI_ORANGE)
            );
        }
    }

    Ok(())
}

// ****************************************************************************
// Create relationship DID (random DID:PEER)
// ****************************************************************************

/// Creates a random did:peer DID representing a relationship DID
/// Add the keys used to the Configuration (you need to save config elsewhere after this)
pub async fn create_relationship_did(
    tdk: &TDK,
    config: &mut Config,
    mediator: &str,
) -> Result<String> {
    // Derive a key path
    let v_path = [
        "m/3'/1'/1'/",
        config
            .private
            .relationships
            .path_pointer
            .to_string()
            .as_str(),
        "'",
    ]
    .concat();
    config.private.relationships.path_pointer += 1;
    let e_path = [
        "m/3'/1'/1'/",
        config
            .private
            .relationships
            .path_pointer
            .to_string()
            .as_str(),
        "'",
    ]
    .concat();
    config.private.relationships.path_pointer += 1;

    let bip32_root = match &config.key_backend {
        KeyBackend::Bip32 { root, .. } => root,
        _ => bail!("create_relationship_did requires a BIP32 key backend"),
    };

    let v_key = bip32_root
        .derive(&v_path.parse::<DerivationPath>()?)?;
    let e_key = bip32_root
        .derive(&e_path.parse::<DerivationPath>()?)?;

    let mut v_secret = Secret::generate_ed25519(None, Some(v_key.signing_key.as_bytes()));
    let mut e_secret = Secret::generate_x25519(
        None,
        Some(&ed25519_private_to_x25519(e_key.signing_key.as_bytes())),
    )?;

    let mut keys = vec![
        (PeerKeyRole::Verification, &mut v_secret),
        (PeerKeyRole::Encryption, &mut e_secret),
    ];
    let r_did = match DID::generate_did_peer_from_secrets(&mut keys, Some(mediator.to_string())) {
        Ok(did) => did,
        Err(e) => {
            println!(
                "{} {}",
                style("ERROR: Failed to create relationship DID:").color256(CLI_RED),
                style(e.to_string()).color256(CLI_ORANGE)
            );
            bail!("Failed to create relationship DID");
        }
    };

    // Add the secrets to the config
    config.key_info.insert(
        v_secret.id.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::Derived { path: v_path },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipVerification,
        },
    );
    config.key_info.insert(
        e_secret.id.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::Derived { path: e_path },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipEncryption,
        },
    );

    // Add the secrets to the TDK secret resolver
    tdk.get_shared_state()
        .secrets_resolver
        .insert(v_secret)
        .await;
    tdk.get_shared_state()
        .secrets_resolver
        .insert(e_secret)
        .await;

    Ok(r_did)
}

async fn remote_ping(tdk: &TDK, config: &mut Config, remote: &str) -> Result<()> {
    let atm = tdk.atm.clone().unwrap();
    let protocols = Protocols::new();

    let Some(contact) = config.private.contacts.find_contact(remote) else {
        println!(
            "{}{}",
            style("ERROR: Couldn't find a contact for: ").color256(CLI_RED),
            style(remote).color256(CLI_ORANGE)
        );
        bail!("Couldn't find contact for remote address");
    };

    // Find the relationship
    let relationship = if let Some(r) = config.private.relationships.get(&contact.did) {
        r
    } else {
        println!(
            "{} {}",
            style("ERROR: No relationship found for remote DID/alias:").color256(CLI_RED),
            style(remote).color256(CLI_ORANGE)
        );
        bail!("No relationship found for remote DID/alias");
    };

    let (our_did, remote_did) = {
        let lock = relationship.lock().unwrap();
        (lock.our_did.clone(), lock.remote_did.clone())
    };

    let profile = if our_did == config.public.persona_did {
        &config.persona_did.profile
    } else if let Some(profile) = config.atm_profiles.get(&our_did) {
        profile
    } else {
        println!(
            "{}{}",
            style("ERROR: Couldn't find Messaging profile for DID: ").color256(CLI_RED),
            style(&our_did).color256(CLI_ORANGE)
        );
        bail!("Missing Messaging Profile");
    };

    let ping_msg =
        protocols
            .trust_ping
            .generate_ping_message(Some(our_did.as_str()), &remote_did, true)?;
    let msg_id = ping_msg.id.clone();

    // Pack the message
    let (ping_msg, _) = ping_msg
        .pack_encrypted(
            &remote_did,
            Some(&our_did),
            Some(&our_did),
            tdk.did_resolver(),
            &tdk.get_shared_state().secrets_resolver,
            &PackEncryptedOptions {
                forward: false,
                ..Default::default()
            },
        )
        .await?;

    atm.forward_and_send_message(
        profile,
        false,
        &ping_msg,
        None,
        &config.public.mediator_did,
        &remote_did,
        None,
        None,
        false,
    )
    .await?;

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Sent ping to remote DID: {} via local DID: {}",
            remote_did, our_did
        ),
    );

    config.private.tasks.new_task(
        &Arc::new(msg_id),
        TaskType::TrustPing {
            from: our_did,
            to: remote_did,
            relationship,
        },
    );

    println!("{}", style("✅ Ping Successfully sent... Run openvtc tasks interactive to check for pong response. NOTE: The remote recipient needs to check their messages first!").color256(CLI_GREEN));

    Ok(())
}
