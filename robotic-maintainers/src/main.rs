/// Robotic auto-responders for maintainers
/// You will need to create a TDK Environments file to hold the identity information for the
/// robotic maintainers
use affinidi_tdk::{
    TDK,
    common::config::TDKConfig,
    data_integrity::DataIntegrityProof,
    didcomm::{Message, PackEncryptedOptions, UnpackMetadata},
    messaging::{
        ATM,
        config::ATMConfig,
        messages::{FetchDeletePolicy, fetch::FetchOptions},
        profiles::ATMProfile,
        transports::websockets::WebSocketResponses,
    },
    secrets_resolver::SecretsResolver,
};
use dtg_credentials::DTGCredential;
use std::{collections::HashMap, env, sync::Arc};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use clap::Parser;
use openvtc::{
    MessageType,
    relationships::{
        RelationshipRequestBody, create_send_message_accepted, create_send_message_rejected,
    },
    vrc::DtgCredentialMessage,
};
use tokio::select;
use tracing::{info, warn};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,
}

struct Relationship {
    pub created: DateTime<Utc>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = Args::parse();

    let environment_name = if let Some(environment_name) = &args.environment {
        environment_name.to_string()
    } else if let Ok(environment_name) = env::var("TDK_ENVIRONMENT") {
        environment_name
    } else {
        "default".to_string()
    };

    println!("Using Environment: {}", environment_name);

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    // Instantiate TDK
    let tdk = TDK::new(
        TDKConfig::builder()
            .with_environment_name(environment_name.clone())
            .with_use_atm(false)
            .build()?,
        None,
    )
    .await?;

    // Custom Trusted Messaging interface, where all messsages for all profiles will come in on a
    // single channel

    let atm = ATM::new(
        ATMConfig::builder()
            .with_inbound_message_channel(10)
            .build()
            .unwrap(),
        tdk.get_shared_state(),
    )
    .await?;

    let environment = &tdk.get_shared_state().environment;
    let Some(mut inbound_channel) = atm.get_inbound_channel() else {
        bail!("Couldn't get ATM aggregated inbound channel");
    };

    let Some(mediator_did) = &environment.default_mediator else {
        println!("There is no default mediator set in the TDK environment configuration!");
        bail!("No default mediator!");
    };

    // Activate Ada Profile
    let tdk_ada = if let Some(ada) = environment.profiles.get("Ada") {
        tdk.add_profile(ada).await;
        ada
    } else {
        bail!("Ada not found in Environment: {}", environment_name);
    };

    let atm_ada = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, tdk_ada).await?, false)
        .await?;
    info!("{} profile loaded", atm_ada.inner.alias);

    // Activate Alan Profile
    let tdk_alan = if let Some(alan) = environment.profiles.get("Alan") {
        tdk.add_profile(alan).await;
        alan
    } else {
        bail!("Alan not found in Environment: {}", environment_name);
    };

    let atm_alan = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, tdk_alan).await?, false)
        .await?;
    info!("{} profile loaded", atm_alan.inner.alias);

    // Activate Grace Profile
    let tdk_grace = if let Some(grace) = environment.profiles.get("Grace") {
        tdk.add_profile(grace).await;
        grace
    } else {
        bail!("Grace not found in Environment: {}", environment_name);
    };

    let atm_grace = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, tdk_grace).await?, false)
        .await?;
    info!("{} profile loaded", atm_grace.inner.alias);

    // Activate Charles Profile
    let tdk_charles = if let Some(charles) = environment.profiles.get("Charles") {
        tdk.add_profile(charles).await;
        charles
    } else {
        bail!("Charles not found in Environment: {}", environment_name);
    };

    let atm_charles = atm
        .profile_add(
            &ATMProfile::from_tdk_profile(&atm, tdk_charles).await?,
            false,
        )
        .await?;
    info!("{} profile loaded", atm_charles.inner.alias);

    // Create an in-memory cache of relationships for incoming requests
    let mut relationships: HashMap<String, Relationship> = HashMap::new();

    // Clean up any existing messages in all profiles
    cleanup_existing(&atm, mediator_did, &atm_ada, &mut relationships).await;
    cleanup_existing(&atm, mediator_did, &atm_grace, &mut relationships).await;
    cleanup_existing(&atm, mediator_did, &atm_alan, &mut relationships).await;
    cleanup_existing(&atm, mediator_did, &atm_charles, &mut relationships).await;

    // Enable websocket live streaming
    let _ = atm.profile_enable_websocket(&atm_ada).await;
    let _ = atm.profile_enable_websocket(&atm_grace).await;
    let _ = atm.profile_enable_websocket(&atm_alan).await;
    let _ = atm.profile_enable_websocket(&atm_charles).await;

    info!("Main loop running...");
    loop {
        select! {
            // Listen for inbound messages for all profiles
            Ok(WebSocketResponses::MessageReceived(inbound_message, meta)) = inbound_channel.recv() => {
                handle_message( &atm, mediator_did, &inbound_message, &meta, &mut relationships).await;
            }

        }
    }
}

// Handles an inbound message for all profiles
async fn handle_message(
    atm: &ATM,
    mediator: &str,
    message: &Message,
    meta: &UnpackMetadata,
    relationships: &mut HashMap<String, Relationship>,
) {
    let to_profile = if let Some(to) = &message.to
        && let Some(first) = to.first()
        && let Some(profile) = atm.find_profile(first).await
    {
        profile
    } else {
        warn!("Invalid message to: address received: {:#?}", message.to);
        return;
    };

    // Ensure we are cleaning up after ourselves
    let _ = atm
        .delete_message_background(&to_profile, &meta.sha256_hash)
        .await;

    let from_did = if let Some(from) = &message.from {
        from.to_string()
    } else {
        warn!(
            "{}: Message receieved had no from: address! Ignoring...",
            to_profile.inner.alias
        );
        return;
    };

    if message.type_ == "https://didcomm.org/messagepickup/3.0/status" {
        // Status message, ignore
        return;
    }

    if let Ok(msg_type) = MessageType::try_from(message) {
        match msg_type {
            MessageType::RelationshipRequest => {
                // Inbound relationship request
                let body: RelationshipRequestBody =
                    match serde_json::from_value(message.body.clone()) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(
                                "{}: Couldn't serialize relationship request body: {e}",
                                to_profile.inner.alias
                            );
                            return;
                        }
                    };

                if body.did != from_did {
                    // Requestor is asking for a relationship-did wrapped channel which we don't
                    // support

                    match create_send_message_rejected(atm, &to_profile, &from_did, mediator, Some(&format!("Sorry, {} doesn't accept r-did based relationships. Only Persona-DID level relationships are allowed!", &to_profile.inner.alias)), &message.id).await {
                        Ok(_) => info!("{}: Rejected a relationship due to using r-dids. Remote: {}", to_profile.inner.alias, &from_did),
                        Err(e) => warn!("{}: Couldn't send a relationship rejection message: {}", to_profile.inner.alias, e),
                    }
                } else {
                    // Accept and send a relationship request accept message
                    match create_send_message_accepted(
                        atm,
                        &to_profile,
                        &from_did,
                        mediator,
                        &to_profile.inner.did,
                        &message.id,
                    )
                    .await
                    {
                        Ok(_) => info!(
                            "{}: Accepted a relationship from: {}",
                            to_profile.inner.alias, &from_did
                        ),
                        Err(e) => warn!(
                            "{}: Couldn't send a relationship accept message: {}",
                            to_profile.inner.alias, e
                        ),
                    }

                    relationships.insert(
                        from_did,
                        Relationship {
                            created: Utc::now(),
                        },
                    );
                }
            }
            MessageType::RelationshipRequestFinalize => {
                info!(
                    "{}: Relationship setup fully completed with: {}",
                    &to_profile.inner.alias, &from_did
                );
            }
            MessageType::VRCRequest => {
                // Create the VRC
                let vrc = match create_vrc(atm, &to_profile, &from_did, relationships).await {
                    Ok(vrc) => vrc,
                    Err(e) => {
                        warn!(
                            "{}: Couldn't create a VRC response from {} Reason: {}",
                            to_profile.inner.alias, &from_did, e
                        );
                        return;
                    }
                };

                // Send VRC to the requestor
                let msg = match vrc.message(&to_profile.inner.did, &from_did, Some(&message.id)) {
                    Ok(message) => message,
                    Err(e) => {
                        warn!(
                            "{}: Couldn't create VRC message to {} Reason: {}",
                            to_profile.inner.alias, &from_did, e
                        );
                        return;
                    }
                };

                // Pack the message
                let (msg, _) = match msg
                    .pack_encrypted(
                        &from_did,
                        Some(&to_profile.inner.did),
                        Some(&to_profile.inner.did),
                        &atm.get_tdk().did_resolver,
                        &atm.get_tdk().secrets_resolver,
                        &PackEncryptedOptions {
                            forward: false,
                            ..Default::default()
                        },
                    )
                    .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        warn!(
                            "{}: Couldn't pack VRC message to {} Reason: {}",
                            to_profile.inner.alias, &from_did, e
                        );
                        return;
                    }
                };

                match atm
                    .forward_and_send_message(
                        &to_profile,
                        false,
                        &msg,
                        None,
                        mediator,
                        &from_did,
                        None,
                        None,
                        false,
                    )
                    .await
                {
                    Ok(_) => info!("{}: Sent VRC to {}", to_profile.inner.alias, &from_did),
                    Err(e) => warn!(
                        "{}: Couldn't send VRC to {} Reason: {}",
                        to_profile.inner.alias, &from_did, e
                    ),
                }
            }
            _ => {
                // Is a message type that we are not interested in. Can safely ignore
                warn!(
                    "{}: Unknown Message: {:#?}",
                    to_profile.inner.alias, message
                );
            }
        }
    }
}

/// When starting, cleans up any queued messages for a given profile
async fn cleanup_existing(
    atm: &ATM,
    mediator: &str,
    profile: &Arc<ATMProfile>,
    relationships: &mut HashMap<String, Relationship>,
) {
    info!(
        "Cleaning up existing messages for profile: {}",
        profile.inner.alias
    );

    loop {
        let messages = atm
            .fetch_messages(
                profile,
                &FetchOptions {
                    limit: 50,
                    delete_policy: FetchDeletePolicy::Optimistic,
                    ..Default::default()
                },
            )
            .await;

        match messages {
            Ok(msgs) => {
                if msgs.success.is_empty() {
                    info!(
                        "No existing messages found for profile: {}",
                        profile.inner.alias
                    );
                    break;
                }

                for message in msgs.success {
                    let (msg, meta) = if let Some(msg) = &message.msg {
                        match atm.unpack(msg).await {
                            Ok((msg, meta)) => (msg, meta),
                            Err(e) => {
                                warn!(
                                    "{}: Couldn't unpack message. Reason: {e}",
                                    &profile.inner.alias
                                );
                                continue;
                            }
                        }
                    } else {
                        warn!(
                            "{}: Downloaded a message, but there was no message...",
                            profile.inner.alias
                        );
                        continue;
                    };
                    handle_message(atm, mediator, &msg, &meta, relationships).await;
                }
            }
            Err(e) => {
                warn!(
                    "Error fetching existing messages for profile: {}: {}",
                    profile.inner.alias, e
                );
                break;
            }
        }
    }
}

async fn create_vrc(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    remote_did: &str,
    relationships: &HashMap<String, Relationship>,
) -> Result<DTGCredential> {
    let mut vrc = DTGCredential::new_vrc(
        profile.inner.did.clone(),
        remote_did.to_string(),
        relationships
            .get(remote_did)
            .map(|r| r.created)
            .unwrap_or(Utc::now()),
        None,
    );

    let Some(secret) = atm
        .get_tdk()
        .secrets_resolver
        .get_secret([&profile.inner.did, "#key-0"].concat().as_str())
        .await
    else {
        warn!("{}: Couldn't find signing secret!", profile.inner.alias);
        bail!("Couldn't find sceret");
    };

    let proof = DataIntegrityProof::sign_jcs_data(&vrc, None, &secret, None)?;
    vrc.credential_mut().proof = Some(proof);

    Ok(vrc)
}
