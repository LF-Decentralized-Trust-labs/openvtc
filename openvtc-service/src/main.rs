use std::sync::Arc;

use crate::config::Config;
use affinidi_tdk::{
    common::TDKSharedState,
    didcomm::{Message, UnpackMetadata},
    messaging::{ATM, config::ATMConfig, profiles::ATMProfile, protocols::Protocols},
    secrets_resolver::SecretsResolver,
};
use anyhow::{Result, bail};
use openvtc::{MessageType, maintainers::create_send_maintainers_list};
use tracing::{info, warn};
use tracing_subscriber::filter;

mod config;

#[tokio::main]
async fn main() -> Result<()> {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    // Load Configuration
    let config = Config::load("conf/config.json")?;

    // Create a basic ATM instance
    let atm = ATM::new(
        ATMConfig::builder().build().unwrap(),
        Arc::new(TDKSharedState::default().await),
    )
    .await?;

    let profile = ATMProfile::new(
        &atm,
        Some("kernel.org".to_string()),
        config.our_did.clone(),
        Some(config.mediator.clone()),
    )
    .await?;

    // Add secrets to ATM
    atm.get_tdk()
        .secrets_resolver
        .insert_vec(&config.secrets)
        .await;

    // Start listening for incoming messages
    let profile = atm.profile_add(&profile, true).await?;

    let protocols = Protocols::new();

    loop {
        let (msg, meta) = match protocols
            .message_pickup
            .live_stream_next(&atm, &profile, None, true)
            .await
        {
            Ok(Some((msg, meta))) => (msg, meta),
            Ok(None) => {
                // No messages received - it is ok to continue the loop
                continue;
            }
            Err(e) => {
                warn!("an error occurred while waiting for new messages: {e}");
                continue;
            }
        };

        // A valid DIDComm message has been received
        let _ = handle_message(&atm, &profile, &config, &msg, &meta).await;
    }
}

async fn handle_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    config: &Config,
    msg: &Message,
    meta: &UnpackMetadata,
) -> Result<()> {
    // Ensure we are cleaning up after ourselves
    let _ = atm
        .delete_message_background(profile, &meta.sha256_hash)
        .await;

    let _ = if let Some(to) = &msg.to
        && let Some(first) = to.first()
    {
        first
    } else {
        warn!("Invalid message to: address received: {:#?}", msg.to);
        bail!("Couldn't get a valid to: address from message");
    };

    let from_did = if let Some(from) = &msg.from {
        from.to_string()
    } else {
        warn!("Message receieved had no from: address! Ignoring...",);
        bail!("Anonymous messages are not allowed!");
    };

    if msg.type_ == "https://didcomm.org/messagepickup/3.0/status" {
        // Status message, ignore
        return Ok(());
    }

    if let Ok(msg_type) = MessageType::try_from(msg) {
        match msg_type {
            MessageType::MaintainersListRequest => {
                // Return the list of Kernel Maintainers
                let _ = create_send_maintainers_list(
                    atm,
                    profile,
                    &from_did,
                    &config.mediator,
                    &config.maintainers,
                    &msg.id,
                )
                .await;
                info!("Maintainer list requested by {}", from_did);
            }
            _ => {
                warn!("Unsupported MessageType receieved: {}", msg.type_);
            }
        }
    }
    Ok(())
}
