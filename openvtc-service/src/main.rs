use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use affinidi_tdk::{
    common::TDKSharedState,
    didcomm::Message,
    messaging::messages::compat::UnpackMetadata,
    messaging::{ATM, config::ATMConfig, profiles::ATMProfile},
    secrets_resolver::SecretsResolver,
};
use anyhow::{Result, bail};
use clap::Parser;
use openvtc::{MessageType, maintainers::create_send_maintainers_list, protocol_urls};
use tracing::{info, warn};
use tracing_subscriber::filter;

mod config;

/// OpenVTC Service — background DIDComm message handler for community operations.
///
/// Listens for incoming DIDComm messages via a mediator and responds to protocol
/// requests (e.g. maintainer list queries). Configure logging verbosity with the
/// RUST_LOG environment variable (e.g. RUST_LOG=info or RUST_LOG=openvtc_service=debug).
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Path to the JSON configuration file
    #[arg(short, long, default_value = "conf/config.json")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    // Load Configuration
    let config = Config::load(&cli.config)?;

    // Create a basic ATM instance
    let atm = ATM::new(
        ATMConfig::builder().build()?,
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

    info!("Service started, listening for incoming messages...");

    tokio::select! {
        _ = message_loop(&atm, &profile, &config) => {
            warn!("Message loop exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received, exiting...");
        }
    }

    info!("Service shut down gracefully");
    Ok(())
}

async fn message_loop(atm: &ATM, profile: &Arc<ATMProfile>, config: &Config) {
    // Rate limiting: max 50 messages per second to prevent resource exhaustion
    const MAX_MSGS_PER_SEC: u32 = 50;
    let mut msg_count: u32 = 0;
    let mut window_start = Instant::now();

    loop {
        // Reset counter each second
        if window_start.elapsed() >= Duration::from_secs(1) {
            msg_count = 0;
            window_start = Instant::now();
        }

        if msg_count >= MAX_MSGS_PER_SEC {
            warn!("Rate limit reached ({MAX_MSGS_PER_SEC} msgs/sec), throttling");
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        let (msg, meta) = match atm
            .message_pickup()
            .live_stream_next(profile, None, true)
            .await
        {
            Ok(Some((msg, meta))) => (msg, meta),
            Ok(None) => continue,
            Err(e) => {
                warn!("an error occurred while waiting for new messages: {e}");
                continue;
            }
        };

        msg_count += 1;

        if let Err(e) = handle_message(atm, profile, config, &msg, &meta).await {
            warn!("Failed to handle incoming DIDComm message: {e}");
        }
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
    if let Err(e) = atm
        .delete_message_background(profile, &meta.sha256_hash)
        .await
    {
        warn!("Failed to delete processed message from mediator: {e}");
    }

    let _ = if let Some(to) = &msg.to
        && let Some(first) = to.first()
    {
        first
    } else {
        warn!("Invalid message to: address received: {:#?}", msg.to);
        bail!("Couldn't get a valid to: address from message");
    };

    let from_did = match openvtc::require_from(msg) {
        Ok(did) => did,
        Err(_) => {
            warn!("Message received had no from: address! Ignoring...");
            bail!("Anonymous messages are not allowed!");
        }
    };

    if msg.typ == protocol_urls::MESSAGEPICKUP_STATUS {
        // Status message, ignore
        return Ok(());
    }

    if let Ok(msg_type) = MessageType::try_from(msg) {
        match msg_type {
            MessageType::MaintainersListRequest => {
                // Return the list of Kernel Maintainers
                if let Err(e) = create_send_maintainers_list(
                    atm,
                    profile,
                    &from_did,
                    &config.mediator,
                    &config.maintainers,
                    &msg.id,
                )
                .await
                {
                    warn!("Failed to send maintainers list to {from_did}: {e}");
                } else {
                    info!("Maintainer list requested by {}", from_did);
                }
            }
            _ => {
                warn!("Unsupported MessageType received: {}", msg.typ);
            }
        }
    }
    Ok(())
}
