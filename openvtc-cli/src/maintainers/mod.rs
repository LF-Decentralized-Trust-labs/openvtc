use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use crate::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED};
use affinidi_tdk::{
    TDK,
    didcomm::{Message, PackEncryptedOptions},
    messaging::protocols::Protocols,
};
use anyhow::{Result, bail};
use clap::ArgMatches;
use console::style;
use openvtc::{MessageType, config::Config, maintainers::Maintainer};
use serde_json::json;
use uuid::Uuid;

pub async fn maintainers_entry(tdk: TDK, config: &mut Config, args: &ArgMatches) -> Result<()> {
    match args.subcommand() {
        Some(("list", _)) => {
            get_maintainers_list(&tdk, config).await?;
        }
        _ => {
            println!(
                "{} {}",
                style("ERROR:").color256(CLI_RED),
                style("No valid maintainers subcommand was used. Use --help for more information.")
                    .color256(CLI_ORANGE)
            );
            bail!("Invalid CLI Options");
        }
    }
    Ok(())
}

async fn get_maintainers_list(tdk: &TDK, config: &Config) -> Result<()> {
    let message =
        create_message_maintainers_list(&config.public.persona_did, &config.public.lk_did)?;
    let msg_id = Arc::new(message.id.clone());

    // Pack the message
    let (message, _) = message
        .pack_encrypted(
            &config.public.lk_did,
            Some(&config.public.persona_did),
            Some(&config.public.persona_did),
            tdk.did_resolver(),
            &tdk.get_shared_state().secrets_resolver,
            &PackEncryptedOptions {
                forward: false,
                ..Default::default()
            },
        )
        .await?;

    // Enable streaming for the Profile account
    let atm = tdk.atm.clone().unwrap();
    let protocols = Protocols::new();

    protocols
        .message_pickup
        .toggle_live_delivery(&atm, &config.persona_did.profile, true)
        .await?;

    atm.forward_and_send_message(
        &config.persona_did.profile,
        false,
        &message,
        None,
        &config.public.mediator_did,
        &config.public.lk_did,
        None,
        None,
        false,
    )
    .await?;

    println!(
        "{}",
        style("Requesting list of known Maintainers").color256(CLI_GREEN)
    );

    match protocols
        .message_pickup
        .live_stream_get(
            &atm,
            &config.persona_did.profile,
            &msg_id,
            Duration::from_secs(10),
            true,
        )
        .await
    {
        Ok(Some((msg, _))) => {
            if let Ok(MessageType::MaintainersListResponse) = MessageType::try_from(&msg) {
                let maintainers: Vec<Maintainer> = match serde_json::from_value(msg.body) {
                    Ok(maintainers) => maintainers,
                    Err(e) => {
                        println!("{}{}", style("ERROR: Couldn't deserialize maintainers list from kernel.org Reason: ").color256(CLI_RED), style(e).color256(CLI_ORANGE));
                        bail!("Couldn't deserialize maintainers list")
                    }
                };

                if maintainers.is_empty() {
                    println!("{}", style("WARN: kernel.org doesn't seem to have any active maintainers right now! Please try again later!").color256(CLI_ORANGE));
                    return Ok(());
                }
                println!();
                println!(
                    "{}",
                    style("Maintainers").color256(CLI_BLUE).bold().underlined()
                );
                for maintainer in maintainers {
                    println!(
                        "{} {} {}",
                        style(maintainer.alias).color256(CLI_GREEN),
                        style(">>").color256(CLI_GREEN),
                        style(maintainer.did).color256(CLI_PURPLE)
                    );
                }
                println!();
            }
        }
        Ok(None) => {
            println!(
                "{}",
                style("WARN: TIMEOUT: A response from kernel.org was not received")
                    .color256(CLI_ORANGE)
            );
            return Ok(());
        }
        Err(e) => {
            println!("{}{}", style(":ERROR: An error occurred while waiting for a response from kernel.org Reason: ").color256(CLI_RED), style(e).color256(CLI_ORANGE));
            bail!("Couldn't retrieve maintainer list")
        }
    }

    Ok(())
}

/// DIDComm message to request list of kernel maintainers
fn create_message_maintainers_list(from: &str, to: &str) -> Result<Message> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let message = Message::build(
        Uuid::new_v4().into(),
        "https://kernel.org/maintainers/1.0/list".to_string(),
        json!({}),
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now)
    .expires_time(60 * 60 * 48) // 48 hours
    .finalize();

    Ok(message)
}
