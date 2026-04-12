/*!
*   Everything to do with DIDComm messaging is contained within this module.
*/

use std::sync::{Arc, Mutex};

use crate::{CLI_ORANGE, CLI_PURPLE, CLI_RED};
use affinidi_tdk::{TDK, didcomm::Message};
use anyhow::{Context, Result, bail};
use console::style;
use openvtc::{config::Config, logs::LogFamily, relationships::Relationship};

/// Pings the mediator to check connectivity
/// uses the persona-DID as the TDK/ATM Profile
pub async fn ping_mediator(tdk: &mut TDK, config: &Config) -> Result<()> {
    let atm = tdk.atm.clone().context("ATM not initialized")?;

    atm.trust_ping()
        .send_ping(
            &config.persona_did.profile,
            &config.public.mediator_did,
            true,
            true,
            true,
        )
        .await?;

    Ok(())
}

/// Handles an inbound trust-ping message and replies if requested with a PONG response
/// Will only reply if there is an established relationship between the two DIDs
pub async fn handle_inbound_ping(
    tdk: &TDK,
    config: &mut Config,
    from: &Arc<String>,
    to: &Arc<String>,
    msg: &Message,
) -> Result<Arc<Mutex<Relationship>>> {
    // Check if there is a relationship between the two DIDs
    let relationship = if let Some(relationship) =
        config.private.relationships.find_by_remote_did(from)
    {
        relationship.clone()
    } else {
        println!("{}", style(format!("WARN: A ping message from ({}) was received, but there is not an established relationship for this DID!", from)).color256(CLI_ORANGE));
        bail!("Invalid Ping received");
    };

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Received ping from remote DID: {} via local DID: {}",
            from, to
        ),
    );

    // Expecting a pong message?
    if let Some(value) = msg.body.get("response_requested")
        && let Some(rr) = value.as_bool()
        && rr
    {
        // Response requested, send PONG
        let atm = tdk.atm.clone().context("ATM not initialized")?;

        let pong_msg = atm
            .trust_ping()
            .generate_pong_message(msg, Some(to.as_str()))?;

        let profile = if to == &config.public.persona_did {
            &config.persona_did.profile
        } else if let Some(profile) = config.atm_profiles.get(to) {
            profile
        } else {
            println!(
                "{}{}",
                style("ERROR: Couldn't find Messaging profile for DID: ").color256(CLI_RED),
                style(&to).color256(CLI_ORANGE)
            );
            bail!("Missing Messaging Profile");
        };

        openvtc::pack_and_send(
            &atm,
            profile,
            &pong_msg,
            to,
            from,
            &config.public.mediator_did,
        )
        .await?;

        config.public.logs.insert(
            LogFamily::Relationship,
            format!("Sent pong to remote DID: {} via local DID: {}", from, to),
        );
    }

    Ok(relationship)
}

/// Handles an inbound trust-pong message
pub fn handle_inbound_pong(
    config: &mut Config,
    from: &Arc<String>,
    to: &Arc<String>,
    task_id: &Arc<String>,
) -> Result<Arc<Mutex<Relationship>>> {
    // Check if there is a relationship between the two DIDs
    let relationship = if let Some(relationship) =
        config.private.relationships.find_by_remote_did(from)
    {
        relationship.clone()
    } else {
        println!("{}", style(format!("WARN: A ping response message from ({}) was received, but there is not an established relationship for this DID!", from)).color256(CLI_ORANGE));
        bail!("Invalid Ping response received");
    };

    if config.private.tasks.get_by_id(task_id).is_none() {
        println!("{}{}", style("WARN: A trust-ping response was received, but no task-id could be found for it! missing task-id: ").color256(CLI_ORANGE), style(task_id).color256(CLI_PURPLE));
        bail!("Couldn't find task-id for trust-ping response");
    };

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Received ping response from remote DID: {} via local DID: {}",
            from, to
        ),
    );

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Received pong from remote DID: {} to local DID: {}",
            from, to
        ),
    );

    config.private.tasks.remove(task_id);

    Ok(relationship)
}
