/*!
*    Handles relationship requests
*/

use crate::{
    CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED,
    relationships::{RelationshipState, create_relationship_did},
};
use affinidi_tdk::{
    TDK,
    didcomm::{Message, PackEncryptedOptions},
};
use anyhow::{Result, bail};
use chrono::Utc;
use console::style;
use openvtc::{
    config::Config,
    logs::LogFamily,
    relationships::{Relationship, RelationshipRequestBody, create_send_message_rejected},
    tasks::TaskType,
};
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
    time::SystemTime,
};
use uuid::Uuid;

/// Creates a new Relationship Request and send it to the remote party
/// tdk: Trust Development Kit instance
/// config: mutable reference to the configuration
/// respondent: the remote alias or DID to create a relationship with
/// alias: optional alias for the remote DID if it doesn't exist in contacts
/// reason: Optional reason for creating this relationship request
/// generate_did: whether to generate a new local R-DID for the relationship
pub async fn create_send_request(
    tdk: &TDK,
    config: &mut Config,
    respondent: &str,
    alias: String,
    reason: Option<&str>,
    generate_did: bool,
) -> Result<()> {
    // Check if the remote DID exists in contacts
    let contact = if let Some(contact) = config.private.contacts.find_contact(respondent) {
        // Filter and check if established relationship exists
        if config
            .private
            .relationships
            .find_by_remote_did(&contact.did)
            .as_ref()
            .map(|r| r.lock().unwrap().state == RelationshipState::Established)
            .unwrap_or(false)
        {
            println!(
                "{} {}.",
                style("You have already established a relationship with").color256(CLI_ORANGE),
                style(contact.alias.as_deref().unwrap_or(&contact.did)).color256(CLI_PURPLE),
            );
            bail!("Established relationship already exists.");
        } else {
            contact
        }
    } else {
        // Create a new contact
        if respondent.starts_with("did:") {
            config
                .private
                .contacts
                .add_contact(tdk, respondent, Some(alias), true, &mut config.public.logs)
                .await?
        } else {
            println!(
                "{}",
                style(format!(
                    "ERROR: No contact found for '{}'. Please provide a valid DID or add the contact first.",
                    respondent
                )).color256(CLI_RED)
            );
            bail!("Not a valid DID");
        }
    };

    let atm = tdk.atm.clone().unwrap();

    // is a local relationship-did needed?
    let r_did = if generate_did {
        let mediator = config.public.mediator_did.clone(); // Clone so we can borrow config
        // as mutable below
        let r_did = Arc::new(create_relationship_did(tdk, config, &mediator).await?);
        println!(
            "{}{}{}{}",
            style("Generated new Relationship DID for contact ").color256(CLI_GREEN),
            style(contact.alias.as_deref().unwrap_or(&contact.did)).color256(CLI_PURPLE),
            style(" :: ").color256(CLI_GREEN),
            style(&r_did).color256(CLI_PURPLE)
        );
        r_did
    } else {
        config.public.persona_did.clone()
    };

    // Create the Relationship Request Message
    let msg = create_message_request(&config.public.persona_did, &contact.did, reason, &r_did)?;
    let msg_id = Arc::new(msg.id.clone());

    // Pack the message
    let (msg, _) = msg
        .pack_encrypted(
            &contact.did,
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

    atm.forward_and_send_message(
        &config.persona_did.profile,
        false,
        &msg,
        None,
        &config.public.mediator_did,
        &contact.did,
        None,
        None,
        false,
    )
    .await?;

    config.private.relationships.relationships.insert(
        contact.did.clone(),
        Arc::new(Mutex::new(Relationship {
            task_id: msg_id.clone(),
            our_did: r_did.clone(),
            remote_p_did: contact.did.clone(),
            remote_did: contact.did.clone(),
            created: Utc::now(),
            state: RelationshipState::RequestSent,
        })),
    );

    config.private.tasks.new_task(
        &msg_id,
        TaskType::RelationshipRequestOutbound {
            to: contact.did.clone(),
        },
    );

    println!();
    println!(
        "{}{}",
        style("✅ Successfully sent Relationship Request to ").color256(CLI_GREEN),
        style(&contact.did).color256(CLI_PURPLE)
    );

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Relationship requested: remote DID({}) Task ID({})",
            &contact.did, &msg_id
        ),
    );

    Ok(())
}

/// Creates the initial relationship request message
/// from: initiator P-DID
/// to: Respondent P-DID
/// reason: Optional reason for the relationship request
/// our_did: What DID to use for this relationship after creation (P-DID or R-DID
fn create_message_request(
    from: &str,
    to: &str,
    reason: Option<&str>,
    our_did: &Arc<String>,
) -> Result<Message> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let message = Message::build(
        Uuid::new_v4().into(),
        "https://linuxfoundation.org/openvtc/1.0/relationship-request".to_string(),
        json!(RelationshipRequestBody {
            reason: reason.map(|r| r.to_string()),
            did: our_did.to_string(),
        }),
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now)
    .expires_time(60 * 60 * 48) // 48 hours
    .finalize();

    Ok(message)
}

/// Sends a Relationship rejection message to the remote party
pub async fn send_rejection(
    tdk: &TDK,
    config: &mut Config,
    respondent: &str,
    reason: Option<&str>,
    task_id: &Arc<String>,
) -> Result<()> {
    // Create the Relationship Request rejection Message
    create_send_message_rejected(
        tdk.atm.as_ref().unwrap(),
        &config.persona_did.profile,
        respondent,
        &config.public.mediator_did,
        reason,
        task_id,
    )
    .await?;

    println!();
    println!(
        "{}{}",
        style("✅ Successfully sent Relationship Request Rejection to ").color256(CLI_GREEN),
        style(respondent).color256(CLI_PURPLE)
    );

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Relationship request rejected: remote DID({}) Task ID({})",
            respondent, task_id
        ),
    );

    Ok(())
}
