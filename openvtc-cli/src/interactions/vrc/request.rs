use affinidi_tdk::TDK;
use anyhow::{Result, anyhow, bail};
use console::style;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use openvtc::{
    colors::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED},
    config::Config,
    logs::LogFamily,
    relationships::Relationship,
    tasks::{Task, TaskType},
    vrc::{VRCRequestReject, VrcRequest},
};
use std::sync::{Arc, Mutex};

use super::{Print, generate_vrc_request_body, select_relationship};

/// Interactive VRC Rquest Flow
pub(super) async fn vrcs_interactive_request(tdk: &TDK, config: &mut Config) -> Result<bool> {
    println!(
        "{}",
        style("Select a relationship to request a VRC:").color256(CLI_BLUE)
    );
    let Some(relationship) = select_relationship(config) else {
        return Ok(false);
    };

    let request_body = generate_vrc_request_body()?;

    request_body.print();

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Send VRC request?")
        .default(true)
        .interact()?
    {
        let (from, to, to_p_did) = {
            let lock = relationship
                .lock()
                .map_err(|e| anyhow!("Relationship mutex poisoned: {e}"))?;
            (
                lock.our_did.clone(),
                lock.remote_did.clone(),
                lock.remote_p_did.clone(),
            )
        };

        let profile = if from == config.public.persona_did {
            &config.persona_did.profile
        } else if let Some(profile) = config.atm_profiles.get(&from) {
            profile
        } else {
            println!(
                "{}{}",
                style("ERROR: Couldn't find messaging profile for local relationship DID: ")
                    .color256(CLI_RED),
                style(from).color256(CLI_ORANGE)
            );
            bail!("Couldn't find ATM Profile for R-DID");
        };

        let message = request_body.create_message(&to, &from)?;
        let msg_id = Arc::new(message.id.clone());

        let atm = tdk
            .atm
            .clone()
            .ok_or_else(|| anyhow!("ATM not initialized"))?;

        openvtc::pack_and_send(
            &atm,
            profile,
            &message,
            &from,
            &to,
            &config.public.mediator_did,
        )
        .await?;

        // Create Task to track response
        let task = config
            .private
            .tasks
            .new_task(&msg_id, TaskType::VRCRequestOutbound { relationship });
        let task_id = {
            task.lock()
                .map_err(|e| anyhow!("Task mutex poisoned: {e}"))?
                .id
                .clone()
        };

        config.public.logs.insert(
            LogFamily::Relationship,
            format!("Requested a VRC from ({}) Task ID ({})", to_p_did, task_id),
        );

        println!(
            "{}{}",
            style("✅ Successfully sent VRC Request. Remote DID: ").color256(CLI_GREEN),
            style(&to).color256(CLI_PURPLE)
        );

        Ok(true)
    } else {
        println!(
            "{}",
            style("VRC Request cancelled. No changes made.").color256(CLI_ORANGE)
        );
        Ok(false)
    }
}

/// Interactive menu to manage an outbound VRC request
pub fn interact_vrc_outbound_request(
    config: &mut Config,
    task: &Arc<Mutex<Task>>,
    relationship: &Arc<Mutex<Relationship>>,
) -> Result<bool> {
    let to_p_did = {
        relationship
            .lock()
            .map_err(|e| anyhow!("Relationship mutex poisoned: {e}"))?
            .remote_p_did
            .clone()
    };
    let (task_id, task_created) = {
        let lock = task
            .lock()
            .map_err(|e| anyhow!("Task mutex poisoned: {e}"))?;
        (lock.id.clone(), lock.created)
    };

    println!(
        "{}{} {}{}",
        style("Task ID: ").color256(CLI_BLUE),
        style(&task_id).color256(CLI_GREEN),
        style("Created: ").color256(CLI_BLUE),
        style(task_created).color256(CLI_GREEN)
    );
    println!(
        "{}{}",
        style("VRC Request Sent To: ").color256(CLI_BLUE),
        style(&to_p_did).color256(CLI_PURPLE)
    );
    println!();

    match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Task Action?")
        .item("Delete this VRC request")
        .item("Return to previous menu?")
        .interact()?
    {
        0 => {
            // Delete this task
            println!("{}", style("When you delete a VRC request, no notification is sent to the remote DID. This means you may still receive a VRC in the future, it is safe to delete the VRC if one arrives.").color256(CLI_BLUE));
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Are you sure you want to DELETE this VRC request?")
                .default(false)
                .interact()?
            {
                config.private.tasks.remove(&task_id);
                config.public.logs.insert(
                    LogFamily::Task,
                    format!(
                        "Deleted VRC request to remote DID({}) Task ID({})",
                        to_p_did, task_id
                    ),
                );
                Ok(true)
            } else {
                Ok(false)
            }
        }
        1 => Ok(false),
        _ => Ok(false),
    }
}

/// Handles the menu for an interactive Inbound VRC Request
pub async fn interact_vrc_inbound_request(
    tdk: &TDK,
    config: &mut Config,
    task: &Arc<Mutex<Task>>,
    request: &VrcRequest,
    relationship: &Arc<Mutex<Relationship>>,
) -> Result<bool> {
    // Show details of the VRC Request
    println!();
    let (from, from_p_did, to) = {
        let lock = relationship
            .lock()
            .map_err(|e| anyhow!("Relationship mutex poisoned: {e}"))?;
        (
            lock.remote_did.clone(),
            lock.remote_p_did.clone(),
            lock.our_did.clone(),
        )
    };

    let task_id = {
        task.lock()
            .map_err(|e| anyhow!("Task mutex poisoned: {e}"))?
            .id
            .clone()
    };

    let alias = if let Some(contact) = config.private.contacts.find_contact(&from_p_did)
        && let Some(alias) = &contact.alias
    {
        style(alias.to_string()).color256(CLI_GREEN)
    } else {
        style("NO ALIAS".to_string()).color256(CLI_ORANGE)
    };

    println!(
        "{}{} {}{}",
        style("From: alias: ").color256(CLI_BLUE),
        alias,
        style(" P-DID: ").color256(CLI_BLUE),
        style(&from_p_did).color256(CLI_PURPLE)
    );
    println!(
        "{}{}",
        style("To: ").color256(CLI_BLUE),
        style(&to).color256(CLI_PURPLE)
    );

    request.print();
    println!();

    match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Task Action?")
        .item("Accept this VRC request")
        .item("Reject this VRC request")
        .item("Delete this VRC request (Does not notify the other party)")
        .item("Return to previous menu?")
        .interact()?
    {
        0 => {
            // Accept the VRC Request
            Ok(super::issued::handle_accept_vrcs_request(tdk, config, task, relationship).await?)
        }
        1 => {
            // Reject the VRC Request
            let reason: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt(
                    "Would you like to provide a reason for this rejection (Leave BLANK for None)?",
                )
                .allow_empty(true)
                .interact_text()?;

            let reason = if reason.trim().is_empty() {
                None
            } else {
                Some(reason.trim().to_string())
            };

            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Are you sure you want to reject this VRC request?")
                .default(true)
                .interact()?
            {
                let msg = VRCRequestReject::create_message(&from, &to, &task_id, reason.clone())?;

                let profile = if to == config.public.persona_did {
                    &config.persona_did.profile
                } else if let Some(profile) = config.atm_profiles.get(&to) {
                    profile
                } else {
                    println!(
                        "{}{}",
                        style("ERROR: Couldn't find Messaging profile for DID: ").color256(CLI_RED),
                        style(to).color256(CLI_ORANGE)
                    );
                    bail!("Couldn't find messaging profile for DID");
                };

                let atm = tdk
                    .atm
                    .clone()
                    .ok_or_else(|| anyhow!("ATM not initialized"))?;

                openvtc::pack_and_send(
                    &atm,
                    profile,
                    &msg,
                    &to,
                    &from,
                    &config.public.mediator_did,
                )
                .await?;

                config.private.tasks.remove(&task_id);
                config.public.logs.insert(
                    LogFamily::Task,
                    format!(
                        "Rejected VRC request from remote DID({}) Task ID({}) Reason: {}",
                        from,
                        task_id,
                        reason.as_deref().unwrap_or("NO REASON PROVIDED")
                    ),
                );

                println!();
                println!(
                    "{}{}",
                    style("✅ Successfully sent VRC Request Rejection to ").color256(CLI_GREEN),
                    style(to).color256(CLI_PURPLE)
                );

                Ok(true)
            } else {
                // Cancel rejection
                Ok(false)
            }
        }
        2 => {
            // Delete the VRC Request
            println!("{}", style("When you delete a VRC request, no response is sent back to the initiator of the request. Deleting acts as a silent ignore...").color256(CLI_BLUE));
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Are you sure you want to DELETE this VRC request?")
                .default(false)
                .interact()?
            {
                config.private.tasks.remove(&task_id);
                config.public.logs.insert(
                    LogFamily::Task,
                    format!(
                        "Deleted VRC request from remote DID({}) Task ID({})",
                        from_p_did, task_id
                    ),
                );
                Ok(true)
            } else {
                Ok(false)
            }
        }
        3 => Ok(false),

        _ => Ok(false),
    }
}
