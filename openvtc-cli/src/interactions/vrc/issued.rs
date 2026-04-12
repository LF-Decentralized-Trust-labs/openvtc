use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::{TDK, didcomm::Message};
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Local, Utc};
use console::style;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use dtg_credentials::{DTGCommon, DTGCredential};
use openvtc::{
    colors::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED, CLI_WHITE},
    config::Config,
    logs::LogFamily,
    relationships::Relationship,
    tasks::{Task, TaskType},
    vrc::DtgCredentialMessage,
};
use std::sync::{Arc, Mutex};

/// Handles an inbound VRC Issued Message
/// If related to a task, updates the Task information
/// If not, then creates a new task for the user to accept or reject the VRC
pub async fn handle_inbound_vrc_issued(
    tdk: &TDK,
    config: &mut Config,
    message: &Message,
) -> Result<DTGCredential> {
    // Valid VRC structure?
    let vrc: DTGCredential = match serde_json::from_value(message.body.clone()) {
        Ok(vrc) => vrc,
        Err(e) => {
            println!(
                "{}{}",
                style("ERROR: VRC issued body is not a valid VRC! Reason: ").color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
            bail!("Invalid VRC Body");
        }
    };

    let Some(proof) = vrc.credential().proof.clone() else {
        println!(
            "{}",
            style("ERROR: VRC issued does not contain a proof!").color256(CLI_RED)
        );
        bail!("VRC Missing Proof");
    };

    let check_vrc = DTGCommon {
        proof: None,
        ..vrc.credential().clone()
    };

    // Check the proof of the VRC
    match tdk.verify_data(&check_vrc, None, &proof).await {
        Ok(r) => {
            if r.verified {
                println!(
                    "{}",
                    style("✅ VRC proof verified successfully").color256(CLI_GREEN)
                );
            } else {
                println!(
                    "{}",
                    style("VRC Proof failed integrity checks.").color256(CLI_RED)
                );
                bail!("VRC Failed Data Integrity Check");
            }
        }
        Err(e) => {
            println!(
                "{}{}",
                style("ERROR: VRC Failed Proof validation. Reason: ").color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
            bail!("VRC Proof Validation Error");
        }
    }

    if let Some(thid) = &message.thid {
        if let Some(task) = config.private.tasks.get_by_id(&Arc::new(thid.to_string())) {
            let mut lock = task
                .lock()
                .map_err(|e| anyhow!("Task mutex poisoned: {e}"))?;
            lock.type_ = TaskType::VRCIssued {
                vrc: Box::new(vrc.clone()),
            };
            config.public.logs.insert(
                LogFamily::Relationship,
                format!("Inbound VRC issued updated Task ID({})", thid),
            );
            return Ok(vrc);
        } else {
            println!(
                "{}{}{}",
                style("WARN: A VRC was issued to you with a task-id (").color256(CLI_ORANGE),
                style(thid).color256(CLI_RED),
                style(") that can't be found. Creating a new task instead").color256(CLI_ORANGE)
            );
        }
    }

    // No task, create a new one
    let task = config.private.tasks.new_task(
        &Arc::new(message.id.clone()),
        TaskType::VRCIssued {
            vrc: Box::new(vrc.clone()),
        },
    );

    let task_id = task
        .lock()
        .map_err(|e| anyhow!("Task mutex poisoned: {e}"))?
        .id
        .clone();
    println!(
        "{} {}",
        style("Issued VRC received. New task created to accept/reject this VRC. Task ID:")
            .color256(CLI_GREEN),
        style(task_id).color256(CLI_PURPLE)
    );

    Ok(vrc)
}

/// Handles the user interaction for an inbound VRC that has been issued to you
pub fn interact_vrc_inbound(
    config: &mut Config,
    task: &Arc<Mutex<Task>>,
    vrc: Box<DTGCredential>,
) -> Result<bool> {
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
    println!();
    println!(
        "{}{}",
        style("VRC Issued By: ").color256(CLI_BLUE),
        style(vrc.issuer()).color256(CLI_PURPLE)
    );
    println!(
        "{}",
        style("Issued VRC:").color256(CLI_BLUE).bold().underlined()
    );
    println!(
        "{}",
        style(serde_json::to_string_pretty(&vrc)?).color256(CLI_WHITE)
    );
    println!();

    Ok(
        match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Task Action?")
            .item("Accept this VRC")
            .item("Delete this VRC")
            .item("Return to previous menu?")
            .interact()?
        {
            0 => {
                // Accept the VRC

                let relationship_p_did = if let Some(relationship) = config
                    .private
                    .relationships
                    .find_by_remote_did(&Arc::new(vrc.issuer().to_string()))
                {
                    relationship
                        .lock()
                        .map_err(|e| anyhow!("Relationship mutex poisoned: {e}"))?
                        .remote_p_did
                        .clone()
                } else {
                    println!(
                        "{}{}",
                        style("ERROR: Couldn't find relationship for Task ID: ").color256(CLI_RED),
                        style(&task_id).color256(CLI_ORANGE)
                    );
                    bail!("Couldn't find relationship for VRC Task");
                };
                config
                    .private
                    .vrcs_received
                    .insert(&relationship_p_did, Arc::new(*vrc))?;

                config.private.tasks.remove(&task_id);

                config.public.logs.insert(
                    LogFamily::Relationship,
                    format!("User accepted inbound VRC issued Task ID({})", task_id),
                );
                config
                    .public
                    .logs
                    .insert(LogFamily::Task, format!("Removing Task ID({})", task_id));

                println!();
                println!(
                    "{}",
                    style("✅ VRC accepted and stored locally.").color256(CLI_GREEN)
                );
                true
            }
            1 => {
                // Delete the VRC
                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to DELETE this VRC?")
                    .default(false)
                    .interact()?
                {
                    config.private.tasks.remove(&task_id);
                    config.public.logs.insert(
                        LogFamily::Task,
                        format!("User deleted inbound VRC issued Task ID({})", task_id),
                    );
                    println!(
                        "{}",
                        style("VRC deleted. No notification is sent to the issuer.")
                            .color256(CLI_ORANGE)
                    );
                    true
                } else {
                    false
                }
            }
            _ => false,
        },
    )
}

/// Interactive menu for generating a VRC Response
pub async fn handle_accept_vrcs_request(
    tdk: &TDK,
    config: &mut Config,
    task: &Arc<Mutex<Task>>,
    relationship: &Arc<Mutex<Relationship>>,
) -> Result<bool> {
    // Start collecting data for VRC Response
    let (our_r_did, their_p_did, their_r_did, r_created) = {
        let lock = relationship
            .lock()
            .map_err(|e| anyhow!("Relationship mutex poisoned: {e}"))?;
        (
            lock.our_did.clone(),
            lock.remote_p_did.clone(),
            lock.remote_did.clone(),
            lock.created,
        )
    };
    let task_id = {
        task.lock()
            .map_err(|e| anyhow!("Task mutex poisoned: {e}"))?
            .id
            .clone()
    };

    println!();
    println!("{}", style("VRC Configuration").color256(CLI_BLUE).bold());
    println!("{}", style("=================").bold().color256(CLI_BLUE));
    println!();

    let valid_from = match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the valid from date for this VRC:")
        .item(format!(
            "Use relationship established date: {}",
            r_created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ))
        .item("Use current date-time")
        .item("Specify a custom date-time")
        .default(0)
        .interact()?
    {
        0 => r_created,
        1 => Utc::now(),
        2 => {
            let now = Local::now();
            println!(
                "{}",
                style("The timestamp format must be in ISO 8601 Format.").color256(CLI_BLUE)
            );
            let custom_valid_from: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter a valid from date-time for this VRC (e.g., 2025-12-01T14:09:29+08:00): ")
            .default(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .validate_with(|input: &String| -> Result<(), &str> {
                if DateTime::parse_from_rfc3339(input).is_ok() {
                    Ok(())
                } else {
                    Err("Invalid date-time format. Use ISO 8601 format (e.g., 2025-12-01T14:09:29+08:00).")
                }
            })
            .interact_text()?;

            custom_valid_from.parse()?
        }
        _ => {
            println!("{}", style("ERROR: Invalid selection!").color256(CLI_RED));
            bail!("Invalid selection");
        }
    };

    let valid_until = if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Does this VRC have a valid until timestamp?")
        .default(false)
        .interact()?
    {
        let now = Local::now();
        println!(
            "{}",
            style("The timestamp format must be in ISO 8601 Format.").color256(CLI_BLUE)
        );
        let custom_valid_until: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter a valid until date-time for this VRC (e.g., 2025-12-01T14:09:29+08:00): ")
            .default(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .validate_with(|input: &String| -> Result<(), &str> {
                if DateTime::parse_from_rfc3339(input).is_ok() {
                    Ok(())
                } else {
                    Err("Invalid date-time format. Use ISO 8601 format (e.g., 2025-12-01T14:09:29+08:00).")
                }
            })
            .interact_text()?;

        Some(custom_valid_until.parse()?)
    } else {
        None
    };

    let mut vrc = DTGCredential::new_vrc(
        config.public.persona_did.to_string(),
        their_r_did.to_string(),
        valid_from,
        valid_until.map(|dt: chrono::DateTime<chrono::FixedOffset>| dt.to_utc()),
    );

    let secret = config.get_persona_keys(tdk).await?.signing.secret;

    let proof = DataIntegrityProof::sign_jcs_data(&vrc, None, &secret, None).await?;
    vrc.credential_mut().proof = Some(proof);

    // Send VRC to the requestor
    let msg = vrc.message(&our_r_did, &their_r_did, Some(&task_id))?;

    let atm = tdk
        .atm
        .clone()
        .ok_or_else(|| anyhow!("ATM not initialized"))?;

    openvtc::pack_and_send(
        &atm,
        &config.persona_did.profile,
        &msg,
        &our_r_did,
        &their_r_did,
        &config.public.mediator_did,
    )
    .await?;

    println!(
        "{}\n{}",
        style("Issued VRC").color256(CLI_BLUE).underlined().bold(),
        style(serde_json::to_string_pretty(&vrc)?).color256(CLI_WHITE)
    );

    config
        .private
        .vrcs_issued
        .insert(&their_p_did, Arc::new(vrc))?;

    config.public.logs.insert(
        LogFamily::Task,
        format!(
            "Issued VRC for remote P-DID({}) Task ID({})",
            their_p_did, task_id
        ),
    );

    config.private.tasks.remove(&task_id);

    Ok(true)
}
