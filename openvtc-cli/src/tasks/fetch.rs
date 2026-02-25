use std::sync::Arc;

use crate::{
    CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED,
    interactions::vrc::handle_inbound_vrc_issued,
    messaging::{handle_inbound_ping, handle_inbound_pong},
    relationships::inbound::ConfigRelationships,
    tasks::TaskType,
};
use affinidi_tdk::{
    TDK,
    messaging::{
        messages::{DeleteMessageRequest, FetchDeletePolicy, fetch::FetchOptions},
        profiles::ATMProfile,
    },
};
use anyhow::{Result, anyhow};
use console::{Term, style};
use openvtc::{
    MessageType,
    config::Config,
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody},
    vrc::VRCRequestReject,
};

/// Fetches tasks from the DIDComm mediator and returns the number of new tasks retrieved
pub async fn fetch_tasks(
    tdk: &TDK,
    config: &mut Config,
    term: &Term,
    profile: &Arc<ATMProfile>,
) -> Result<u32> {
    let atm = tdk.atm.clone().unwrap();
    let our_did = profile.dids()?.0.to_string();

    print!(
        "{}{}",
        style("Fetching tasks for DID: ").color256(CLI_BLUE),
        style(&our_did).color256(CLI_PURPLE)
    );
    let _ = term.hide_cursor();
    let _ = term.flush();
    let msgs = atm
        .fetch_messages(
            profile,
            &FetchOptions {
                limit: 100,
                start_id: None,
                delete_policy: FetchDeletePolicy::DoNotDelete,
            },
        )
        .await?;

    let _ = term.show_cursor();
    println!(
        " {}{}",
        style("✅ tasks fetched: ").color256(CLI_GREEN),
        style(msgs.success.len()).color256(CLI_PURPLE),
    );

    let mut task_count: u32 = 0;
    let mut delete_list = DeleteMessageRequest::default();

    for msg in &msgs.success {
        task_count += 1;
        if let Some(message) = &msg.msg {
            // Ensure message is deleted after processing
            delete_list.message_ids.push(msg.msg_id.clone());

            let unpacked_msg = match atm.unpack(message).await {
                Ok((msg, _)) => msg,
                Err(e) => {
                    println!(
                        "{} {}",
                        style("WARN: Message fetched, but the DIDComm envelope is bad. Error:")
                            .color256(CLI_ORANGE),
                        style(e).color256(CLI_ORANGE)
                    );
                    println!("DIDComm bad enevlope:\n{:#?}", message);
                    continue;
                }
            };

            // No anonymous messages are allowed
            let from_did = if let Some(did) = &unpacked_msg.from {
                Arc::new(did.to_string())
            } else {
                // Ignore this TASK as it is anonymous
                println!("{}", style("WARN: An anonymous message has been received. These are not allowed as there is no ability to reply/respond to an anonymous message. Ignoring this message").color256(CLI_ORANGE));
                delete_list.message_ids.push(unpacked_msg.id.clone());
                continue;
            };

            let to_did = if let Some(to) = &unpacked_msg.to {
                if to.contains(&our_did) {
                    // Message is addressed to us
                    Arc::new(our_did.clone())
                } else {
                    // Ignore this TASK as it isn't addressed to us
                    println!("{}", style("WARN: An incoming message is not addressed to our Profile DID. Ignoring this message for safety.").color256(CLI_ORANGE));
                    println!(
                        "  {}{}",
                        style("from: ").color256(CLI_ORANGE),
                        style(from_did).color256(CLI_PURPLE)
                    );
                    delete_list.message_ids.push(unpacked_msg.id.clone());
                    continue;
                }
            } else {
                // Ignore this TASK as it isn't addressed correctly
                println!("{}", style("WARN: An incoming message is missing the to: address field. This is going to be ignored for safety.").color256(CLI_ORANGE));
                println!(
                    "  {}{}",
                    style("from: ").color256(CLI_ORANGE),
                    style(from_did).color256(CLI_PURPLE)
                );
                delete_list.message_ids.push(unpacked_msg.id.clone());
                continue;
            };

            let (task_type_style, task_type) = if let Ok(msg_type) =
                MessageType::try_from(&unpacked_msg)
            {
                match msg_type {
                    MessageType::RelationshipRequest => {
                        let task_type = TaskType::RelationshipRequestInbound {
                            from: from_did.clone(),
                            to: to_did.clone(),
                            request: serde_json::from_value(unpacked_msg.body)?,
                        };
                        config
                            .private
                            .tasks
                            .new_task(&Arc::new(unpacked_msg.id.clone()), task_type.clone());
                        (
                            style(msg_type.friendly_name()).color256(CLI_GREEN),
                            task_type,
                        )
                    }
                    MessageType::RelationshipRequestRejected => {
                        let task_id = if let Some(task_id) = &unpacked_msg.thid {
                            Arc::new(task_id.to_string())
                        } else {
                            println!(
                                "{}",
                                style(
                                    "WARN: A Relationship request rejection message was received, but has no `thid` header. Can't do anything with this..."
                                )
                            );
                            continue;
                        };

                        let body: RelationshipRejectBody = match serde_json::from_value(
                            unpacked_msg.body,
                        ) {
                            Ok(body) => body,
                            Err(e) => {
                                println!(
                                    "{}",
                                    style(format!(
                                        "WARN: Invalid body receieved for relationship request rejection message. Reason: {}",
                                        e
                                    ))
                                );
                                continue;
                            }
                        };
                        if let Err(e) =
                            config.handle_relationship_reject(&task_id, body.reason.as_deref())
                        {
                            println!("{}", style(format!("WARN: An error occurred when processing a relationship request rejection response. Error: {}", e)).color256(CLI_ORANGE));
                            continue;
                        }
                        (
                            style(format!(
                                "Relationship request rejected. Reason: {}",
                                body.reason.unwrap_or("None given".to_string())
                            ))
                            .color256(CLI_ORANGE),
                            TaskType::RelationshipRequestRejected,
                        )
                    }
                    MessageType::RelationshipRequestAccepted => {
                        let task_id = if let Some(task_id) = &unpacked_msg.thid {
                            Arc::new(task_id.to_string())
                        } else {
                            println!(
                                "{}",
                                style(
                                    "WARN: A Relationship request accept message was received, but has no `thid` header. Can't do anything with this..."
                                )
                            );
                            continue;
                        };

                        let body: RelationshipAcceptBody = match serde_json::from_value(
                            unpacked_msg.body,
                        ) {
                            Ok(body) => body,
                            Err(e) => {
                                println!(
                                    "{}",
                                    style(format!(
                                        "WARN: Invalid body receieved for relationship request accept message. Reason: {}",
                                        e
                                    ))
                                );
                                continue;
                            }
                        };
                        if let Err(e) = config
                            .handle_relationship_inbound_accept(tdk, &from_did, &task_id, &body.did)
                            .await
                        {
                            println!("{}", style(format!("WARN: An error occurred when processing a relationship request accept response. Error: {}", e)).color256(CLI_ORANGE));
                            continue;
                        }
                        (
                            style("Relationship request accepted".to_string()).color256(CLI_GREEN),
                            TaskType::RelationshipRequestAccepted,
                        )
                    }
                    MessageType::RelationshipRequestFinalize => {
                        let task_id = if let Some(task_id) = &unpacked_msg.thid {
                            Arc::new(task_id.to_string())
                        } else {
                            println!(
                                "{}",
                                style(
                                    "WARN: A Relationship request finalize message was received, but has no `thid` header. Can't do anything with this..."
                                )
                            );
                            continue;
                        };

                        if let Err(e) = config
                            .handle_relationship_inbound_finalize(&from_did, &task_id)
                            .await
                        {
                            println!("{}", style(format!("WARN: An error occurred when processing a relationship request finalize response. Error: {}", e)).color256(CLI_ORANGE));
                            continue;
                        }

                        config.private.tasks.remove(&task_id);
                        (
                            style("Relationship request finalized".to_string()).color256(CLI_GREEN),
                            TaskType::RelationshipRequestFinalized,
                        )
                    }
                    MessageType::TrustPing => {
                        match handle_inbound_ping(tdk, config, &from_did, &to_did, &unpacked_msg)
                            .await
                        {
                            Ok(relationship) => (
                                style(format!(
                                    "Relationship trust-ping received from({})",
                                    &from_did
                                ))
                                .color256(CLI_GREEN),
                                TaskType::TrustPing {
                                    from: from_did.clone(),
                                    to: to_did.clone(),
                                    relationship,
                                },
                            ),
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                    MessageType::TrustPong => {
                        let task_id = if let Some(task_id) = &unpacked_msg.thid {
                            Arc::new(task_id.to_string())
                        } else {
                            println!(
                                "{}",
                                style(
                                    "WARN: A Trust-Ping response was reeceived, but has no thread-id (`thid`). Can't process this message..."
                                )
                            );
                            continue;
                        };

                        match handle_inbound_pong(config, &from_did, &to_did, &task_id) {
                            Ok(relationship) => (
                                style(format!(
                                    "Relationship trust-ping received from({})",
                                    &from_did
                                ))
                                .color256(CLI_GREEN),
                                TaskType::TrustPing {
                                    from: from_did.clone(),
                                    to: to_did.clone(),
                                    relationship,
                                },
                            ),
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                    MessageType::VRCRequest => {
                        let task_type = TaskType::VRCRequestInbound {
                            request: serde_json::from_value(unpacked_msg.body)?,
                            relationship: config
                                .private
                                .relationships
                                .find_by_remote_did(&from_did)
                                .ok_or(anyhow!("Couldn't find relationship for this VRC Request"))?
                                .clone(),
                        };

                        config
                            .private
                            .tasks
                            .new_task(&Arc::new(unpacked_msg.id.clone()), task_type.clone());
                        (
                            style(msg_type.friendly_name()).color256(CLI_GREEN),
                            task_type,
                        )
                    }
                    MessageType::VRCRequestRejected => {
                        let Some(task_id) = &unpacked_msg.thid else {
                            println!(
                                "{}",
                                style(
                                    "WARN: A VRC request rejection message was received, but has no `thid` header. Can't do anything with this..."
                                )
                            );
                            continue;
                        };

                        let body: VRCRequestReject = match serde_json::from_value(unpacked_msg.body)
                        {
                            Ok(body) => body,
                            Err(e) => {
                                println!(
                                    "{}",
                                    style(format!(
                                        "WARN: Invalid body receieved for VRC request rejection message. Reason: {}",
                                        e
                                    ))
                                );
                                continue;
                            }
                        };
                        if let Err(e) = config.handle_vrc_reject(
                            &Arc::new(task_id.to_string()),
                            body.reason.as_deref(),
                            &from_did,
                        ) {
                            println!("{}", style(format!("WARN: An error occurred when processing a VRC request rejection response. Error: {}", e)).color256(CLI_ORANGE));
                            continue;
                        }
                        (
                            style("VRC request rejected".to_string()).color256(CLI_ORANGE),
                            TaskType::VRCRequestRejected,
                        )
                    }
                    MessageType::VRCIssued => {
                        match handle_inbound_vrc_issued(tdk, config, &unpacked_msg).await {
                            Ok(vrc) => (
                                style(format!("Signed VRC received from({})", &from_did))
                                    .color256(CLI_GREEN),
                                TaskType::VRCIssued { vrc: Box::new(vrc) },
                            ),
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                    _ => {
                        println!(
                            "{}{}",
                            style("ERROR: Unknown MessageType received: ").color256(CLI_RED),
                            style::<String>(msg_type.into()).color256(CLI_ORANGE)
                        );
                        continue;
                    }
                }
            } else {
                println!(
                    "{}{}",
                    style("INVALID Task Type: ").color256(CLI_RED),
                    style(unpacked_msg.type_).color256(CLI_ORANGE)
                );
                continue;
            };

            println!(
                "{}{} {}{}",
                style("Task Id: ").color256(CLI_BLUE),
                style(if let Some(thid) = unpacked_msg.thid.as_deref() {
                    thid
                } else {
                    &unpacked_msg.id
                })
                .color256(CLI_PURPLE),
                style("Type: ").color256(CLI_BLUE),
                style(task_type_style).color256(CLI_PURPLE),
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!(
                    "Fetched: Task ID({}) Type({}) From({}) To({})",
                    if let Some(thid) = unpacked_msg.thid.as_deref() {
                        thid
                    } else {
                        &unpacked_msg.id
                    },
                    task_type,
                    from_did,
                    &to_did
                ),
            );
        } else {
            println!(
                "{}",
                style("ERROR: Task fetched, but no message was found!").color256(CLI_RED)
            );
        }
        println!();
    }

    // Delete messages as we have retrieved them
    if !delete_list.message_ids.is_empty() {
        match atm.delete_messages_direct(profile, &delete_list).await {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "{}",
                    style(format!(
                        "WARN: Couldn't delete tasks from server. Reason: {}",
                        e
                    ))
                    .color256(CLI_ORANGE)
                );
            }
        }
    }

    Ok(task_count)
}
