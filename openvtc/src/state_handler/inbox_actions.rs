//! Inbox task action handlers.
//!
//! These functions process user decisions on inbox tasks (accept/reject
//! relationship requests, accept VRCs, dismiss tasks). They operate on
//! `&mut Config` and `&TDK` owned by the StateHandler.

use std::sync::{Arc, Mutex};

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::TDK;
use affinidi_tdk::didcomm::Message;
use anyhow::Result;
use chrono::Utc;
use openvtc_core::{
    config::Config,
    logs::LogFamily,
    relationships::{
        Relationship, RelationshipAcceptBody, RelationshipRejectBody, RelationshipState,
    },
    tasks::TaskType,
};
use serde_json::json;
use tracing::{debug, info, warn};

/// Accept an inbound relationship request.
///
/// When `generate_r_did` is true and the key backend is BIP32, a unique
/// relationship DID (did:peer) is derived for privacy. Otherwise the
/// persona DID is used directly.
pub async fn accept_relationship_request(
    config: &mut Config,
    tdk: &TDK,
    service: &DIDCommService,
    task_id: &str,
    generate_r_did: bool,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> Result<()> {
    let task_id = Arc::new(task_id.to_string());

    // Find the task and extract request data
    let (from_did, their_did, sender_name) = {
        let task_arc = Arc::clone(
            config
                .private
                .tasks
                .get_by_id(&task_id)
                .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?,
        );
        let task = task_arc
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        match &task.type_ {
            TaskType::RelationshipRequestInbound { from, request, .. } => {
                // Sanitize the sender-supplied name before it persists as a
                // contact alias — strips ANSI / control chars / bidi-overrides
                // / zero-width chars. Hard-cap at 64 chars so a hostile peer
                // can't dominate the relationships list.
                let sanitized_name = request
                    .name
                    .as_deref()
                    .map(|n| super::main_page::sanitize_display(n, 64));
                (Arc::clone(from), request.did.clone(), sanitized_name)
            }
            _ => anyhow::bail!("task {} is not an inbound relationship request", task_id),
        }
    };

    // Optionally generate a random relationship DID for privacy.
    // The R-DID is exchanged in the message body but NOT used for routing
    // during the handshake — all handshake messages use persona DIDs for
    // from/to so the mediator can route them and sender validation is simple.
    // The R-DID listener is registered for post-establishment communication.
    let our_did = if generate_r_did {
        // Snapshot the mediator before the &mut config borrow below.
        let mediator = config.mediator_did().to_string();
        let r_did = Arc::new(
            super::relationship_actions::create_relationship_did(tdk, config, &mediator, admin_vta)
                .await?,
        );
        // Register listener for post-establishment use (no need to wait for connection)
        let listener_config = super::didcomm::relationship_listener_config(
            config,
            tdk,
            &r_did,
            &from_did,
            config.mediator_did(),
        )
        .await;
        if let Err(e) = service.add_listener(listener_config).await {
            tracing::warn!(did = %r_did, error = %e, "failed to add R-DID listener");
        }
        r_did
    } else {
        config.persona_did_arc()
    };

    // Add or update contact with sender's name as alias
    if let Some(existing) = config.private.contacts.find_contact(&from_did) {
        // Contact exists — update alias if sender provided a name and contact has no alias
        if existing.alias.is_none() && sender_name.is_some() {
            // Remove and re-add with the alias
            config
                .private
                .contacts
                .remove_contact(&mut config.public.logs, &from_did);
            config
                .private
                .contacts
                .add_contact(
                    tdk,
                    &from_did,
                    sender_name.clone(),
                    false,
                    &mut config.public.logs,
                )
                .await?;
        }
    } else {
        config
            .private
            .contacts
            .add_contact(
                tdk,
                &from_did,
                sender_name.clone(),
                false,
                &mut config.public.logs,
            )
            .await?;
    }

    // Build and send acceptance using persona DIDs for routing.
    // The R-DID is carried in the body — the mediator only sees persona DIDs.
    // from/to use persona DIDs so encryption keys match the persona listener.
    let msg = build_accept_message(
        config.persona_did(), // from: our persona
        &from_did,            // to: their persona
        &our_did,             // body.did: our R-DID (or persona if no R-DID)
        &task_id,
    )?;
    super::didcomm::send_message(service, config, &msg, config.persona_did(), &from_did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send acceptance: {e}"))?;

    // Create relationship entry
    config.private.relationships.relationships.insert(
        Arc::clone(&from_did),
        Arc::new(Mutex::new(Relationship {
            task_id: Arc::clone(&task_id),
            remote_did: Arc::new(their_did),
            remote_p_did: Arc::clone(&from_did),
            our_did,
            created: Utc::now(),
            state: RelationshipState::RequestAccepted,
        })),
    );

    // Remove the task
    config.private.tasks.remove(&task_id);

    config.public.logs.insert(
        LogFamily::Relationship,
        format!("Accepted relationship request from ({})", from_did),
    );
    info!(from = %from_did, "relationship request accepted");
    Ok(())
}

/// Reject an inbound relationship request.
///
/// Sends rejection message to the remote party and removes the task.
pub async fn reject_relationship_request(
    config: &mut Config,
    service: &DIDCommService,
    task_id: &str,
    reason: Option<&str>,
) -> Result<()> {
    let task_id = Arc::new(task_id.to_string());

    // Find the task and extract sender
    let from_did = {
        let task_arc = Arc::clone(
            config
                .private
                .tasks
                .get_by_id(&task_id)
                .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?,
        );
        let task = task_arc
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        match &task.type_ {
            TaskType::RelationshipRequestInbound { from, .. } => Arc::clone(from),
            _ => anyhow::bail!("task {} is not an inbound relationship request", task_id),
        }
    };

    // Build and send rejection message
    let msg = build_reject_message(config.persona_did(), &from_did, reason, &task_id)?;
    super::didcomm::send_message(service, config, &msg, config.persona_did(), &from_did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send rejection: {e}"))?;

    // Remove the task
    config.private.tasks.remove(&task_id);

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Rejected relationship request from ({}). Reason: {}",
            from_did,
            reason.unwrap_or("none")
        ),
    );
    info!(from = %from_did, "relationship request rejected");
    Ok(())
}

/// Accept a received VRC — store it in vrcs_received and remove the task.
pub fn accept_vrc(config: &mut Config, task_id: &str) -> Result<()> {
    let task_id = Arc::new(task_id.to_string());

    // Find the task and extract VRC + sender
    let (vrc, remote_p_did) = {
        let task_arc = Arc::clone(
            config
                .private
                .tasks
                .get_by_id(&task_id)
                .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?,
        );
        let task = task_arc
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        match &task.type_ {
            TaskType::VRCIssued { vrc } => {
                // Determine issuer as remote p-did
                let issuer = Arc::new(vrc.issuer().to_string());
                (Arc::new(*vrc.clone()), issuer)
            }
            _ => anyhow::bail!("task {} is not a VRC issued task", task_id),
        }
    };

    // Store in received VRCs
    config.private.vrcs_received.insert(&remote_p_did, vrc)?;

    // Remove the task
    config.private.tasks.remove(&task_id);

    config.public.logs.insert(
        LogFamily::Task,
        format!("Accepted VRC from ({})", remote_p_did),
    );
    info!(from = %remote_p_did, "VRC accepted and stored");
    Ok(())
}

/// Accept an inbound VRC request — create, sign, and send a VRC back to the requester.
///
/// Uses current timestamp as valid_from and no valid_until (simplest default).
pub async fn accept_vrc_request(
    config: &mut Config,
    tdk: &TDK,
    service: &DIDCommService,
    task_id: &str,
) -> Result<()> {
    use dtg_credentials::DTGCredential;
    use openvtc_core::vrc::DtgCredentialMessage;

    let task_id = Arc::new(task_id.to_string());

    // Find the task and extract relationship info
    let relationship = {
        let task_arc = Arc::clone(
            config
                .private
                .tasks
                .get_by_id(&task_id)
                .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?,
        );
        let task = task_arc
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        match &task.type_ {
            TaskType::VRCRequestInbound { relationship, .. } => Arc::clone(relationship),
            _ => anyhow::bail!("task {} is not an inbound VRC request", task_id),
        }
    };

    let (our_r_did, their_p_did, their_r_did) = {
        let lock = relationship
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        (
            Arc::clone(&lock.our_did),
            Arc::clone(&lock.remote_p_did),
            Arc::clone(&lock.remote_did),
        )
    };

    // Create VRC with current timestamp
    let valid_from = Utc::now();
    let mut vrc = DTGCredential::new_vrc(
        config.persona_did().to_string(),
        their_r_did.to_string(),
        valid_from,
        None, // no valid_until
    );

    // Sign the VRC with our persona signing key. Goes through dtg-credentials'
    // own signing helper to keep the proof type aligned with the version of
    // affinidi-data-integrity that dtg-credentials brings in.
    let persona_keys = config.get_persona_keys(tdk).await?;
    vrc.sign(&persona_keys.signing.secret, None).await?;

    // Send VRC back to the requester
    let msg = vrc.message(&our_r_did, &their_r_did, Some(&task_id))?;

    super::didcomm::send_message(service, config, &msg, &our_r_did, &their_r_did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send VRC: {e}"))?;

    // Store in issued VRCs
    config
        .private
        .vrcs_issued
        .insert(&their_p_did, Arc::new(vrc))?;

    // Remove the task
    config.private.tasks.remove(&task_id);

    config.public.logs.insert(
        LogFamily::Task,
        format!("Issued VRC to ({}) Task ID ({})", their_p_did, task_id),
    );

    info!(to = %their_p_did, "VRC issued and sent");
    Ok(())
}

/// Reject an inbound VRC request.
///
/// Sends a rejection message to the requester and removes the task.
pub async fn reject_vrc_request(
    config: &mut Config,
    service: &DIDCommService,
    task_id: &str,
    reason: Option<&str>,
) -> Result<()> {
    use openvtc_core::vrc::VRCRequestReject;

    let task_id = Arc::new(task_id.to_string());

    // Find the task and extract relationship info
    let relationship = {
        let task_arc = Arc::clone(
            config
                .private
                .tasks
                .get_by_id(&task_id)
                .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?,
        );
        let task = task_arc
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        match &task.type_ {
            TaskType::VRCRequestInbound { relationship, .. } => Arc::clone(relationship),
            _ => anyhow::bail!("task {} is not an inbound VRC request", task_id),
        }
    };

    let (our_r_did, their_r_did, their_p_did) = {
        let lock = relationship
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        (
            Arc::clone(&lock.our_did),
            Arc::clone(&lock.remote_did),
            Arc::clone(&lock.remote_p_did),
        )
    };

    // Build and send rejection message
    let msg = VRCRequestReject::create_message(
        &their_r_did,
        &our_r_did,
        &task_id,
        reason.map(|s| s.to_string()),
    )?;

    super::didcomm::send_message(service, config, &msg, &our_r_did, &their_r_did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send VRC rejection: {e}"))?;

    // Remove the task
    config.private.tasks.remove(&task_id);

    config.public.logs.insert(
        LogFamily::Task,
        format!(
            "Rejected VRC request from ({}). Reason: {}",
            their_p_did,
            reason.unwrap_or("none")
        ),
    );
    info!(from = %their_p_did, "VRC request rejected");
    Ok(())
}

/// Clear all tasks from the inbox.
pub fn clear_all_tasks(config: &mut Config) -> Result<()> {
    config.private.tasks.clear();
    info!("all inbox tasks cleared");
    Ok(())
}

/// Dismiss (remove) a task from the inbox without any action.
pub fn dismiss_task(config: &mut Config, task_id: &str) -> Result<()> {
    let task_id = Arc::new(task_id.to_string());
    if config.private.tasks.remove(&task_id) {
        debug!(task_id = %task_id, "task dismissed");
    } else {
        warn!(task_id = %task_id, "task not found for dismissal");
    }
    Ok(())
}

// ------------------------------------------------------------------
// Message construction helpers — kept transport-agnostic so the same
// builders can be packed by the DIDComm service later.
// ------------------------------------------------------------------

/// Build a DIDComm relationship-acceptance message.
fn build_accept_message(from: &str, to: &str, r_did: &str, thid: &str) -> Result<Message> {
    super::didcomm::build_didcomm_message(
        openvtc_core::protocol_urls::RELATIONSHIP_REQUEST_ACCEPT,
        json!(RelationshipAcceptBody {
            did: r_did.to_string()
        }),
        from,
        to,
        Some(thid),
    )
}

/// Build a DIDComm relationship-rejection message.
fn build_reject_message(from: &str, to: &str, reason: Option<&str>, thid: &str) -> Result<Message> {
    super::didcomm::build_didcomm_message(
        openvtc_core::protocol_urls::RELATIONSHIP_REQUEST_REJECT,
        json!(RelationshipRejectBody {
            reason: reason.map(|r| r.to_string())
        }),
        from,
        to,
        Some(thid),
    )
}

// ============================================================
// State-handler dispatch wrappers
//
// These were inlined into state_handler/mod.rs's main_loop. They share
// nothing with the rest of the file beyond their UI-feedback shape, so
// hosting them next to the protocol-level handlers above keeps related
// code together and shrinks mod.rs.
// ============================================================

use crate::state_handler::{
    actions::InboxAction,
    dispatch_util,
    main_page::content::{ActiveTaskView, TaskKind},
    settings_actions,
    state::State,
};
use tokio::sync::watch;

fn handle_inbox_select(state: &mut State, index: usize) {
    state.main_page.content_panel.inbox.selected_index = index;
}

fn handle_inbox_open_detail(state: &mut State, index: usize) {
    state.main_page.content_panel.inbox.selected_index = index;
    if let Some(task) = state.main_page.content_panel.inbox.tasks.get(index) {
        let view = match &task.kind {
            TaskKind::RelationshipRequestInbound {
                from_did,
                their_did,
                reason,
                name,
            } => Some(ActiveTaskView::RelationshipRequestInbound {
                task_id: task.id.clone(),
                from_did: from_did.clone(),
                their_did: their_did.clone(),
                reason: reason.clone(),
                name: name.clone(),
            }),
            TaskKind::VRCRequestInbound { reason } => Some(ActiveTaskView::VRCRequestInbound {
                task_id: task.id.clone(),
                from_did: task.remote_did.clone(),
                reason: reason.clone(),
            }),
            TaskKind::VRCIssued => Some(ActiveTaskView::VRCIssued {
                task_id: task.id.clone(),
                issuer: task.remote_did.clone(),
            }),
            TaskKind::RelationshipRequestOutbound { our_did } => {
                Some(ActiveTaskView::RelationshipRequestOutbound {
                    task_id: task.id.clone(),
                    to_did: task.remote_did.clone(),
                    our_did: our_did.clone(),
                    state: "Request Sent".to_string(),
                })
            }
            TaskKind::VRCRequestOutbound => Some(ActiveTaskView::VRCRequestOutbound {
                task_id: task.id.clone(),
                remote_did: task.remote_did.clone(),
            }),
            TaskKind::TrustPing | TaskKind::Informational(_) => Some(ActiveTaskView::Info {
                task_id: task.id.clone(),
                type_display: task.type_display.clone(),
                remote_did: task.remote_did.clone(),
            }),
        };
        state.main_page.content_panel.inbox.active_task = view;
    }
}

/// Helper: save config after an inbox action, sync UI state, and log messages.
fn save_and_sync(
    config: &Config,
    state: &mut State,
    profile: &str,
    success_status: &str,
    success_log: &str,
) {
    state.main_page.content_panel.inbox.active_task = None;
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        profile,
        dispatch_util::Persist::SaveAndSync,
        |mp| &mut mp.content_panel.inbox.status_message,
        success_status.to_string(),
        dispatch_util::SyncLog::Plain(success_log.to_string()),
    );
}

fn record_error(state: &mut State, context: &str, err: &anyhow::Error) {
    dispatch_util::record_error(
        &mut state.main_page,
        |mp| &mut mp.content_panel.inbox.status_message,
        context,
        err,
    );
}

#[allow(clippy::too_many_arguments)]
async fn handle_accept_relationship(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    state_tx: &watch::Sender<State>,
    profile: &str,
    task_id: &str,
    generate_r_did: bool,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) {
    if generate_r_did {
        state.main_page.content_panel.inbox.status_message =
            Some("Accepting with R-DID — creating keys...".to_string());
        state
            .main_page
            .log("Accepting relationship request (creating R-DID)...");
    } else {
        state.main_page.content_panel.inbox.status_message =
            Some("Accepting relationship request...".to_string());
        state.main_page.log("Accepting relationship request...");
    }
    let _ = state_tx.send(state.clone());

    match accept_relationship_request(config, tdk, service, task_id, generate_r_did, admin_vta)
        .await
    {
        Ok(()) => save_and_sync(
            config,
            state,
            profile,
            "Relationship request accepted",
            "Accepted relationship request",
        ),
        Err(e) => record_error(state, "Failed to accept relationship", &e),
    }
}

async fn handle_reject_relationship(
    config: &mut Box<Config>,
    service: &DIDCommService,
    state: &mut State,
    profile: &str,
    task_id: &str,
    reason: Option<&str>,
) {
    match reject_relationship_request(config, service, task_id, reason).await {
        Ok(()) => save_and_sync(
            config,
            state,
            profile,
            "Relationship request rejected",
            "Rejected relationship request",
        ),
        Err(e) => record_error(state, "Failed to reject relationship", &e),
    }
}

fn handle_accept_vrc(config: &mut Box<Config>, state: &mut State, profile: &str, task_id: &str) {
    match accept_vrc(config, task_id) {
        Ok(()) => save_and_sync(
            config,
            state,
            profile,
            "VRC accepted and stored",
            "VRC accepted and stored",
        ),
        Err(e) => record_error(state, "Failed to accept VRC", &e),
    }
}

async fn handle_accept_vrc_request(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    profile: &str,
    task_id: &str,
) {
    match accept_vrc_request(config, tdk, service, task_id).await {
        Ok(()) => save_and_sync(
            config,
            state,
            profile,
            "VRC issued and sent",
            "VRC issued and sent",
        ),
        Err(e) => record_error(state, "Failed to issue VRC", &e),
    }
}

async fn handle_reject_vrc_request(
    config: &mut Box<Config>,
    service: &DIDCommService,
    state: &mut State,
    profile: &str,
    task_id: &str,
    reason: Option<&str>,
) {
    match reject_vrc_request(config, service, task_id, reason).await {
        Ok(()) => save_and_sync(
            config,
            state,
            profile,
            "VRC request rejected",
            "Rejected VRC request",
        ),
        Err(e) => record_error(state, "Failed to reject VRC request", &e),
    }
}

fn handle_dismiss_task(config: &mut Box<Config>, state: &mut State, profile: &str, task_id: &str) {
    if let Err(e) = dismiss_task(config, task_id) {
        state.main_page.log_error("Failed to dismiss task", &e);
        return;
    }
    state.main_page.content_panel.inbox.active_task = None;
    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log_error("Failed to save config", &e);
    }
    state.main_page.sync_from_config(config);
    state.main_page.log("Task dismissed");
}

fn handle_clear_all(config: &mut Box<Config>, state: &mut State, profile: &str) {
    if let Err(e) = clear_all_tasks(config) {
        state.main_page.log_error("Failed to clear inbox", &e);
        return;
    }
    state.main_page.content_panel.inbox.active_task = None;
    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log_error("Failed to save config", &e);
    }
    state.main_page.sync_from_config(config);
    state.main_page.log("All inbox tasks cleared");
}

/// Dispatch a single `InboxAction` to its handler. Centralizes what was
/// previously a >30-line nested match in `state_handler::main_loop`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch(
    action: InboxAction,
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    state_tx: &watch::Sender<State>,
    profile: &str,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) {
    match action {
        InboxAction::SelectTask(index) => handle_inbox_select(state, index),
        InboxAction::OpenDetail(index) => handle_inbox_open_detail(state, index),
        InboxAction::Back => {
            state.main_page.content_panel.inbox.active_task = None;
        }
        InboxAction::AcceptRelationship {
            task_id,
            generate_r_did,
        } => {
            handle_accept_relationship(
                config,
                tdk,
                service,
                state,
                state_tx,
                profile,
                &task_id,
                generate_r_did,
                admin_vta,
            )
            .await
        }
        InboxAction::RejectRelationship { task_id, reason } => {
            handle_reject_relationship(config, service, state, profile, &task_id, reason.as_deref())
                .await
        }
        InboxAction::AcceptVrc { task_id } => handle_accept_vrc(config, state, profile, &task_id),
        InboxAction::AcceptVrcRequest { task_id } => {
            handle_accept_vrc_request(config, tdk, service, state, profile, &task_id).await
        }
        InboxAction::RejectVrcRequest { task_id, reason } => {
            handle_reject_vrc_request(config, service, state, profile, &task_id, reason.as_deref())
                .await
        }
        InboxAction::DismissTask { task_id } => {
            handle_dismiss_task(config, state, profile, &task_id)
        }
        InboxAction::ClearAll => handle_clear_all(config, state, profile),
    }
}
