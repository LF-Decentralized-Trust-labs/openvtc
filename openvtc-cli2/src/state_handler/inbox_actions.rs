//! Inbox task action handlers.
//!
//! These functions process user decisions on inbox tasks (accept/reject
//! relationship requests, accept VRCs, dismiss tasks). They operate on
//! `&mut Config` and `&TDK` owned by the StateHandler.

use std::sync::{Arc, Mutex};

use affinidi_tdk::TDK;
use anyhow::{Context, Result};
use chrono::Utc;
use openvtc::{
    config::Config,
    logs::LogFamily,
    relationships::{
        Relationship, RelationshipState, create_send_message_accepted, create_send_message_rejected,
    },
    tasks::TaskType,
};
use tracing::{debug, info, warn};

/// Accept an inbound relationship request.
///
/// Uses the persona DID as the relationship DID (simple default).
/// Creates the relationship, sends acceptance message, and removes the task.
pub async fn accept_relationship_request(
    config: &mut Config,
    tdk: &TDK,
    task_id: &str,
) -> Result<()> {
    let task_id = Arc::new(task_id.to_string());

    // Find the task and extract request data
    let (from_did, their_did) = {
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
                (Arc::clone(from), request.did.clone())
            }
            _ => anyhow::bail!("task {} is not an inbound relationship request", task_id),
        }
    };

    // Use persona DID as our relationship DID (simple default)
    let our_did = Arc::clone(&config.public.persona_did);

    // Add contact if not already known
    if config.private.contacts.find_contact(&from_did).is_none() {
        config
            .private
            .contacts
            .add_contact(tdk, &from_did, None, false, &mut config.public.logs)
            .await?;
    }

    // Send acceptance message
    let atm = tdk.atm.as_ref().context("ATM not initialized")?;
    create_send_message_accepted(
        atm,
        &config.persona_did.profile,
        &from_did,
        &config.public.mediator_did,
        &our_did,
        &task_id,
    )
    .await?;

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
    tdk: &TDK,
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

    // Send rejection message
    let atm = tdk.atm.as_ref().context("ATM not initialized")?;
    create_send_message_rejected(
        atm,
        &config.persona_did.profile,
        &from_did,
        &config.public.mediator_did,
        reason,
        &task_id,
    )
    .await?;

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
pub async fn accept_vrc_request(config: &mut Config, tdk: &TDK, task_id: &str) -> Result<()> {
    use affinidi_data_integrity::DataIntegrityProof;
    use dtg_credentials::DTGCredential;
    use openvtc::vrc::DtgCredentialMessage;

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
        config.public.persona_did.to_string(),
        their_r_did.to_string(),
        valid_from,
        None, // no valid_until
    );

    // Sign the VRC with our persona signing key
    let persona_keys = config.get_persona_keys(tdk).await?;
    let proof =
        DataIntegrityProof::sign_jcs_data(&vrc, None, &persona_keys.signing.secret, None).await?;
    vrc.credential_mut().proof = Some(proof);

    // Send VRC back to the requester
    let msg = vrc.message(&our_r_did, &their_r_did, Some(&task_id))?;
    let atm = tdk.atm.as_ref().context("ATM not initialized")?;

    let profile = if our_r_did == config.public.persona_did {
        &config.persona_did.profile
    } else {
        config
            .atm_profiles
            .get(&our_r_did)
            .ok_or_else(|| anyhow::anyhow!("No messaging profile for DID: {}", our_r_did))?
    };

    openvtc::pack_and_send(
        atm,
        profile,
        &msg,
        &our_r_did,
        &their_r_did,
        &config.public.mediator_did,
    )
    .await?;

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
    tdk: &TDK,
    task_id: &str,
    reason: Option<&str>,
) -> Result<()> {
    use openvtc::vrc::VRCRequestReject;

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

    // Send rejection message
    let msg = VRCRequestReject::create_message(
        &their_r_did,
        &our_r_did,
        &task_id,
        reason.map(|s| s.to_string()),
    )?;

    let atm = tdk.atm.as_ref().context("ATM not initialized")?;
    let profile = if our_r_did == config.public.persona_did {
        &config.persona_did.profile
    } else {
        config
            .atm_profiles
            .get(&our_r_did)
            .ok_or_else(|| anyhow::anyhow!("No messaging profile for DID: {}", our_r_did))?
    };

    openvtc::pack_and_send(
        atm,
        profile,
        &msg,
        &our_r_did,
        &their_r_did,
        &config.public.mediator_did,
    )
    .await?;

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
