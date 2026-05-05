//! Credential (VRC) action handlers for the TUI.

use std::sync::Arc;

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::TDK;
use anyhow::Result;
use openvtc_core::{config::Config, logs::LogFamily, tasks::TaskType, vrc::VrcRequest};
use tracing::{debug, info};

/// Send a VRC request to a remote party via an established relationship.
pub async fn send_vrc_request(
    config: &mut Config,
    _tdk: &TDK,
    service: &DIDCommService,
    remote_p_did: &str,
    reason: Option<&str>,
) -> Result<()> {
    let remote_key = Arc::new(remote_p_did.to_string());

    let relationship = config
        .private
        .relationships
        .get(&remote_key)
        .ok_or_else(|| anyhow::anyhow!("No relationship found for {}", remote_p_did))?;

    let (our_did, remote_did) = {
        let lock = relationship
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        (Arc::clone(&lock.our_did), Arc::clone(&lock.remote_did))
    };

    let request_body = VrcRequest {
        reason: reason.map(|s| s.to_string()),
    };

    let message = request_body.create_message(&remote_did, &our_did)?;
    let msg_id = Arc::new(message.id.clone());

    super::didcomm::send_message(service, config, &message, &our_did, &remote_did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send VRC request: {e}"))?;

    // Create tracking task
    config
        .private
        .tasks
        .new_task(&msg_id, TaskType::VRCRequestOutbound { relationship });

    config.public.logs.insert(
        LogFamily::Relationship,
        format!("Requested VRC from ({}) Task ID ({})", remote_p_did, msg_id),
    );

    info!(to = %remote_p_did, "VRC request sent");
    Ok(())
}

/// Remove a VRC by its ID from both received and issued collections.
pub fn remove_vrc(config: &mut Config, vrc_id: &str) -> Result<()> {
    let vrc_id = Arc::new(vrc_id.to_string());
    config.private.vrcs_received.remove_vrc(&vrc_id);
    config.private.vrcs_issued.remove_vrc(&vrc_id);

    config
        .public
        .logs
        .insert(LogFamily::Task, format!("Removed VRC ({})", vrc_id));

    debug!(vrc_id = %vrc_id, "VRC removed");
    Ok(())
}
