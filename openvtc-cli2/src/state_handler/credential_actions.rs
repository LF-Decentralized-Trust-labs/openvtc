//! Credential (VRC) action handlers for the TUI.
//!
//! Ported from `openvtc-cli/src/interactions/vrc/request.rs`.

use std::sync::Arc;

use affinidi_tdk::TDK;
use anyhow::{Context, Result};
use openvtc::{config::Config, logs::LogFamily, tasks::TaskType, vrc::VrcRequest};
use tracing::info;

/// Send a VRC request to a remote party via an established relationship.
pub async fn send_vrc_request(
    config: &mut Config,
    tdk: &TDK,
    remote_p_did: &str,
    reason: Option<&str>,
) -> Result<()> {
    let atm = tdk.atm.as_ref().context("ATM not initialized")?;
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
        (lock.our_did.clone(), lock.remote_did.clone())
    };

    let profile = if our_did == config.public.persona_did {
        &config.persona_did.profile
    } else {
        config
            .atm_profiles
            .get(&our_did)
            .ok_or_else(|| anyhow::anyhow!("No messaging profile for DID: {}", our_did))?
    };

    let request_body = VrcRequest {
        reason: reason.map(|s| s.to_string()),
    };

    let message = request_body.create_message(&remote_did, &our_did)?;
    let msg_id = Arc::new(message.id.clone());

    openvtc::pack_and_send(
        atm,
        profile,
        &message,
        &our_did,
        &remote_did,
        &config.public.mediator_did,
    )
    .await?;

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
