//! Relationship action handlers for the TUI.
//!
//! Ported from `openvtc-cli/src/relationships/messages.rs` and `mod.rs`.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use affinidi_tdk::{TDK, didcomm::Message};
use anyhow::{Context, Result};
use chrono::Utc;
use openvtc::{
    config::Config,
    logs::LogFamily,
    relationships::{Relationship, RelationshipRequestBody, RelationshipState},
    tasks::TaskType,
};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

/// Create and send a new relationship request to a remote party.
///
/// Simplified version for the TUI: always uses persona DID (no R-DID generation yet).
pub async fn send_relationship_request(
    config: &mut Config,
    tdk: &TDK,
    respondent_did: &str,
    alias: &str,
    reason: Option<&str>,
) -> Result<()> {
    // Validate DID format
    if !respondent_did.starts_with("did:") {
        anyhow::bail!("Invalid DID: must start with 'did:'");
    }

    // Check for existing established relationship
    let respondent_arc = Arc::new(respondent_did.to_string());
    if let Some(rel) = config.private.relationships.get(&respondent_arc) {
        let lock = rel
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        if lock.state == RelationshipState::Established {
            anyhow::bail!("An established relationship already exists with this DID");
        }
    }

    // Add or find contact
    let alias_opt = if alias.trim().is_empty() {
        None
    } else {
        Some(alias.trim().to_string())
    };

    if config
        .private
        .contacts
        .find_contact(respondent_did)
        .is_none()
    {
        config
            .private
            .contacts
            .add_contact(
                tdk,
                respondent_did,
                alias_opt,
                true,
                &mut config.public.logs,
            )
            .await?;
    }

    let atm = tdk.atm.as_ref().context("ATM not initialized")?;

    // Use persona DID as our relationship DID
    let our_did = config.public.persona_did.clone();

    // Build the relationship request message
    let msg = create_request_message(&config.public.persona_did, respondent_did, reason, &our_did)?;
    let msg_id = Arc::new(msg.id.clone());

    openvtc::pack_and_send(
        atm,
        &config.persona_did.profile,
        &msg,
        &config.public.persona_did,
        respondent_did,
        &config.public.mediator_did,
    )
    .await?;

    // Create relationship entry
    config.private.relationships.relationships.insert(
        respondent_arc.clone(),
        Arc::new(Mutex::new(Relationship {
            task_id: msg_id.clone(),
            our_did,
            remote_p_did: respondent_arc.clone(),
            remote_did: respondent_arc.clone(),
            created: Utc::now(),
            state: RelationshipState::RequestSent,
        })),
    );

    // Create tracking task
    config.private.tasks.new_task(
        &msg_id,
        TaskType::RelationshipRequestOutbound {
            to: respondent_arc.clone(),
        },
    );

    config.public.logs.insert(
        LogFamily::Relationship,
        format!(
            "Relationship requested: remote DID({}) Task ID({})",
            respondent_did, msg_id
        ),
    );

    info!(to = %respondent_did, "relationship request sent");
    Ok(())
}

/// Send a trust-ping to a relationship.
pub async fn ping_relationship(config: &mut Config, tdk: &TDK, remote_p_did: &str) -> Result<()> {
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

    let ping_msg =
        atm.trust_ping()
            .generate_ping_message(Some(our_did.as_str()), &remote_did, true)?;
    let msg_id = ping_msg.id.clone();

    openvtc::pack_and_send(
        atm,
        profile,
        &ping_msg,
        &our_did,
        &remote_did,
        &config.public.mediator_did,
    )
    .await?;

    config.public.logs.insert(
        LogFamily::Relationship,
        format!("Sent ping to {} via {}", remote_did, our_did),
    );

    config.private.tasks.new_task(
        &Arc::new(msg_id),
        TaskType::TrustPing {
            from: our_did,
            to: remote_did,
            relationship,
        },
    );

    info!(to = %remote_p_did, "trust-ping sent");
    Ok(())
}

/// Remove a relationship and clean up associated VRCs.
pub fn remove_relationship(config: &mut Config, remote_p_did: &str) -> Result<()> {
    let key = Arc::new(remote_p_did.to_string());

    config.private.relationships.remove(
        &key,
        &mut config.private.vrcs_issued,
        &mut config.private.vrcs_received,
    );

    config.public.logs.insert(
        LogFamily::Relationship,
        format!("Removed relationship with ({})", remote_p_did),
    );

    info!(remote = %remote_p_did, "relationship removed");
    Ok(())
}

/// Build a DIDComm relationship request message.
fn create_request_message(
    from: &str,
    to: &str,
    reason: Option<&str>,
    our_did: &str,
) -> Result<Message> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let message = Message::build(
        Uuid::new_v4().to_string(),
        openvtc::protocol_urls::RELATIONSHIP_REQUEST.to_string(),
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
