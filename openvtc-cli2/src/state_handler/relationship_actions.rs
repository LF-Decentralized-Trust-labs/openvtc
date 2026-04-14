//! Relationship action handlers for the TUI.
//!
//! Ported from `openvtc-cli/src/relationships/messages.rs` and `mod.rs`.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use affinidi_tdk::{
    TDK,
    affinidi_crypto::ed25519::ed25519_private_to_x25519,
    didcomm::Message,
    dids::{DID, PeerKeyRole},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use ed25519_dalek_bip32::DerivationPath;
use openvtc::{
    config::{
        Config, KeyBackend, KeyTypes,
        secured_config::{KeyInfoConfig, KeySourceMaterial},
    },
    logs::LogFamily,
    relationships::{Relationship, RelationshipRequestBody, RelationshipState},
    tasks::TaskType,
};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

/// Create and send a new relationship request to a remote party.
///
/// When `generate_r_did` is true and the key backend is BIP32, a unique
/// relationship DID (did:peer) is derived for privacy. Otherwise the
/// persona DID is used directly.
pub async fn send_relationship_request(
    config: &mut Config,
    tdk: &TDK,
    respondent_did: &str,
    alias: &str,
    reason: Option<&str>,
    generate_r_did: bool,
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

    // Optionally generate a random relationship DID for privacy
    let our_did: Arc<String> = if generate_r_did
        && matches!(config.key_backend, KeyBackend::Bip32 { .. })
    {
        Arc::new(create_relationship_did(tdk, config, &config.public.mediator_did.clone()).await?)
    } else {
        Arc::clone(&config.public.persona_did)
    };

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
        Arc::clone(&respondent_arc),
        Arc::new(Mutex::new(Relationship {
            task_id: Arc::clone(&msg_id),
            our_did,
            remote_p_did: Arc::clone(&respondent_arc),
            remote_did: Arc::clone(&respondent_arc),
            created: Utc::now(),
            state: RelationshipState::RequestSent,
        })),
    );

    // Create tracking task
    config.private.tasks.new_task(
        &msg_id,
        TaskType::RelationshipRequestOutbound {
            to: Arc::clone(&respondent_arc),
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
        (Arc::clone(&lock.our_did), Arc::clone(&lock.remote_did))
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

/// Creates a random did:peer DID representing a relationship DID.
///
/// Derives signing and encryption keys from the BIP32 root using the
/// relationship path pointer, registers the secrets with the TDK resolver,
/// and records key metadata in the configuration.
async fn create_relationship_did(tdk: &TDK, config: &mut Config, mediator: &str) -> Result<String> {
    // Derive a key path for the verification (signing) key
    let v_path = [
        "m/3'/1'/1'/",
        config
            .private
            .relationships
            .path_pointer
            .to_string()
            .as_str(),
        "'",
    ]
    .concat();
    config.private.relationships.path_pointer += 1;

    // Derive a key path for the encryption key
    let e_path = [
        "m/3'/1'/1'/",
        config
            .private
            .relationships
            .path_pointer
            .to_string()
            .as_str(),
        "'",
    ]
    .concat();
    config.private.relationships.path_pointer += 1;

    let bip32_root = match &config.key_backend {
        KeyBackend::Bip32 { root, .. } => root,
        _ => bail!("create_relationship_did requires a BIP32 key backend"),
    };

    let v_key = bip32_root.derive(&v_path.parse::<DerivationPath>()?)?;
    let e_key = bip32_root.derive(&e_path.parse::<DerivationPath>()?)?;

    let mut v_secret = Secret::generate_ed25519(None, Some(v_key.signing_key.as_bytes()));
    let mut e_secret = Secret::generate_x25519(
        None,
        Some(&ed25519_private_to_x25519(e_key.signing_key.as_bytes())),
    )?;

    let mut keys = vec![
        (PeerKeyRole::Verification, &mut v_secret),
        (PeerKeyRole::Encryption, &mut e_secret),
    ];
    let r_did = DID::generate_did_peer_from_secrets(&mut keys, Some(mediator.to_string()))
        .map_err(|e| anyhow::anyhow!("Failed to create relationship DID: {e}"))?;

    // Add the secrets to the config
    config.key_info.insert(
        v_secret.id.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::Derived { path: v_path },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipVerification,
        },
    );
    config.key_info.insert(
        e_secret.id.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::Derived { path: e_path },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipEncryption,
        },
    );

    // Add the secrets to the TDK secret resolver
    tdk.get_shared_state()
        .secrets_resolver
        .insert(v_secret)
        .await;
    tdk.get_shared_state()
        .secrets_resolver
        .insert(e_secret)
        .await;

    // NOTE: v_key and e_key contain BIP32-derived signing key bytes on the stack.
    // ed25519-dalek-bip32 does not implement Zeroize, so these bytes may persist
    // in memory after this function returns. This is a known limitation.
    // The Secret structs (v_secret, e_secret) are now owned by the TDK resolver.
    drop(v_key);
    drop(e_key);

    Ok(r_did)
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
