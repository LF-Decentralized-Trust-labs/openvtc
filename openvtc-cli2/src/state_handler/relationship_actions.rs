//! Relationship action handlers for the TUI.
//!
//! Ported from `openvtc-cli/src/relationships/messages.rs` and `mod.rs`.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::{
    TDK,
    affinidi_crypto::ed25519::ed25519_private_to_x25519,
    didcomm::Message,
    dids::{DID, PeerKeyRole},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use anyhow::{Result, bail};
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
use secrecy::SecretString;
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
    service: &DIDCommService,
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

    // Optionally generate a random relationship DID for privacy
    let our_did: Arc<String> = if generate_r_did {
        let r_did = Arc::new(
            create_relationship_did(tdk, config, &config.public.mediator_did.clone()).await?,
        );
        // Register a listener for the new R-DID
        let listener_config = super::didcomm::relationship_listener_config(
            config,
            tdk,
            &r_did,
            respondent_did,
            &config.public.mediator_did,
        )
        .await;
        if let Err(e) = service.add_listener(listener_config).await {
            tracing::warn!(did = %r_did, error = %e, "failed to add R-DID listener");
        }
        r_did
    } else {
        Arc::clone(&config.public.persona_did)
    };

    // Build the relationship request message
    let friendly_name = if config.public.friendly_name.is_empty() {
        None
    } else {
        Some(config.public.friendly_name.as_str())
    };
    let msg = create_request_message(
        &config.public.persona_did,
        respondent_did,
        reason,
        &our_did,
        friendly_name,
    )?;
    let msg_id = Arc::new(msg.id.clone());

    super::didcomm::send_message(
        service,
        config,
        &msg,
        &config.public.persona_did,
        respondent_did,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to send relationship request: {e}"))?;

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
pub async fn ping_relationship(
    config: &mut Config,
    _tdk: &TDK,
    service: &DIDCommService,
    remote_p_did: &str,
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

    // Build ping message using the relationship DIDs (R-DIDs if available)
    let ping_msg = {
        use std::time::SystemTime;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        affinidi_tdk::didcomm::Message::build(
            Uuid::new_v4().to_string(),
            "https://didcomm.org/trust-ping/2.0/ping".to_string(),
            serde_json::json!({"response_requested": true}),
        )
        .from(our_did.to_string())
        .to(remote_did.to_string())
        .created_time(now)
        .expires_time(now + 60 * 5)
        .finalize()
    };
    let msg_id = ping_msg.id.clone();

    // Send via the correct listener (R-DID listener if our_did != persona_did)
    super::didcomm::send_message(service, config, &ping_msg, &our_did, &remote_did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send trust-ping: {e}"))?;

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

/// Remove a relationship, clean up associated VRCs, and remove the R-DID listener.
pub async fn remove_relationship(
    config: &mut Config,
    service: &affinidi_messaging_didcomm_service::DIDCommService,
    remote_p_did: &str,
) -> Result<()> {
    let key = Arc::new(remote_p_did.to_string());

    // Clean up R-DID listener before removing the relationship data
    if let Some(rel) = config.private.relationships.get(&key) {
        if let Ok(lock) = rel.lock() {
            if *lock.our_did != *config.public.persona_did {
                let listener_id =
                    super::didcomm::listener_id_for_did(&lock.our_did, &config.public.persona_did);
                if let Err(e) = service.remove_listener(&listener_id).await {
                    tracing::warn!(
                        listener = %listener_id,
                        error = %e,
                        "failed to remove R-DID listener"
                    );
                }
            }
        }
    }

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
/// Dispatches to the appropriate backend-specific implementation based on
/// the configured key backend (BIP32 or VTA).
pub(crate) async fn create_relationship_did(
    tdk: &TDK,
    config: &mut Config,
    mediator: &str,
) -> Result<String> {
    match &config.key_backend {
        KeyBackend::Bip32 { .. } => create_relationship_did_bip32(tdk, config, mediator).await,
        KeyBackend::Vta {
            vta_url,
            credential_did,
            credential_private_key,
            vta_did,
            ..
        } => {
            let vta_url = vta_url.clone();
            let credential_did = credential_did.clone();
            let credential_private_key = credential_private_key.clone();
            let vta_did = vta_did.clone();
            create_relationship_did_vta(
                tdk,
                config,
                mediator,
                &vta_url,
                &credential_did,
                &credential_private_key,
                &vta_did,
            )
            .await
        }
    }
}

/// BIP32 backend: derives signing and encryption keys from the BIP32 root
/// using the relationship path pointer, registers the secrets with the TDK
/// resolver, and records key metadata in the configuration.
async fn create_relationship_did_bip32(
    tdk: &TDK,
    config: &mut Config,
    mediator: &str,
) -> Result<String> {
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
        _ => bail!("create_relationship_did_bip32 requires a BIP32 key backend"),
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

/// VTA backend: creates signing and encryption keys via the VTA service,
/// builds a did:peer from the resulting secrets, and registers everything
/// in the TDK resolver and config.
async fn create_relationship_did_vta(
    tdk: &TDK,
    config: &mut Config,
    mediator: &str,
    vta_url: &str,
    credential_did: &str,
    credential_private_key: &SecretString,
    vta_did: &str,
) -> Result<String> {
    use secrecy::ExposeSecret;
    use vta_sdk::client::{CreateKeyRequest, VtaClient};
    use vta_sdk::keys::KeyType;

    // Authenticate with VTA
    info!("authenticating with VTA for R-DID creation...");
    let token = super::setup_sequence::vta::authenticate(
        vta_url,
        credential_did,
        credential_private_key.expose_secret(),
        vta_did,
    )
    .await?;

    let client = VtaClient::new(vta_url);
    client.set_token(token.access_token);

    // Create signing key (Ed25519) for verification
    info!("creating Ed25519 signing key via VTA...");
    let sign_resp = client
        .create_key(CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("relationship-signing".to_string()),
            context_id: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create signing key: {e}"))?;

    let sign_secret_resp = client
        .get_key_secret(&sign_resp.key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get signing key secret: {e}"))?;

    let mut v_secret = vta_sdk::did_key::secret_from_key_response(&sign_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    v_secret.id = v_secret.get_public_keymultibase()?;

    // Create encryption key (X25519)
    info!("creating X25519 encryption key via VTA...");
    let enc_resp = client
        .create_key(CreateKeyRequest {
            key_type: KeyType::X25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("relationship-encryption".to_string()),
            context_id: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create encryption key: {e}"))?;

    let enc_secret_resp = client
        .get_key_secret(&enc_resp.key_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get encryption key secret: {e}"))?;

    let mut e_secret = vta_sdk::did_key::secret_from_key_response(&enc_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    e_secret.id = e_secret.get_public_keymultibase()?;

    // Build did:peer from secrets
    let mut keys = vec![
        (PeerKeyRole::Verification, &mut v_secret),
        (PeerKeyRole::Encryption, &mut e_secret),
    ];
    let r_did = DID::generate_did_peer_from_secrets(&mut keys, Some(mediator.to_string()))
        .map_err(|e| anyhow::anyhow!("Failed to create relationship DID: {e}"))?;

    // Register key info in config
    config.key_info.insert(
        v_secret.id.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::VtaManaged {
                key_id: sign_resp.key_id,
            },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipVerification,
        },
    );
    config.key_info.insert(
        e_secret.id.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::VtaManaged {
                key_id: enc_resp.key_id,
            },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipEncryption,
        },
    );

    // Register secrets in TDK resolver
    tdk.get_shared_state()
        .secrets_resolver
        .insert(v_secret)
        .await;
    tdk.get_shared_state()
        .secrets_resolver
        .insert(e_secret)
        .await;

    Ok(r_did)
}

/// Build a DIDComm relationship request message.
fn create_request_message(
    from: &str,
    to: &str,
    reason: Option<&str>,
    our_did: &str,
    friendly_name: Option<&str>,
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
            name: friendly_name.map(|n| n.to_string()),
        }),
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now)
    .expires_time(now + 60 * 60 * 48) // 48 hours
    .finalize();

    Ok(message)
}
