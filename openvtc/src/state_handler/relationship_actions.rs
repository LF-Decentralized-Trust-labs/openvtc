//! Relationship action handlers for the TUI.

use std::sync::{Arc, Mutex};

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
use openvtc_core::{
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
#[allow(clippy::too_many_arguments)]
pub async fn send_relationship_request(
    config: &mut Config,
    tdk: &TDK,
    service: &DIDCommService,
    respondent_did: &str,
    alias: &str,
    reason: Option<&str>,
    generate_r_did: bool,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
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
        // Snapshot the mediator before the &mut config borrow below.
        let mediator = config.mediator_did().to_string();
        let r_did = Arc::new(create_relationship_did(tdk, config, &mediator, admin_vta).await?);
        // Register a listener for the new R-DID
        let listener_config = super::didcomm::relationship_listener_config(
            config,
            tdk,
            &r_did,
            respondent_did,
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

    // Build the relationship request message
    let friendly_name = if config.public.friendly_name.is_empty() {
        None
    } else {
        Some(config.public.friendly_name.as_str())
    };
    let msg = create_request_message(
        config.persona_did(),
        respondent_did,
        reason,
        &our_did,
        friendly_name,
    )?;
    let msg_id = Arc::new(msg.id.clone());

    super::didcomm::send_message(service, config, &msg, config.persona_did(), respondent_did)
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
    info!(
        our_did = %our_did,
        remote_did = %remote_did,
        is_r_did = !config.is_persona_did(our_did.as_str()),
        "ping using relationship DIDs"
    );
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
    // Extract listener ID before any async work to avoid holding MutexGuard across await
    let listener_to_remove = if let Some(rel_arc) = config.private.relationships.get(&key)
        && let Ok(lock) = rel_arc.lock()
        && !config.is_persona_did(lock.our_did.as_str())
    {
        Some(super::didcomm::listener_id_for_did(&lock.our_did, config))
    } else {
        None
    };
    if let Some(lid) = listener_to_remove
        && let Err(e) = service.remove_listener(&lid).await
    {
        tracing::warn!(listener = %lid, error = %e, "failed to remove R-DID listener");
    }

    config.private.relationships.remove(
        &key,
        &mut config.private.vrcs_issued,
        &mut config.private.vrcs_received,
    );

    // Also remove the associated contact (and its alias mapping). Without this,
    // the alias remains registered and re-creating the relationship with the
    // same alias fails with a duplicate-alias error.
    config
        .private
        .contacts
        .remove_contact(&mut config.public.logs, remote_p_did);

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
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> Result<String> {
    match &config.key_backend {
        KeyBackend::Bip32 { .. } => create_relationship_did_bip32(tdk, config, mediator).await,
        KeyBackend::Vta { .. } => {
            create_relationship_did_vta(tdk, config, mediator, admin_vta).await
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
        .secrets_resolver()
        .insert(v_secret)
        .await;
    tdk.get_shared_state()
        .secrets_resolver()
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
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> Result<String> {
    // Create the relationship signing (Ed25519) + encryption (X25519) keys via
    // the VTA. Reuse the always-on admin session when the runtime provides one;
    // otherwise open a transient session (guaranteed to shut down on every exit).
    let (mut v_secret, mut e_secret, sign_key_id, enc_key_id) = match admin_vta {
        Some(client) => create_relationship_keys(client).await?,
        None => {
            openvtc_core::config::with_runtime_vta_client::<_, _, _, anyhow::Error>(
                &config.key_backend,
                |client| async move { create_relationship_keys(&client).await },
            )
            .await?
        }
    };

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
                key_id: sign_key_id,
            },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipVerification,
        },
    );
    config.key_info.insert(
        e_secret.id.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::VtaManaged { key_id: enc_key_id },
            create_time: Utc::now(),
            purpose: KeyTypes::RelationshipEncryption,
        },
    );

    // Register secrets in TDK resolver
    tdk.get_shared_state()
        .secrets_resolver()
        .insert(v_secret)
        .await;
    tdk.get_shared_state()
        .secrets_resolver()
        .insert(e_secret)
        .await;

    Ok(r_did)
}

/// Create a relationship's signing (Ed25519) + encryption (X25519) keys via the
/// VTA and fetch their secrets, on the given (admin) session. Returns
/// `(v_secret, e_secret, signing_key_id, encryption_key_id)`.
async fn create_relationship_keys(
    client: &vta_sdk::client::VtaClient,
) -> Result<(Secret, Secret, String, String)> {
    use vta_sdk::client::CreateKeyRequest;
    use vta_sdk::keys::KeyType;

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

    Ok((v_secret, e_secret, sign_resp.key_id, enc_resp.key_id))
}

/// Build a DIDComm relationship request message.
fn create_request_message(
    from: &str,
    to: &str,
    reason: Option<&str>,
    our_did: &str,
    friendly_name: Option<&str>,
) -> Result<Message> {
    super::didcomm::build_didcomm_message(
        openvtc_core::protocol_urls::RELATIONSHIP_REQUEST,
        json!(RelationshipRequestBody {
            reason: reason.map(|r| r.to_string()),
            did: our_did.to_string(),
            name: friendly_name.map(|n| n.to_string()),
        }),
        from,
        to,
        None,
    )
}

// ============================================================
// State-handler dispatch wrappers
// ============================================================

use crate::state_handler::{
    actions::RelationshipAction, credential_actions, dispatch_util, log_did,
    main_page::content::RelationshipsMode, resolve_did_to_display, settings_actions, state::State,
};
use openvtc_core::config::protected_config::Contact;
use std::time::Instant;
use tokio::sync::watch;

fn handle_open_detail(state: &mut State, index: usize) {
    state.main_page.content_panel.relationships.selected_index = index;
    state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
        index,
        selected_vrc: None,
    };
}

fn handle_start_new_request(state: &mut State) {
    state.main_page.content_panel.relationships.mode = RelationshipsMode::NewRequest {
        did_input: String::new(),
        alias_input: String::new(),
        reason_input: String::new(),
        generate_r_did: false,
        active_field: 0,
    };
}

fn handle_cancel_or_back(state: &mut State) {
    state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
    state.main_page.content_panel.relationships.status_message = None;
}

fn handle_input_update(state: &mut State, field: usize, value: String) {
    if let RelationshipsMode::NewRequest {
        ref mut did_input,
        ref mut alias_input,
        ref mut reason_input,
        ..
    } = state.main_page.content_panel.relationships.mode
    {
        match field {
            0 => *did_input = value,
            1 => *alias_input = value,
            _ => *reason_input = value,
        }
    }
}

fn handle_toggle_r_did(state: &mut State) {
    if let RelationshipsMode::NewRequest {
        ref mut generate_r_did,
        ..
    } = state.main_page.content_panel.relationships.mode
    {
        *generate_r_did = !*generate_r_did;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_submit(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    state_tx: &watch::Sender<State>,
    profile: &str,
    did: &str,
    alias: &str,
    reason: Option<&str>,
    generate_r_did: bool,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) {
    if generate_r_did {
        state.main_page.content_panel.relationships.status_message =
            Some("Creating relationship DID...".to_string());
        state
            .main_page
            .log("Creating relationship DID via key backend...");
    } else {
        state.main_page.content_panel.relationships.status_message =
            Some("Sending request...".to_string());
    }
    let _ = state_tx.send(state.clone());

    match send_relationship_request(
        config,
        tdk,
        service,
        did,
        alias,
        reason,
        generate_r_did,
        admin_vta,
    )
    .await
    {
        Ok(()) => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
            let detail = {
                let rel_key = std::sync::Arc::new(did.to_string());
                if let Some(rel_arc) = config.private.relationships.get(&rel_key)
                    && let Ok(r) = rel_arc.lock()
                {
                    format!(
                        "Relationship Request Sent\n\
                         ─────────────────────────\n\
                         To (persona):  {}\n\
                         Our DID:       {}\n\
                         R-DID used:    {}\n\
                         Task ID:       {}",
                        r.remote_p_did,
                        r.our_did,
                        if !config.is_persona_did(r.our_did.as_str()) {
                            "yes"
                        } else {
                            "no"
                        },
                        r.task_id,
                    )
                } else {
                    String::new()
                }
            };
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                profile,
                dispatch_util::Persist::SaveAndSync,
                |mp| &mut mp.content_panel.relationships.status_message,
                format!("Request sent to {}", log_did(did)),
                dispatch_util::SyncLog::Detailed {
                    summary: format!("Relationship request sent to {}", log_did(did)),
                    detail,
                },
            );
        }
        Err(e) => {
            dispatch_util::record_error(
                &mut state.main_page,
                |mp| &mut mp.content_panel.relationships.status_message,
                "Failed to send relationship request",
                &e,
            );
        }
    }
}

async fn handle_ping(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
) {
    let rel_key = std::sync::Arc::new(remote_p_did.to_string());
    let (our_did_str, remote_did_str) = if let Some(rel_arc) =
        config.private.relationships.get(&rel_key)
        && let Ok(r) = rel_arc.lock()
    {
        (r.our_did.to_string(), r.remote_did.to_string())
    } else {
        (String::new(), String::new())
    };
    let display_name = resolve_did_to_display(config, remote_p_did);

    match ping_relationship(config, tdk, service, remote_p_did).await {
        Ok(()) => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
            let using_rdid = !config.is_persona_did(&our_did_str);
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                profile,
                dispatch_util::Persist::SaveAndSync,
                |mp| &mut mp.content_panel.relationships.status_message,
                "Ping sent",
                dispatch_util::SyncLog::Detailed {
                    summary: format!(
                        "Trust-ping sent to {display_name}{}",
                        if using_rdid { " (via R-DID)" } else { "" }
                    ),
                    detail: format!(
                        "Trust-Ping Sent\n\
                         ───────────────\n\
                         To:              {display_name}\n\
                         Sent to DID:     {remote_did_str}\n\
                         Sent from DID:   {our_did_str}\n\
                         Remote persona:  {remote_p_did}\n\
                         Using R-DIDs:    {}\n\
                         Routed via:      mediator",
                        if using_rdid { "yes" } else { "no" },
                    ),
                },
            );
        }
        Err(e) => {
            state.main_page.content_panel.relationships.status_message =
                Some(format!("Ping failed: {e:#}"));
            state.main_page.log_detailed(
                format!("Ping to {display_name} failed: {e}"),
                format!(
                    "Trust-Ping Failed\n\
                     ─────────────────\n\
                     To (persona):    {remote_p_did}\n\
                     To (R-DID):      {remote_did_str}\n\
                     From (our DID):  {our_did_str}\n\
                     Error:           {e:#}\n\n\
                     Debug:\n{e:?}",
                ),
            );
        }
    }
}

async fn handle_remove(
    config: &mut Box<Config>,
    service: &DIDCommService,
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
) {
    if let Err(e) = remove_relationship(config, service, remote_p_did).await {
        state
            .main_page
            .log_error("Failed to remove relationship", &e);
        return;
    }
    state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        profile,
        dispatch_util::Persist::SaveAndSync,
        |mp| &mut mp.content_panel.relationships.status_message,
        "Relationship removed",
        dispatch_util::SyncLog::Plain("Relationship removed".to_string()),
    );
}

fn handle_edit_alias(
    config: &mut Box<Config>,
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
    alias: &str,
) {
    config
        .private
        .contacts
        .remove_contact(&mut config.public.logs, remote_p_did);

    let alias_opt = if alias.trim().is_empty() {
        None
    } else {
        Some(alias.trim().to_string())
    };
    let contact_did = std::sync::Arc::new(remote_p_did.to_string());
    let contact = std::sync::Arc::new(Contact {
        did: contact_did.clone(),
        alias: alias_opt.clone(),
    });
    config
        .private
        .contacts
        .contacts
        .insert(contact_did, contact.clone());
    if let Some(ref a) = alias_opt {
        config.private.contacts.aliases.insert(a.clone(), contact);
    }

    config.public.logs.insert(
        openvtc_core::logs::LogFamily::Config,
        format!(
            "Alias updated for {}: {}",
            remote_p_did,
            alias_opt.as_deref().unwrap_or("(removed)")
        ),
    );

    if let Err(e) = settings_actions::save_config(config, profile) {
        state.main_page.log_error("Failed to save config", &e);
    }
    state.main_page.sync_from_config(config);
    let index = state
        .main_page
        .content_panel
        .relationships
        .relationships
        .iter()
        .position(|r| r.remote_p_did == remote_p_did)
        .unwrap_or(0);
    state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
        index,
        selected_vrc: None,
    };
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        profile,
        dispatch_util::Persist::None,
        |mp| &mut mp.content_panel.relationships.status_message,
        "Alias updated",
        dispatch_util::SyncLog::Plain("Alias updated".to_string()),
    );
}

async fn handle_request_vrc(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    profile: &str,
    remote_p_did: &str,
) {
    let display_name = resolve_did_to_display(config, remote_p_did);
    match credential_actions::send_vrc_request(config, tdk, service, remote_p_did, None).await {
        Ok(()) => {
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                profile,
                dispatch_util::Persist::SaveAndSync,
                |mp| &mut mp.content_panel.relationships.status_message,
                format!("VRC requested from {display_name}"),
                dispatch_util::SyncLog::Detailed {
                    summary: format!("VRC requested from {display_name}"),
                    detail: format!(
                        "VRC Request Sent\n\
                         ────────────────\n\
                         To:      {display_name}\n\
                         DID:     {remote_p_did}",
                    ),
                },
            );
        }
        Err(e) => {
            state.main_page.content_panel.relationships.status_message =
                Some(format!("VRC request failed: {e:#}"));
            state
                .main_page
                .log_error(format!("VRC request to {display_name} failed"), &e);
        }
    }
}

/// Dispatch a single `RelationshipAction`. `ping_sent_at` is updated when
/// a Ping action runs so the main loop can correlate the inbound pong.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch(
    action: RelationshipAction,
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &DIDCommService,
    state: &mut State,
    state_tx: &watch::Sender<State>,
    profile: &str,
    ping_sent_at: &mut Option<Instant>,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) {
    match action {
        RelationshipAction::Select(index) => {
            state.main_page.content_panel.relationships.selected_index = index;
        }
        RelationshipAction::OpenDetail(index) => handle_open_detail(state, index),
        RelationshipAction::StartNewRequest => handle_start_new_request(state),
        RelationshipAction::CancelNewRequest | RelationshipAction::Back => {
            handle_cancel_or_back(state)
        }
        RelationshipAction::InputUpdate { field, value } => {
            handle_input_update(state, field, value)
        }
        RelationshipAction::ToggleRDid => handle_toggle_r_did(state),
        RelationshipAction::FocusField(field) => {
            if let RelationshipsMode::NewRequest {
                ref mut active_field,
                ..
            } = state.main_page.content_panel.relationships.mode
            {
                *active_field = field;
            }
        }
        RelationshipAction::SubmitRequest {
            did,
            alias,
            reason,
            generate_r_did,
        } => {
            handle_submit(
                config,
                tdk,
                service,
                state,
                state_tx,
                profile,
                &did,
                &alias,
                reason.as_deref(),
                generate_r_did,
                admin_vta,
            )
            .await
        }
        RelationshipAction::Ping { remote_p_did } => {
            handle_ping(config, tdk, service, state, profile, &remote_p_did).await;
            *ping_sent_at = Some(Instant::now());
        }
        RelationshipAction::Remove { remote_p_did } => {
            handle_remove(config, service, state, profile, &remote_p_did).await
        }
        RelationshipAction::StartEditAlias {
            index,
            current_alias,
        } => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::EditAlias {
                index,
                alias_input: current_alias,
            };
        }
        RelationshipAction::EditAliasUpdate(value) => {
            if let RelationshipsMode::EditAlias {
                ref mut alias_input,
                ..
            } = state.main_page.content_panel.relationships.mode
            {
                *alias_input = value;
            }
        }
        RelationshipAction::EditAlias {
            remote_p_did,
            alias,
        } => handle_edit_alias(config, state, profile, &remote_p_did, &alias),
        RelationshipAction::CancelEditAlias { index } => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
                index,
                selected_vrc: None,
            };
        }
        RelationshipAction::RequestVrc { remote_p_did } => {
            handle_request_vrc(config, tdk, service, state, profile, &remote_p_did).await
        }
    }
}
