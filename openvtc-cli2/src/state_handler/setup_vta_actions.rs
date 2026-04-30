use crate::state_handler::{
    setup_sequence::{Completion, MessageType, SetupPage},
    state::State,
};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use vta_sdk::provision_client::{
    DiagStatus, EphemeralSetupKey, ProvisionAsk, VtaEvent, VtaIntent, VtaReply, apply_update,
    pending_list, run_connection_test,
};

/// Handle the `VtaSubmitDid` action: resolve the VTA service URL from the
/// supplied DID and mint an ephemeral did:key the operator will authorise via
/// PNM in the next step. On success we transition to `VtaAclInstructions`; on
/// failure we stay on `VtaEnterDid` so the operator can edit and resubmit.
pub(crate) async fn handle_vta_submit_did(
    state: &mut State,
    state_tx: &watch::Sender<State>,
    vta_did: String,
) -> anyhow::Result<()> {
    // The transition from StartAsk → VtaEnterDid is a UI-only navigation
    // (handle_nav_result doesn't round-trip through the backend), so the
    // backend's active_page is still StartAsk at this point. Pin it to
    // VtaEnterDid before pushing the first state update so the UI doesn't
    // momentarily re-render StartAsk while we resolve the URL.
    state.setup.active_page = SetupPage::VtaEnterDid;
    state.setup.vta.messages.clear();
    state.setup.vta.completed = Completion::NotFinished;
    state.setup.vta.vta_did = vta_did.clone();
    state.setup.vta.messages.push(MessageType::Info(
        "Resolving VTA service endpoint…".to_string(),
    ));
    let _ = state_tx.send(state.clone());

    let vta_url = match vta_sdk::session::resolve_vta_url(&vta_did).await {
        Ok(url) => url,
        Err(e) => {
            state.setup.vta.messages.push(MessageType::Error(format!(
                "Could not resolve VTA URL from {vta_did}: {e}"
            )));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(());
        }
    };
    state.setup.vta.vta_url = vta_url.clone();
    state
        .setup
        .vta
        .messages
        .push(MessageType::Info(format!("VTA URL: {vta_url}")));

    // Mint the ephemeral admin did:key. Held in memory only — a fresh key is
    // generated if the wizard restarts, and the operator must re-run the PNM
    // ACL step for the new DID.
    let setup_key = match EphemeralSetupKey::generate() {
        Ok(k) => Arc::new(k),
        Err(e) => {
            state.setup.vta.messages.push(MessageType::Error(format!(
                "Could not generate setup did:key: {e}"
            )));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(());
        }
    };
    state.setup.vta.messages.push(MessageType::Info(format!(
        "Setup DID minted: {}",
        setup_key.did
    )));
    state.setup.vta.setup_key = Some(setup_key);
    state.setup.vta.completed = Completion::CompletedOK;
    state.setup.active_page = SetupPage::VtaAclInstructions;
    let _ = state_tx.send(state.clone());

    Ok(())
}

/// Handle the `VtaStartProvision` action: spawn `run_connection_test` against
/// the VTA, drain its `VtaEvent` stream into the diagnostics list, and on
/// success store the issued admin VC + access token before transitioning to
/// the existing `VtaAuthenticate` screen so the keys-fetch / webvh-server
/// pick flow takes over unchanged.
pub(crate) async fn handle_vta_start_provision(
    state: &mut State,
    state_tx: &watch::Sender<State>,
    context_id: String,
) -> anyhow::Result<()> {
    use crate::state_handler::setup_sequence::vta;
    use vta_sdk::client::VtaClient;

    let setup_key = match state.setup.vta.setup_key.clone() {
        Some(k) => k,
        None => {
            state.setup.vta.messages.push(MessageType::Error(
                "Setup DID not generated yet — restart the setup wizard.".to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(());
        }
    };
    let vta_did = state.setup.vta.vta_did.clone();
    // Persist the operator's chosen context id so downstream config writes use
    // the same value.
    state.setup.vta.context_id = Some(context_id.clone());

    state.setup.active_page = SetupPage::VtaProvisioning;
    state.setup.vta.messages.clear();
    state.setup.vta.completed = Completion::NotFinished;
    state.setup.vta.diagnostics = pending_list();
    let _ = state_tx.send(state.clone());

    let (tx, mut rx) = mpsc::unbounded_channel::<VtaEvent>();
    // AdminRotated mints a fresh long-term admin DID on the VTA side; the
    // ephemeral setup did:key is only used to authenticate the bootstrap
    // call. The reply still arrives as `VtaReply::AdminOnly`, so the rest
    // of this handler is unchanged.
    let ask = ProvisionAsk::vta_admin_rotated(context_id.clone()).with_label("openvtc");
    let setup_did = setup_key.did.clone();
    let setup_priv = setup_key.private_key_multibase().to_string();
    let runner_vta_did = vta_did.clone();
    tokio::spawn(async move {
        run_connection_test(
            VtaIntent::AdminRotated,
            runner_vta_did,
            setup_did,
            setup_priv,
            ask,
            None,
            tx,
        )
        .await;
    });

    let mut admin_reply: Option<vta_sdk::provision_client::AdminCredentialReply> = None;
    let mut connect_rest_url: Option<String> = None;
    let mut connect_mediator_did: Option<String> = None;

    while let Some(ev) = rx.recv().await {
        match ev {
            VtaEvent::CheckStart(check) => {
                apply_update(&mut state.setup.vta.diagnostics, check, DiagStatus::Running);
            }
            VtaEvent::CheckDone(check, status) => {
                apply_update(&mut state.setup.vta.diagnostics, check, status);
            }
            VtaEvent::Resolved(resolved) => {
                if let Some(rest) = resolved.rest_url.clone() {
                    state.setup.vta.vta_url = rest;
                }
            }
            VtaEvent::AttemptCompleted { .. } => {
                // Per-transport telemetry; the diagnostics list already shows
                // the operator-relevant outcome on the matching DiagCheck row.
            }
            VtaEvent::PreflightDone { .. } => {
                // AdminOnly intent never reaches preflight — FullSetup-only.
            }
            VtaEvent::Connected {
                rest_url,
                mediator_did,
                reply,
                ..
            } => {
                connect_rest_url = rest_url;
                connect_mediator_did = mediator_did;
                if let VtaReply::AdminOnly(adm) = reply {
                    admin_reply = Some(adm);
                }
            }
            VtaEvent::Failed(reason) => {
                state
                    .setup
                    .vta
                    .messages
                    .push(MessageType::Error(reason.clone()));
                state.setup.vta.completed = Completion::CompletedFail;
                let _ = state_tx.send(state.clone());
            }
        }
        let _ = state_tx.send(state.clone());
    }

    let Some(admin) = admin_reply else {
        if matches!(state.setup.vta.completed, Completion::NotFinished) {
            state.setup.vta.messages.push(MessageType::Error(
                "Provisioning ended without an admin credential.".to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedFail;
            let _ = state_tx.send(state.clone());
        }
        return Ok(());
    };

    // Adopt the admin credential as the authenticated identity for the rest
    // of setup. Mirrors what the legacy paste-bundle flow used to do.
    state.setup.vta.credential_did = admin.admin_did.clone();
    if let Some(rest) = connect_rest_url {
        state.setup.vta.vta_url = rest;
    }
    if let Some(mediator) = connect_mediator_did
        && state.setup.custom_mediator.is_none()
    {
        state.setup.custom_mediator = Some(mediator);
    }
    state
        .setup
        .vta
        .messages
        .push(MessageType::Info("Authenticating with VTA…".to_string()));
    let _ = state_tx.send(state.clone());

    let vta_url = state.setup.vta.vta_url.clone();
    match vta::authenticate(
        &vta_url,
        &admin.admin_did,
        &admin.admin_private_key_mb,
        &vta_did,
    )
    .await
    {
        Ok(token_result) => {
            state.setup.vta.access_token = Some(token_result.access_token.clone());
            state.setup.vta.authenticated = true;
            state.setup.vta.admin_credential = Some(admin);
            state.setup.vta.messages.push(MessageType::Info(
                "VTA authentication successful.".to_string(),
            ));

            // Discover available WebVH servers (context is already known, so
            // skip the ACL-based context discovery path).
            let client = VtaClient::new(&vta_url);
            client.set_token(token_result.access_token);
            match vta::list_webvh_servers(&client).await {
                Ok(servers) => {
                    if !servers.is_empty() {
                        state.setup.vta.messages.push(MessageType::Info(format!(
                            "Found {} WebVH server(s) available for DID hosting.",
                            servers.len()
                        )));
                    }
                    state.setup.vta.webvh_servers = servers;
                }
                Err(e) => {
                    state.setup.vta.messages.push(MessageType::Info(format!(
                        "Could not list WebVH servers: {e}"
                    )));
                    state.setup.vta.webvh_servers = vec![];
                }
            }

            state.setup.vta.completed = Completion::CompletedOK;
            // Stay on VtaProvisioning so the operator can see the admin DID
            // rotation result (ephemeral setup DID → long-term admin DID)
            // before advancing on Enter.
            let _ = state_tx.send(state.clone());
        }
        Err(e) => {
            state
                .setup
                .vta
                .messages
                .push(MessageType::Error(format!("Authentication failed: {e}")));
            state.setup.vta.completed = Completion::CompletedFail;
            let _ = state_tx.send(state.clone());
        }
    }

    Ok(())
}

/// Handle the `VtaCreateKeys` action: create persona keys and WebVH update keys via VTA.
/// Returns `true` if the caller should `continue`.
pub(crate) async fn handle_vta_create_keys(
    state: &mut State,
    state_tx: &watch::Sender<State>,
) -> anyhow::Result<bool> {
    use crate::state_handler::setup_sequence::vta;
    use vta_sdk::client::VtaClient;

    state.setup.vta.messages.clear();
    state.setup.vta.completed = Completion::NotFinished;
    state.setup.active_page = SetupPage::VtaKeysFetch;
    state.setup.vta.messages.push(MessageType::Info(
        "Creating persona keys via VTA...".to_string(),
    ));
    let _ = state_tx.send(state.clone());

    let access_token = match state.setup.vta.access_token.clone() {
        Some(t) => t,
        None => {
            state.setup.vta.messages.push(MessageType::Error(
                "VTA access token not available. Please authenticate first.".to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(true);
        }
    };
    let vta_url = state.setup.vta.vta_url.clone();
    let client = VtaClient::new(&vta_url);
    client.set_token(access_token);

    // Create persona keys (signing, authentication, encryption)
    let context_id = state.setup.vta.context_id.as_deref();
    match vta::create_persona_keys(&client, context_id).await {
        Ok(persona_keys) => {
            state.setup.vta.messages.push(MessageType::Info(
                "Persona keys created successfully.".to_string(),
            ));
            let _ = state_tx.send(state.clone());

            // Create WebVH update keys
            state.setup.vta.messages.push(MessageType::Info(
                "Creating WebVH update keys...".to_string(),
            ));
            let _ = state_tx.send(state.clone());

            match vta::create_update_keys(&client, context_id).await {
                Ok((update_secret, next_update_secret)) => {
                    state.setup.vta.update_secret = Some(update_secret);
                    state.setup.vta.next_update_secret = Some(next_update_secret);
                    state.setup.vta.messages.push(MessageType::Info(
                        "WebVH update keys created successfully.".to_string(),
                    ));
                    state.setup.vta.completed = Completion::CompletedOK;
                    state.setup.did_keys = Some(persona_keys);
                }
                Err(e) => {
                    state.setup.vta.messages.push(MessageType::Error(format!(
                        "Failed to create update keys: {e}"
                    )));
                    state.setup.vta.completed = Completion::CompletedFail;
                }
            }
        }
        Err(e) => {
            state.setup.vta.messages.push(MessageType::Error(format!(
                "Failed to create persona keys: {e}"
            )));
            state.setup.vta.completed = Completion::CompletedFail;
        }
    }
    Ok(false)
}
