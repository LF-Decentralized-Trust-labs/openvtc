use crate::state_handler::{
    setup_sequence::{Completion, MessageType, SetupPage},
    state::State,
};
use tokio::sync::mpsc::UnboundedSender;

/// Handle the `VtaSubmitCredential` action: decode credential bundle, authenticate, discover context & servers.
pub(crate) async fn handle_vta_submit_credential(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    credential_input: String,
) -> anyhow::Result<()> {
    use crate::state_handler::setup_sequence::vta;

    match vta::decode_credential(&credential_input) {
        Ok(bundle) => {
            // Immediately show progress so the user knows something is happening
            state.setup.vta.credential_bundle_raw = Some(credential_input);
            state.setup.vta.credential_did = bundle.did.clone();
            state.setup.vta.vta_did = bundle.vta_did.clone();
            state.setup.vta.messages.clear();
            state.setup.vta.completed = Completion::NotFinished;
            state.setup.active_page = SetupPage::VtaAuthenticate;
            state.setup.vta.messages.push(MessageType::Info(
                "Resolving VTA service endpoint...".to_string(),
            ));
            state_tx.send(state.clone())?;

            // Resolve VTA URL from DID document's #vta service endpoint,
            // falling back to bundle URL if resolution fails
            let vta_url = match vta_sdk::session::resolve_vta_url(&bundle.vta_did).await {
                Ok(url) => url,
                Err(_) => bundle.vta_url.clone().unwrap_or_default(),
            };
            state.setup.vta.vta_url = vta_url.clone();

            // Pre-populate mediator DID from #didcomm service endpoint
            state.setup.vta.messages.push(MessageType::Info(
                "Resolving mediator endpoint...".to_string(),
            ));
            state_tx.send(state.clone())?;
            if let Ok(Some(mediator_did)) =
                vta_sdk::session::resolve_mediator_did(&bundle.vta_did).await
            {
                state.setup.custom_mediator = Some(mediator_did);
            }

            state
                .setup
                .vta
                .messages
                .push(MessageType::Info(format!("VTA URL: {}", vta_url)));
            state
                .setup
                .vta
                .messages
                .push(MessageType::Info("Authenticating with VTA...".to_string()));
            state_tx.send(state.clone())?;

            // Auto-trigger authentication inline
            match vta::authenticate(
                &vta_url,
                &bundle.did,
                &bundle.private_key_multibase,
                &bundle.vta_did,
            )
            .await
            {
                Ok(token_result) => {
                    state.setup.vta.access_token = Some(token_result.access_token);
                    state.setup.vta.authenticated = true;
                    state.setup.vta.messages.push(MessageType::Info(
                        "VTA authentication successful.".to_string(),
                    ));
                    state.setup.vta.completed = Completion::CompletedOK;

                    // Discover admin's allowed contexts from ACL
                    discover_context_and_servers(state, &vta_url).await;
                }
                Err(e) => {
                    state
                        .setup
                        .vta
                        .messages
                        .push(MessageType::Error(format!("Authentication failed: {e}")));
                    state.setup.vta.completed = Completion::CompletedFail;
                }
            }
        }
        Err(e) => {
            state.setup.vta.messages = vec![MessageType::Error(format!(
                "Invalid credential bundle: {e}"
            ))];
            state.setup.vta.completed = Completion::CompletedFail;
        }
    }
    Ok(())
}

/// Handle the `VtaAuthenticate` action: retry authentication with VTA.
/// Returns `true` if the caller should `continue` (skip the rest of the loop iteration).
pub(crate) async fn handle_vta_authenticate(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
) -> anyhow::Result<bool> {
    use crate::state_handler::setup_sequence::vta;

    state.setup.vta.messages.clear();
    state.setup.vta.completed = Completion::NotFinished;
    state.setup.active_page = SetupPage::VtaAuthenticate;
    state
        .setup
        .vta
        .messages
        .push(MessageType::Info("Authenticating with VTA...".to_string()));
    state_tx.send(state.clone())?;

    let credential_raw = match state.setup.vta.credential_bundle_raw.clone() {
        Some(raw) => raw,
        None => {
            state.setup.vta.messages.push(MessageType::Error(
                "No credential bundle available for re-authentication.".to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(true);
        }
    };
    let bundle = match vta::decode_credential(&credential_raw) {
        Ok(b) => b,
        Err(e) => {
            state.setup.vta.messages.push(MessageType::Error(format!(
                "Failed to decode credential: {e}"
            )));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(true);
        }
    };

    // Resolve VTA URL from DID document, falling back to stored URL
    let vta_url = match vta_sdk::session::resolve_vta_url(&bundle.vta_did).await {
        Ok(url) => url,
        Err(_) => state.setup.vta.vta_url.clone(),
    };

    match vta::authenticate(
        &vta_url,
        &bundle.did,
        &bundle.private_key_multibase,
        &bundle.vta_did,
    )
    .await
    {
        Ok(token_result) => {
            state.setup.vta.access_token = Some(token_result.access_token);
            state.setup.vta.authenticated = true;
            state.setup.vta.messages.push(MessageType::Info(
                "VTA authentication successful.".to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedOK;

            // Discover admin's allowed contexts from ACL
            discover_context_and_servers(state, &vta_url).await;
        }
        Err(e) => {
            state
                .setup
                .vta
                .messages
                .push(MessageType::Error(format!("Authentication failed: {e}")));
            state.setup.vta.completed = Completion::CompletedFail;
        }
    }
    Ok(false)
}

/// Handle the `VtaCreateKeys` action: create persona keys and WebVH update keys via VTA.
/// Returns `true` if the caller should `continue`.
pub(crate) async fn handle_vta_create_keys(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
) -> anyhow::Result<bool> {
    use crate::state_handler::setup_sequence::vta;
    use vta_sdk::client::VtaClient;

    state.setup.vta.messages.clear();
    state.setup.vta.completed = Completion::NotFinished;
    state.setup.active_page = SetupPage::VtaKeysFetch;
    state.setup.vta.messages.push(MessageType::Info(
        "Creating persona keys via VTA...".to_string(),
    ));
    state_tx.send(state.clone())?;

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
            state_tx.send(state.clone())?;

            // Create WebVH update keys
            state.setup.vta.messages.push(MessageType::Info(
                "Creating WebVH update keys...".to_string(),
            ));
            state_tx.send(state.clone())?;

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

/// Shared helper: discover allowed contexts from ACL and check for WebVH servers.
async fn discover_context_and_servers(state: &mut State, vta_url: &str) {
    use vta_sdk::client::VtaClient;

    if let Some(token) = state.setup.vta.access_token.clone() {
        let acl_client = VtaClient::new(vta_url);
        acl_client.set_token(token);
        match acl_client.get_acl(&state.setup.vta.credential_did).await {
            Ok(acl) => {
                if acl.allowed_contexts.len() == 1 {
                    state.setup.vta.context_id = Some(acl.allowed_contexts[0].clone());
                    state.setup.vta.messages.push(MessageType::Info(format!(
                        "Context: {}",
                        acl.allowed_contexts[0]
                    )));
                }
            }
            Err(e) => {
                state.setup.vta.messages.push(MessageType::Info(format!(
                    "Could not discover context: {e}"
                )));
            }
        }

        // Check for available WebVH servers
        use crate::state_handler::setup_sequence::vta;
        match vta::list_webvh_servers(&acl_client).await {
            Ok(servers) => {
                if !servers.is_empty() {
                    state.setup.vta.messages.push(MessageType::Info(format!(
                        "Found {} WebVH server(s) available for DID hosting.",
                        servers.len()
                    )));
                }
                state.setup.vta.webvh_servers = servers;
            }
            Err(_) => {
                state.setup.vta.webvh_servers = vec![];
            }
        }
    }
}
