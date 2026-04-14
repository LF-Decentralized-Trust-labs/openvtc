use affinidi_tdk::TDK;
use openvtc::{LF_PUBLIC_MEDIATOR_DID, config::did::create_initial_webvh_did};
use pgp::composed::ArmorOptions;
use secrecy::SecretString;

use crate::{
    state_handler::{
        setup_sequence::{Completion, MessageType, SetupPage, did_keys::export_persona_did_keys},
        state::State,
    },
    ui::pages::setup_flow::did_keys_export_inputs::DIDKeysExportInputs,
};
use tokio::sync::mpsc::UnboundedSender;

/// Handle the `ExportDIDKeys` action.
pub(crate) async fn handle_export_did_keys(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    export_inputs: DIDKeysExportInputs,
) {
    state.setup.active_page = SetupPage::DidKeysExportShow;
    state
        .setup
        .did_keys_export
        .messages
        .push("Starting key export...".to_string());

    // Send the initial state so that the UX shows the key export page
    let _ = state_tx.send(state.clone());

    let state_tx_clone = state_tx.clone();
    let mut state_clone = state.clone();
    let export = tokio::spawn(async move {
        match export_persona_did_keys(
            &mut state_clone,
            &state_tx_clone,
            export_inputs.username.value(),
            SecretString::new(export_inputs.passphrase.value().to_string().into()),
        ) {
            Ok(export) => {
                state_clone.setup.did_keys_export.exported =
                    match export.to_armored_string(ArmorOptions::default()) {
                        Ok(armored) => Some(armored),
                        Err(e) => {
                            state_clone
                                .setup
                                .did_keys_export
                                .messages
                                .push(format!("Error armoring exported keys: {}", e));
                            None
                        }
                    };
            }
            Err(e) => {
                state_clone
                    .setup
                    .did_keys_export
                    .messages
                    .push(format!("Error exporting DID keys: {}", e));
            }
        }
        state_clone.setup.did_keys_export
    })
    .await;
    match export {
        Ok(did_keys_export) => state.setup.did_keys_export = did_keys_export,
        Err(e) => {
            state
                .setup
                .did_keys_export
                .messages
                .push(format!("Key export task failed: {e}"));
        }
    }
    if state.setup.did_keys_export.exported.is_some() {
        state
            .setup
            .did_keys_export
            .messages
            .push("Key export completed".to_string());
    }
}

/// Handle the `WebvhServerCreateDid` action.
/// Returns `true` if the caller should `continue`.
pub(crate) async fn handle_webvh_server_create_did(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    tdk: &TDK,
    server_id: String,
    custom_path: Option<String>,
) -> anyhow::Result<bool> {
    use vta_sdk::client::VtaClient;

    state.setup.vta.use_webvh_server = true;
    state.setup.active_page = SetupPage::WebvhServerProgress;
    state.setup.webvh_server.messages.clear();
    state.setup.webvh_server.completed = Completion::NotFinished;
    state.setup.webvh_server.messages.push(MessageType::Info(
        "Creating DID via WebVH server...".to_string(),
    ));
    state_tx.send(state.clone())?;

    let access_token = match state.setup.vta.access_token.clone() {
        Some(t) => t,
        None => {
            state.setup.webvh_server.messages.push(MessageType::Error(
                "VTA access token not available.".to_string(),
            ));
            state.setup.webvh_server.completed = Completion::CompletedFail;
            return Ok(true);
        }
    };
    let vta_url = state.setup.vta.vta_url.clone();
    let client = VtaClient::new(&vta_url);
    client.set_token(access_token);

    let context_id = state.setup.vta.context_id.clone().unwrap_or_default();

    state
        .setup
        .webvh_server
        .messages
        .push(MessageType::Info(format!("Server: {}", server_id)));
    state_tx.send(state.clone())?;

    apply_server_create_result(state, &client, tdk, &context_id, &server_id, custom_path).await;
    Ok(false)
}

/// Handle the `SetCustomMediator` action when `use_webvh_server` is true.
/// Returns `true` if the caller should `continue`.
pub(crate) async fn handle_custom_mediator_webvh(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    tdk: &TDK,
) -> anyhow::Result<bool> {
    use vta_sdk::client::VtaClient;

    state.setup.active_page = SetupPage::WebvhServerProgress;
    state.setup.webvh_server.messages.clear();
    state.setup.webvh_server.completed = Completion::NotFinished;
    state.setup.webvh_server.messages.push(MessageType::Info(
        "Creating DID via WebVH server...".to_string(),
    ));
    state_tx.send(state.clone())?;

    let access_token = match state.setup.vta.access_token.clone() {
        Some(t) => t,
        None => {
            state.setup.webvh_server.messages.push(MessageType::Error(
                "VTA access token not available.".to_string(),
            ));
            state.setup.webvh_server.completed = Completion::CompletedFail;
            return Ok(true);
        }
    };
    let vta_url = state.setup.vta.vta_url.clone();
    let client = VtaClient::new(&vta_url);
    client.set_token(access_token);

    let context_id = state.setup.vta.context_id.clone().unwrap_or_default();
    let server_id = state.setup.webvh_server.selected_server_id.clone();
    let custom_path = state.setup.webvh_server.custom_path.clone();

    state
        .setup
        .webvh_server
        .messages
        .push(MessageType::Info(format!("Server: {}", server_id)));
    state_tx.send(state.clone())?;

    apply_server_create_result(state, &client, tdk, &context_id, &server_id, custom_path).await;
    Ok(false)
}

/// Shared helper: call `vta::create_did_via_server` and apply the result to state.
async fn apply_server_create_result(
    state: &mut State,
    client: &vta_sdk::client::VtaClient,
    tdk: &TDK,
    context_id: &str,
    server_id: &str,
    custom_path: Option<String>,
) {
    use crate::state_handler::setup_sequence::vta;

    match vta::create_did_via_server(client, tdk, context_id, server_id, custom_path).await {
        Ok((persona_keys, did, document, mnemonic)) => {
            state
                .setup
                .webvh_server
                .messages
                .push(MessageType::Info(format!("DID created: {}", did)));
            state.setup.webvh_server.did = did.clone();
            state.setup.webvh_server.document = document.clone();
            state.setup.webvh_server.mnemonic = mnemonic;
            state.setup.webvh_server.completed = Completion::CompletedOK;

            // Populate did_keys and webvh_address for Config::create compatibility
            state.setup.did_keys = Some(persona_keys);
            state.setup.webvh_address.did = did;
            state.setup.webvh_address.document = document;
            state.setup.webvh_address.completed = Completion::CompletedOK;
        }
        Err(e) => {
            state
                .setup
                .webvh_server
                .messages
                .push(MessageType::Error(format!("Failed: {e}")));
            state.setup.webvh_server.completed = Completion::CompletedFail;
        }
    }
}

/// Handle the `CreateWebVHDID` action.
/// Returns `true` if the caller should `continue`.
pub(crate) async fn handle_create_webvh_did(
    state: &mut State,
    webvh_address: String,
) -> anyhow::Result<bool> {
    let mut keys = match state.setup.did_keys.clone() {
        Some(k) => k,
        None => {
            state.setup.webvh_address.completed = Completion::CompletedFail;
            state.setup.webvh_address.messages.push(MessageType::Error(
                "DID persona keys not available.".to_string(),
            ));
            return Ok(true);
        }
    };
    let update_secret = match state.setup.vta.update_secret.clone() {
        Some(s) => s,
        None => {
            state.setup.webvh_address.completed = Completion::CompletedFail;
            state
                .setup
                .webvh_address
                .messages
                .push(MessageType::Error("VTA update secret not set.".to_string()));
            return Ok(true);
        }
    };
    let next_update_secret = match state.setup.vta.next_update_secret.clone() {
        Some(s) => s,
        None => {
            state.setup.webvh_address.completed = Completion::CompletedFail;
            state.setup.webvh_address.messages.push(MessageType::Error(
                "VTA next update secret not set.".to_string(),
            ));
            return Ok(true);
        }
    };
    match create_initial_webvh_did(
        &webvh_address,
        &mut keys,
        state
            .setup
            .custom_mediator
            .as_ref()
            .unwrap_or(&LF_PUBLIC_MEDIATOR_DID.to_string()),
        update_secret,
        next_update_secret,
    )
    .await
    {
        Ok((did, document)) => {
            state.setup.webvh_address.did = did;
            state.setup.webvh_address.document = document;
            state.setup.did_keys = Some(keys);
            state.setup.webvh_address.completed = Completion::CompletedOK;
            state.setup.webvh_address.messages.push(MessageType::Info(
                "WebVH DID created successfully.".to_string(),
            ));
        }
        Err(e) => {
            state.setup.webvh_address.completed = Completion::CompletedFail;
            state
                .setup
                .webvh_address
                .messages
                .push(MessageType::Error(format!("Error creating WebVH DID: {e}")));
        }
    }
    Ok(false)
}

/// Handle the `ResolveWebVHDID` action.
pub(crate) async fn handle_resolve_webvh_did(state: &mut State, tdk: &TDK, did: String) {
    match tdk.did_resolver().resolve(&did).await {
        Ok(response) => {
            // Change the key ID's to match the DID VM ID's
            if let Some(keys) = &mut state.setup.did_keys {
                keys.signing.secret.id = [&did, "#key-1"].concat();
                keys.authentication.secret.id = [&did, "#key-2"].concat();
                keys.decryption.secret.id = [&did, "#key-3"].concat();
            }

            state.setup.webvh_address.did = did;
            state.setup.webvh_address.document = response.doc;
            state.setup.webvh_address.completed = Completion::CompletedOK;
            state.setup.webvh_address.messages.push(MessageType::Info(
                "Your DID resolved successfully.".to_string(),
            ));
        }
        Err(e) => {
            state.setup.webvh_address.completed = Completion::CompletedFail;
            state
                .setup
                .webvh_address
                .messages
                .push(MessageType::Error(format!("Error resolving DID: {e}")));
        }
    }
}
