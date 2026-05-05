//! Backend handler for the auto-`did-git-sign` install step.
//!
//! Pulls everything `did_git_sign::init::install` needs out of the
//! current setup state — persona signing key, admin VC, VTA URL/DID —
//! and runs the install synchronously. Failures don't abort the wizard;
//! they're surfaced on the page so the operator can hit Enter and
//! continue without git signing.

use openvtc_core::config::secured_config::KeySourceMaterial;
use tokio::sync::watch;

use crate::state_handler::{
    setup_sequence::{Completion, MessageType, SetupPage},
    state::State,
};

pub(crate) async fn handle_did_git_sign_install(
    state: &mut State,
    state_tx: &watch::Sender<State>,
) -> anyhow::Result<()> {
    // Render the install page immediately so the operator sees progress
    // even if the local file ops complete in milliseconds.
    state.setup.active_page = SetupPage::DidGitSignSetup;
    state.setup.did_git_sign.completed = Completion::NotFinished;
    state.setup.did_git_sign.messages.clear();
    state.setup.did_git_sign.config_path = None;
    state.setup.did_git_sign.ssh_public_key = None;
    state.setup.did_git_sign.overridden_global_signing_key = None;
    state
        .setup
        .did_git_sign
        .messages
        .push(MessageType::Info("Configuring did-git-sign…".to_string()));
    let _ = state_tx.send(state.clone());

    match try_install(state) {
        Ok(()) => {
            state
                .setup
                .did_git_sign
                .messages
                .push(MessageType::Info("Done.".to_string()));
            state.setup.did_git_sign.completed = Completion::CompletedOK;
        }
        Err(e) => {
            state
                .setup
                .did_git_sign
                .messages
                .push(MessageType::Error(format!("{e}")));
            state.setup.did_git_sign.completed = Completion::CompletedFail;
        }
    }
    let _ = state_tx.send(state.clone());

    Ok(())
}

/// Pull the necessary fields out of `state` and run the install. Returns
/// an error if state is incomplete or the underlying did-git-sign install
/// fails.
fn try_install(state: &mut State) -> anyhow::Result<()> {
    let did_keys = state
        .setup
        .did_keys
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("persona keys are not yet provisioned"))?;
    let admin = state
        .setup
        .vta
        .admin_credential
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("VTA admin credential is missing"))?;

    // The persona signing key. Both setup paths set `secret.id` to a full
    // DID URL (#key-0 for the WebVH-server flow, #key-1 for the manual
    // flow), so we can use it directly as did_key_id.
    let did_key_id = did_keys.signing.secret.id.clone();
    if did_key_id.is_empty() {
        return Err(anyhow::anyhow!("persona signing key has no DID URL set"));
    }

    // Persona signing keys are always VtaManaged in the online flow —
    // refuse to proceed if we somehow ended up with another source.
    let vta_key_id = match &did_keys.signing.source {
        KeySourceMaterial::VtaManaged { key_id } => key_id.clone(),
        other => {
            return Err(anyhow::anyhow!(
                "persona signing key is not VTA-managed (source={other:?}); \
                 did-git-sign auto-setup only supports VTA-managed keys",
            ));
        }
    };

    // Ed25519 verifying key — 32 raw bytes from the Secret.
    let pub_bytes = did_keys.signing.secret.get_public_bytes();
    if pub_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "persona signing key public bytes are {} bytes, expected 32 (Ed25519)",
            pub_bytes.len()
        ));
    }
    let mut verifying_key = [0u8; 32];
    verifying_key.copy_from_slice(pub_bytes);

    let vta_url = state.setup.vta.vta_url.clone();
    let vta_did = state.setup.vta.vta_did.clone();
    let mediator_did = state.setup.vta.mediator_did.clone();
    if vta_did.is_empty() {
        return Err(anyhow::anyhow!("VTA DID not populated in setup state"));
    }
    // For REST-only VTAs we still need a URL; for DIDComm-only VTAs the
    // signer talks to the mediator instead, so an empty URL is fine.
    if vta_url.is_empty() && mediator_did.is_none() {
        return Err(anyhow::anyhow!(
            "VTA exposes neither a REST URL nor a DIDComm mediator — \
             did-git-sign cannot reach the VTA"
        ));
    }

    let user_name = if state.setup.username.is_empty() {
        None
    } else {
        Some(state.setup.username.clone())
    };

    let result = did_git_sign::init::install(did_git_sign::init::InstallArgs {
        // Use a global config so signing works across every repo without
        // forcing the operator to re-init per-repo. Matches what most
        // operators expect from a single openvtc setup.
        global: true,
        did_key_id: did_key_id.clone(),
        vta_key_id,
        credential_did: admin.admin_did.clone(),
        credential_private_key_mb: admin.admin_private_key_mb.clone(),
        vta_did,
        vta_url,
        mediator_did,
        user_name,
        verifying_key: &verifying_key,
    })?;

    state.setup.did_git_sign.config_path = Some(result.config_path.display().to_string());
    state.setup.did_git_sign.ssh_public_key = Some(result.ssh_public_key);
    state.setup.did_git_sign.overridden_global_signing_key = result.overridden_global_signing_key;
    state.setup.did_git_sign.messages.push(MessageType::Info(
        "Git config + allowed_signers updated.".to_string(),
    ));
    state.setup.did_git_sign.messages.push(MessageType::Info(
        "VTA credentials stored in OS keyring.".to_string(),
    ));
    Ok(())
}
