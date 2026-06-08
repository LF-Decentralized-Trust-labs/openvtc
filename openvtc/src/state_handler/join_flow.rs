//! State-B "join a community" orchestration (R-A-5 Stage 4).
//!
//! [`StateHandler::join_flow`] is a nested `tokio::select!` loop modelled on
//! [`setup_wizard`](crate::state_handler::setup_wizard): it owns the screen
//! while [`ActivePage::Join`](crate::state_handler::state::ActivePage::Join) is
//! active, processes the join actions, renders via `state_tx`, and returns to
//! the main page when the user cancels or the sequence finishes.
//!
//! The actual work runs in [`run_join_sequence`]: mint a fresh persona (reusing
//! the setup VTA helpers), derive + register the per-community sub-context,
//! submit the join, and persist a `Pending` [`CommunityRecord`]. Every failure
//! is surfaced into the join log as a [`MessageType::Error`] — the loop never
//! `?`-bubbles a sequence error in a way that would kill the app.

use affinidi_tdk::TDK;
use anyhow::Result;
use chrono::Utc;
use openvtc_core::config::{
    Config,
    account::{CommunityRecord, PersonaId},
    context_path::build_sub_context_id,
};
use tokio::sync::{broadcast, mpsc::UnboundedReceiver};
use tracing::debug;
use vta_sdk::{client::VtaClient, protocols::did_management::create::WebvhPathMode};

use crate::{
    Interrupted,
    state_handler::{
        StateHandler,
        actions::Action,
        join::JoinPage,
        setup_sequence::{Completion, config::ConfigExtension, vta},
        state::{ActivePage, State},
    },
};

impl StateHandler {
    /// Run the join flow until the user cancels or the sequence finishes.
    ///
    /// Mirrors `setup_wizard`'s loop shape. `admin_vta` is the always-on admin
    /// VTA session (threaded in from the caller); `config` is mutated in place
    /// and persisted by the sequence on success.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn join_flow(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        state: &mut State,
        tdk: &TDK,
        config: &mut Config,
        admin_vta: Option<&VtaClient>,
        profile: &str,
    ) -> Result<JoinExit> {
        // Enter the flow on a fresh EnterDid page.
        state.join.reset();
        state.active_page = ActivePage::Join;
        let _ = self.state_tx.send(state.clone());

        loop {
            tokio::select! {
                maybe_action = action_rx.recv() => {
                    let Some(action) = maybe_action else {
                        // Channel closed — treat as a user-initiated exit.
                        return Ok(JoinExit::Exit(Interrupted::UserInt));
                    };
                    match action {
                        Action::Exit => return Ok(JoinExit::Exit(Interrupted::UserInt)),
                        Action::UXError(interrupted) => {
                            return Ok(JoinExit::Exit(interrupted));
                        }
                        Action::JoinCancel => {
                            // Leave the flow; the caller restores the main page.
                            state.active_page = ActivePage::Main;
                            return Ok(JoinExit::Returned);
                        }
                        Action::JoinSubmitVtc(vtc_did) => {
                            let vtc_did = vtc_did.trim().to_string();
                            if vtc_did.is_empty() {
                                continue;
                            }
                            // Move to the progress page and lock input.
                            state.join.page = JoinPage::Progress;
                            state.join.processing = true;
                            state.join.completed = Completion::NotFinished;
                            state.join.messages.clear();
                            state.join.info(format!("Joining {vtc_did}…"));
                            let _ = self.state_tx.send(state.clone());

                            run_join_sequence(
                                self,
                                state,
                                tdk,
                                config,
                                admin_vta,
                                profile,
                                vtc_did,
                            )
                            .await;

                            state.join.processing = false;
                            let _ = self.state_tx.send(state.clone());
                        }
                        _ => {}
                    }
                }
                Ok(interrupted) = interrupt_rx.recv() => {
                    return Ok(JoinExit::Exit(interrupted));
                }
            }
            let _ = self.state_tx.send(state.clone());
        }
    }
}

/// Outcome of a `join_flow` invocation.
pub(crate) enum JoinExit {
    /// User cancelled / finished — return to the main page and resume the
    /// caller's loop.
    Returned,
    /// Application is exiting (Exit / UXError / interrupt).
    Exit(Interrupted),
}

/// Run the automated mint → sub-context → join-submit → persist sequence.
///
/// All progress and errors land in `state.join`. On success
/// `state.join.completed` is `CompletedOK` and `created_community` holds the new
/// pending record; on any failure it is `CompletedFail` with the error logged.
async fn run_join_sequence(
    handler: &StateHandler,
    state: &mut State,
    tdk: &TDK,
    config: &mut Config,
    admin_vta: Option<&VtaClient>,
    profile: &str,
    vtc_did: String,
) {
    // 1. Idempotency (R-B-9): refuse a duplicate live/pending membership.
    if config.account.live_community(&vtc_did).is_some() {
        state
            .join
            .fail("Already a member of (or have a pending request for) this community.");
        return;
    }

    // 3. The mint + join sequence needs the admin VTA session.
    let Some(admin_vta) = admin_vta else {
        state
            .join
            .fail("VTA session unavailable — cannot join right now.");
        return;
    };

    // 2. Resolve a display name for the community (best-effort).
    let display_name = match tdk.did_resolver().resolve(&vtc_did).await {
        Ok(resolved) => resolved_display_name(&resolved.doc),
        Err(e) => {
            debug!("VTC DID resolve failed (continuing without name): {e}");
            None
        }
    };
    state.join.display_name = display_name.clone();

    let top_context_id = config.account.top_context_id.clone();

    // 4. Mint a fresh persona into `state.setup` (reusing the setup helpers).
    // Persona signing/auth/encryption keys.
    state
        .join
        .info("Creating persona keys (signing, authentication, encryption)…");
    let _ = handler.state_tx.send(state.clone());
    match vta::create_persona_keys(admin_vta, Some(&top_context_id)).await {
        Ok(keys) => state.setup.did_keys = Some(keys),
        Err(e) => {
            state
                .join
                .fail(format!("Failed to create persona keys: {e}"));
            return;
        }
    }
    // WebVH update keys.
    state.join.info("Creating DID update keys…");
    let _ = handler.state_tx.send(state.clone());
    match vta::create_update_keys(admin_vta, Some(&top_context_id)).await {
        Ok((update, next_update)) => {
            state.setup.vta.update_secret = Some(update);
            state.setup.vta.next_update_secret = Some(next_update);
        }
        Err(e) => {
            state
                .join
                .fail(format!("Failed to create update keys: {e}"));
            return;
        }
    }

    // Pick the first WebVH server. Serverless mint is a deliberate follow-up.
    state.join.info("Finding a DID hosting server…");
    let _ = handler.state_tx.send(state.clone());
    let server_id = match vta::list_webvh_servers(admin_vta).await {
        Ok(servers) => match servers.into_iter().next() {
            Some(s) => s.id,
            None => {
                state.join.fail(
                    "No WebVH server available from the VTA (serverless mint not yet supported).",
                );
                return;
            }
        },
        Err(e) => {
            state
                .join
                .fail(format!("Failed to list WebVH servers: {e}"));
            return;
        }
    };

    // Create the persona did:webvh via the server (auto-assigned path).
    state
        .join
        .info(format!("Creating persona DID via {server_id}…"));
    let _ = handler.state_tx.send(state.clone());
    match vta::create_did_via_server(
        admin_vta,
        tdk,
        &top_context_id,
        &server_id,
        WebvhPathMode::AutoAssign,
    )
    .await
    {
        Ok((keys, did, document, _mnemonic)) => {
            state.setup.did_keys = Some(keys);
            state.setup.webvh_address.did = did;
            state.setup.webvh_address.document = document;
        }
        Err(e) => {
            state
                .join
                .fail(format!("Failed to create persona DID: {e}"));
            return;
        }
    }

    // The persona's mediator is the account's VTA mediator: the DID minted via
    // the VTA's webvh server advertises that mediator in its DIDComm service, so
    // the persona listener must use the same one. Hardcoding `None` (the public
    // default) left the persona with no usable mediator — the listener then
    // failed with "No Mediator is configured" and retried forever.
    state.setup.custom_mediator = match &config.key_backend {
        openvtc_core::config::KeyBackend::Vta { mediator_did, .. } => mediator_did.clone(),
        _ => None,
    };
    state.setup.username = display_name.clone().unwrap_or_else(|| {
        openvtc_core::config::context_path::render_for_display(&vtc_did).to_string()
    });

    // 5. Persist the persona into the account.
    let persona_id = match Config::mint_persona_into(config, &state.setup, tdk, profile).await {
        Ok(id) => id,
        Err(e) => {
            state.join.fail(format!("Failed to save persona: {e}"));
            return;
        }
    };
    let persona_did = state.setup.webvh_address.did.clone();
    state.join.info(format!("Persona created: {persona_did}"));
    let _ = handler.state_tx.send(state.clone());

    // 6. Derive the per-community sub-context id (D9, collision-safe).
    let sub_context_id =
        match build_sub_context_id(&top_context_id, display_name.as_deref(), &vtc_did, |id| {
            config
                .account
                .communities
                .values()
                .any(|c| c.sub_context_id == id)
        }) {
            Ok(id) => id,
            Err(e) => {
                state
                    .join
                    .fail(format!("Failed to derive sub-context id: {e}"));
                rollback_minted_persona(config, persona_id, state, profile);
                return;
            }
        };

    // 7. Register the sub-context at the VTA.
    state
        .join
        .info(format!("Creating sub-context {sub_context_id}…"));
    let _ = handler.state_tx.send(state.clone());
    if let Err(e) = vta::create_sub_context(admin_vta, &top_context_id, &sub_context_id).await {
        state
            .join
            .fail(format!("Failed to create sub-context: {e}"));
        rollback_minted_persona(config, persona_id, state, profile);
        return;
    }

    // 8. Submit the join request to the VTC over DIDComm. The persona is
    // the authcrypt sender (the VTC reads the applicant from the
    // envelope — no holder-binding signature, and a did:webvh persona
    // can't use the VTC's did:key-only REST signature path). The minted
    // persona's runtime identity (ATM profile + mediator) was built into
    // `config.identities` by `mint_persona_into`. The VTC's
    // submit-receipt (with the authoritative requestId) returns
    // asynchronously to the persona's mediator; until that receipt
    // handler lands, the request message id is the correlation handle
    // stored on the Pending record.
    state.join.info("Submitting join request…");
    let _ = handler.state_tx.send(state.clone());

    let Some(atm) = tdk.atm.as_ref() else {
        state
            .join
            .fail("Messaging (ATM) unavailable — cannot submit the join request.");
        rollback_minted_persona(config, persona_id, state, profile);
        return;
    };
    let (applicant_did, persona_profile, persona_mediator) =
        match config.identities.get(&persona_id) {
            Some(ident) => (
                ident.persona_did().to_string(),
                ident.profile().clone(),
                ident.mediator_did.clone().unwrap_or_default(),
            ),
            None => {
                state
                    .join
                    .fail("Persona identity unavailable after mint — cannot submit.");
                rollback_minted_persona(config, persona_id, state, profile);
                return;
            }
        };
    let vp = serde_json::json!({
        "type": "VerifiablePresentation",
        "holder": applicant_did,
    });
    let request_id = match openvtc_core::join::submit_join_request(
        atm,
        &persona_profile,
        &applicant_did,
        &vtc_did,
        &persona_mediator,
        vp,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            state
                .join
                .fail(format!("Failed to submit join request: {e}"));
            rollback_minted_persona(config, persona_id, state, profile);
            return;
        }
    };

    // 9. Record the pending membership and persist.
    let record = CommunityRecord::new_pending(
        vtc_did.clone(),
        display_name,
        sub_context_id,
        persona_id,
        request_id,
        Utc::now(),
    );
    config.account.communities.insert(vtc_did, record.clone());
    if let Err(e) = save_config(config, profile) {
        state
            .join
            .fail(format!("Failed to save community record: {e}"));
        return;
    }

    // 10. Success — refresh the communities panel and surface the relaunch prompt.
    state.main_page.sync_from_config(config);
    state
        .main_page
        .log("Join request submitted — Pending in your Communities list.");
    state.join.created_community = Some(record);
    state.join.created_persona_did = Some(persona_did.clone());
    state.join.completed = Completion::CompletedOK;
    state
        .join
        .info("Join request submitted — it's now Pending in your Communities list.");
}

/// Persist the config, abstracting over the openpgp-card touch prompt.
/// Roll back a just-minted persona when a later join step fails before the
/// persona is bound to a community. The mint (`mint_persona_into`) persists the
/// persona record + runtime identity + key info *before* the submit; without
/// this, a failed join (e.g. a submit error) leaves an orphan persona in the
/// account — a spurious identity with no membership, which then confuses the
/// active-identity display. Best-effort re-save; the VTA-side keys are cleaned
/// separately via the DID manager.
fn rollback_minted_persona(
    config: &mut Config,
    persona_id: PersonaId,
    state: &State,
    profile: &str,
) {
    config.account.personas.remove(&persona_id);
    config.identities.remove(&persona_id);
    if let Some(keys) = &state.setup.did_keys {
        config.key_info.remove(&keys.signing.secret.id);
        config.key_info.remove(&keys.authentication.secret.id);
        config.key_info.remove(&keys.decryption.secret.id);
    }
    if let Err(e) = save_config(config, profile) {
        debug!("persona rollback re-save failed after a failed join: {e}");
    }
}

fn save_config(config: &Config, profile: &str) -> Result<(), openvtc_core::errors::OpenVTCError> {
    config.save(
        profile,
        #[cfg(feature = "openpgp-card")]
        &|| {
            eprintln!("Touch confirmation needed for decryption");
        },
    )
}

/// Best-effort display name from a resolved VTC DID document. Prefers a
/// non-empty `name`-like service/alias if present; falls back to `None` so the
/// sub-context derivation uses the DID-derived token (D9).
fn resolved_display_name(_doc: &affinidi_tdk::did_common::Document) -> Option<String> {
    // The DID-core document has no canonical human name field; community naming
    // (whois/metadata) is a later enrichment. Returning `None` keeps the
    // derivation deterministic (DID-token slug) until that lands.
    None
}
