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
    account::{CommunityRecord, PersonaId, VtcDid},
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
        join::{JoinPage, JoinState, PersonaOption, PresentedInvitation},
        main_page::content::{VicLifecycle, VicSummary},
        main_page::shorten_did,
        setup_sequence::{Completion, MessageType, config::ConfigExtension, vta},
        state::{ActivePage, State},
    },
};

/// Which identity to present to the community being joined (R-B-3 / D1).
#[derive(Clone, Debug)]
enum JoinIdentityChoice {
    /// Mint a fresh, self-contained `did:webvh` persona (D6).
    Mint,
    /// Reuse an existing account persona (links the user across communities).
    Reuse(PersonaId),
}

/// The persona + community of a just-completed join, handed back to the runtime
/// loop so it can bring a live session up immediately (R-B-5 / D11) rather than
/// only on the next launch.
pub(crate) struct JoinedSession {
    pub persona_id: PersonaId,
    pub persona_did: String,
    pub vtc_did: VtcDid,
}

/// Extract the [`JoinedSession`] from a finished join's state — `Some` only when
/// the sequence persisted a community (i.e. the join succeeded).
fn joined_session(js: &JoinState) -> Option<JoinedSession> {
    let record = js.created_community.as_ref()?;
    Some(JoinedSession {
        persona_id: record.persona_ref,
        persona_did: js.created_persona_did.clone().unwrap_or_default(),
        vtc_did: record.vtc_did.clone(),
    })
}

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
        // Surface the launch-supplied invitation on the entry page (reset clears
        // the transient join sub-state, so mirror the flag back in afterwards).
        state.join.has_invitation = state.invitation_credential.is_some();
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
                            // Hand back the joined session (if any) so the runtime
                            // loop can bring its live session up (R-B-5).
                            state.active_page = ActivePage::Main;
                            return Ok(JoinExit::Returned(joined_session(&state.join)));
                        }
                        Action::JoinPasteVic(text) => {
                            // #3: a pasted invitation credential — validate it is a
                            // VIC and stash it so the join presents it (mirrors the
                            // `--invitation <file>` launch flag).
                            match serde_json::from_str::<serde_json::Value>(&text) {
                                Ok(vic) => match openvtc_core::join::validate_invitation_credential(
                                    &vic,
                                ) {
                                    Ok(()) => {
                                        state.invitation_credential = Some(vic);
                                        state.join.has_invitation = true;
                                        state.join.vic_cleared = false;
                                        state.join.messages.clear();
                                    }
                                    Err(why) => {
                                        state.join.messages.push(MessageType::Error(format!(
                                            "Pasted invitation is not usable: {why}"
                                        )));
                                    }
                                },
                                Err(e) => {
                                    state.join.messages.push(MessageType::Error(format!(
                                        "Pasted text is not valid JSON: {e}"
                                    )));
                                }
                            }
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinClearVic => {
                            // Explicit "proceed without a VIC": drop the loaded
                            // invitation so it isn't presented, and flag the clear so
                            // the entry page shows "joining without an invitation".
                            state.invitation_credential = None;
                            state.join.has_invitation = false;
                            state.join.vic_cleared = true;
                            state.join.messages.clear();
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinSubmitVtc(vtc_did) => {
                            let Some(vtc_did) = validate_join_input(&vtc_did) else {
                                continue;
                            };
                            // Idempotency (R-B-9): refuse a duplicate live/pending
                            // membership before bothering the user with an identity
                            // choice.
                            if is_duplicate_membership(config, &vtc_did) {
                                state.join.page = JoinPage::Progress;
                                state.join.fail(
                                    "Already a member of (or have a pending request for) this community.",
                                );
                                let _ = self.state_tx.send(state.clone());
                                continue;
                            }
                            // When an invitation is available for THIS community —
                            // a loaded VIC that matches, or one held in the vault —
                            // let the operator choose whether to present it or join
                            // as an open request (default: present it). Shown only
                            // when one actually exists; otherwise there's nothing to
                            // choose and we go straight to identity selection.
                            if invitation_available_for(state, admin_vta, &vtc_did).await {
                                state.join.pending_vtc = Some(vtc_did);
                                state.join.invitation_use_selected = 0; // default: use it
                                state.join.present_invitation = true;
                                state.join.page = JoinPage::InvitationChoice;
                                let _ = self.state_tx.send(state.clone());
                                continue;
                            }
                            // No invitation available — nothing to present.
                            state.join.present_invitation = false;
                            if let Some(interrupted) = self
                                .proceed_after_invitation_choice(
                                    vtc_did,
                                    interrupt_rx,
                                    state,
                                    tdk,
                                    config,
                                    admin_vta,
                                    profile,
                                )
                                .await
                            {
                                return Ok(JoinExit::Exit(interrupted));
                            }
                        }
                        Action::JoinIdentitySelect(i) => {
                            // Clamp to the reuse rows plus the trailing "mint" row.
                            state.join.identity_selected = i.min(state.join.mint_row());
                            // Moving the highlight dismisses any armed warning.
                            state.join.reuse_confirm = None;
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinIdentityChoose => {
                            if state.join.mint_row_selected() {
                                let Some(vtc_did) = state.join.pending_vtc.clone() else {
                                    continue;
                                };
                                if let Some(interrupted) = self
                                    .launch_join_sequence(
                                        JoinIdentityChoice::Mint,
                                        vtc_did,
                                        interrupt_rx,
                                        state,
                                        tdk,
                                        config,
                                        admin_vta,
                                        profile,
                                    )
                                    .await
                                {
                                    return Ok(JoinExit::Exit(interrupted));
                                }
                            } else if let Some(opt) =
                                state.join.persona_options.get(state.join.identity_selected)
                            {
                                // Arm the cross-community linkage warning (D1).
                                state.join.reuse_confirm = Some(opt.id);
                                let _ = self.state_tx.send(state.clone());
                            }
                        }
                        Action::JoinReuseConfirm => {
                            let Some(persona_id) = state.join.reuse_confirm else {
                                continue;
                            };
                            let Some(vtc_did) = state.join.pending_vtc.clone() else {
                                continue;
                            };
                            state.join.reuse_confirm = None;
                            if let Some(interrupted) = self
                                .launch_join_sequence(
                                    JoinIdentityChoice::Reuse(persona_id),
                                    vtc_did,
                                    interrupt_rx,
                                    state,
                                    tdk,
                                    config,
                                    admin_vta,
                                    profile,
                                )
                                .await
                            {
                                return Ok(JoinExit::Exit(interrupted));
                            }
                        }
                        Action::JoinReuseCancel => {
                            state.join.reuse_confirm = None;
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinInvitationSelect(i) => {
                            // Two rows: 0 = use the invitation, 1 = join without it.
                            state.join.invitation_use_selected = i.min(1);
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinInvitationChoose => {
                            let Some(vtc_did) = state.join.pending_vtc.clone() else {
                                continue;
                            };
                            state.join.present_invitation =
                                state.join.invitation_use_selected == 0;
                            if let Some(interrupted) = self
                                .proceed_after_invitation_choice(
                                    vtc_did,
                                    interrupt_rx,
                                    state,
                                    tdk,
                                    config,
                                    admin_vta,
                                    profile,
                                )
                                .await
                            {
                                return Ok(JoinExit::Exit(interrupted));
                            }
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

    /// Route from the invitation choice (or directly when no invitation is
    /// available) to identity selection. When we'll present a loaded VIC bound to
    /// one of our personas, pre-select that persona (#1a/#1b); otherwise offer the
    /// persona list, or mint directly on a first join. Returns `Some(interrupted)`
    /// only when a direct mint launched and was interrupted mid-sequence.
    #[allow(clippy::too_many_arguments)]
    async fn proceed_after_invitation_choice(
        &self,
        vtc_did: String,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        state: &mut State,
        tdk: &TDK,
        config: &mut Config,
        admin_vta: Option<&VtaClient>,
        profile: &str,
    ) -> Option<Interrupted> {
        // #1a/#1b: a loaded invitation bound to one of our personas — pre-select
        // it so Enter joins as the invited identity (no linkage), and a different
        // choice builds the subject-linkage proof. Only when we'll present it.
        if state.join.present_invitation
            && let Some(pid) = invitation_subject_persona(config, state)
        {
            let options = build_persona_options(config);
            let idx = options.iter().position(|o| o.id == pid).unwrap_or(0);
            state.join.pending_vtc = Some(vtc_did);
            state.join.persona_options = options;
            state.join.identity_selected = idx;
            state.join.reuse_confirm = None;
            state.join.page = JoinPage::IdentityChoice;
            let _ = self.state_tx.send(state.clone());
            return None;
        }
        // R-B-3 / D1: with existing personas, let the user choose to reuse one or
        // mint a fresh identity; with none (the first join), mint directly.
        let options = build_persona_options(config);
        if options.is_empty() {
            return self
                .launch_join_sequence(
                    JoinIdentityChoice::Mint,
                    vtc_did,
                    interrupt_rx,
                    state,
                    tdk,
                    config,
                    admin_vta,
                    profile,
                )
                .await;
        }
        state.join.pending_vtc = Some(vtc_did);
        state.join.persona_options = options;
        state.join.identity_selected = 0;
        state.join.reuse_confirm = None;
        state.join.page = JoinPage::IdentityChoice;
        let _ = self.state_tx.send(state.clone());
        None
    }

    /// Move to the progress page and run [`run_join_sequence`] for the chosen
    /// identity, raced against the interrupt (R15). Returns `Some(interrupted)`
    /// when the user cancelled mid-sequence (the caller then exits the flow);
    /// `None` when the sequence ran to its own success/failure terminal.
    #[allow(clippy::too_many_arguments)]
    async fn launch_join_sequence(
        &self,
        choice: JoinIdentityChoice,
        vtc_did: String,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        state: &mut State,
        tdk: &TDK,
        config: &mut Config,
        admin_vta: Option<&VtaClient>,
        profile: &str,
    ) -> Option<Interrupted> {
        // Move to the progress page and lock input.
        state.join.page = JoinPage::Progress;
        state.join.processing = true;
        state.join.completed = Completion::NotFinished;
        state.join.messages.clear();
        state.join.info(format!("Joining {vtc_did}…"));
        let _ = self.state_tx.send(state.clone());

        // R15: race the multi-step VTA sequence against the interrupt so Ctrl-C /
        // Exit stay live for its whole (network-bound) duration. On interrupt the
        // sequence future is DROPPED — cancelled at whatever `.await` it parked
        // on. `minted_persona` is the only handle to mid-sequence persisted state
        // (`mint_persona_into` writes a persona before the receipt), so a cancel
        // after that point rolls it back. It lives outside the future so it stays
        // readable after the drop. A *reused* persona is never set here, so it is
        // never rolled back.
        let mut minted_persona: Option<PersonaId> = None;
        // Captured before the mint so a rollback (cancel or failure) can restore
        // it — `mint_persona_into` overwrites `public.friendly_name` with the
        // attempted community's persona name.
        let prior_friendly_name = config.public.friendly_name.clone();
        let sequence = run_join_sequence(
            self,
            state,
            tdk,
            config,
            admin_vta,
            profile,
            vtc_did,
            choice,
            &mut minted_persona,
            &prior_friendly_name,
        );
        let interrupted = race_against_interrupt(sequence, interrupt_rx).await;

        if let Some(interrupted) = interrupted {
            if let Some(persona_id) = minted_persona
                && !config.account.persona_referenced(&persona_id)
            {
                rollback_minted_persona(config, persona_id, state, profile, &prior_friendly_name);
            }
            state.join.processing = false;
            state.join.completed = Completion::CompletedFail;
            state.join.info(
                "Join cancelled. Any partially-minted persona was rolled back; a sub-context may remain at the VTA.",
            );
            state.main_page.log("Join cancelled by user.");
            let _ = self.state_tx.send(state.clone());
            return Some(interrupted);
        }

        state.join.processing = false;
        let _ = self.state_tx.send(state.clone());
        None
    }
}

/// Build the reuse options for the identity-choice page (R-B-3): every existing
/// persona, labelled, with the communities it is already presented to (the
/// linkage-warning detail). Sorted by label for a stable list.
fn build_persona_options(config: &Config) -> Vec<PersonaOption> {
    let mut options: Vec<PersonaOption> = config
        .account
        .personas
        .values()
        .map(|p| {
            let mut linked_communities: Vec<String> = config
                .account
                .communities
                .values()
                .filter(|c| c.persona_ref == p.persona_id)
                .map(|c| {
                    c.display_name
                        .clone()
                        .unwrap_or_else(|| shorten_did(&c.vtc_did, 40))
                })
                .collect();
            linked_communities.sort();
            PersonaOption {
                id: p.persona_id,
                label: p.label.clone().unwrap_or_else(|| shorten_did(&p.did, 32)),
                did: p.did.clone(),
                linked_communities,
            }
        })
        .collect();
    options.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.did.cmp(&b.did)));
    options
}

/// Outcome of a `join_flow` invocation.
pub(crate) enum JoinExit {
    /// User cancelled / finished — return to the main page and resume the
    /// caller's loop. Carries the just-joined session when a join succeeded, so
    /// the runtime loop can register it + start its listener live (R-B-5).
    Returned(Option<JoinedSession>),
    /// Application is exiting (Exit / UXError / interrupt).
    Exit(Interrupted),
}

/// Validate the raw VTC DID the operator submitted on the EnterDid page.
///
/// Pure decision peeled out of the `JoinSubmitVtc` arm: trims surrounding
/// whitespace and rejects an empty input (the loop `continue`s, staying on the
/// EnterDid page). Returns the cleaned DID to drive the sequence with, or `None`
/// when there is nothing to submit.
fn validate_join_input(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// #1a: the existing persona a loaded invitation is bound to, if any. When the
/// VIC's `credentialSubject.id` matches one of our personas, the join can
/// present that persona directly (holder-binding satisfied, no linkage proof).
fn invitation_subject_persona(config: &Config, state: &State) -> Option<PersonaId> {
    let vic = state.invitation_credential.as_ref()?;
    let subject = openvtc_core::join::invitation_subject(vic)?;
    config.account.persona_id_for_did(subject)
}

/// Whether an invitation for `vtc_did` is available to present — a loaded VIC
/// that matches this community and is currently usable, or a community-matched,
/// valid VIC held in the vault. Drives the invitation-choice step, which is shown
/// only when one actually exists. Best-effort: with no admin VTA only a loaded
/// VIC counts. The vault check fetches the candidate body; the join sequence
/// re-resolves it independently, so this stays a pure availability probe.
async fn invitation_available_for(
    state: &State,
    admin_vta: Option<&VtaClient>,
    vtc_did: &str,
) -> bool {
    if let Some(vic) = state.invitation_credential.as_ref()
        && openvtc_core::join::invitation_matches_community(vic, vtc_did)
        && !openvtc_core::join::invitation_is_expired(vic, Utc::now())
        && openvtc_core::join::validate_invitation_credential(vic).is_ok()
    {
        return true;
    }
    match admin_vta {
        Some(vta) => load_invitation_from_vault(vta, vtc_did).await.is_some(),
        None => false,
    }
}

/// #2: load a *presentable* invitation the VTA already holds for the community
/// being joined (`vtc_did`). Queries the credential vault for `purpose = invite`
/// and selects an active, vault-valid (not expired / revoked) VIC whose issuer is
/// this community — preferring the one that stays valid longest — then fetches
/// its body. The first-match grab this replaced could present a VIC for the wrong
/// community (or an expired one), which the VTC then rejected. Best-effort: any
/// error / no match yields `None`, and the join proceeds as an open request.
async fn load_invitation_from_vault(
    admin_vta: &VtaClient,
    vtc_did: &str,
) -> Option<serde_json::Value> {
    let listing = admin_vta
        .cred_vault_query(serde_json::json!({ "purpose": "invite" }))
        .await
        .ok()?;
    let descriptors = listing.get("credentials").and_then(|c| c.as_array())?;
    // Community-matched, active, vault-valid candidates; prefer the latest
    // `validUntil` (longest-lived). RFC 3339 timestamps sort lexicographically.
    let best = descriptors
        .iter()
        .map(VicSummary::from_descriptor)
        .filter(|v| {
            v.issuer == vtc_did && v.status == "valid" && v.lifecycle == VicLifecycle::Active
        })
        .max_by(|a, b| a.valid_until.cmp(&b.valid_until))?;
    let got = admin_vta.cred_vault_get(&best.id).await.ok()?;
    got.get("credential").cloned()
}

/// #1b: build a subject-linkage proof when the presenting DID differs from the
/// loaded VIC's subject — the invited persona authorizes the presenter. Returns
/// `None` on the join-as-subject path (presenter == subject), when no invitation
/// is loaded, or when the subject isn't one of our personas (we can't sign for a
/// key we don't hold; the VTC then refuses the mismatched binding). Best-effort:
/// a signing failure is logged and yields `None`.
async fn build_linkage_proof(
    config: &Config,
    admin_vta: &VtaClient,
    state: &State,
    presenter_did: &str,
) -> Option<openvtc_core::join::SubjectLinkage> {
    let vic = state.invitation_credential.as_ref()?;
    let subject = openvtc_core::join::invitation_subject(vic)?;
    if subject == presenter_did {
        return None; // join-as-subject — no linkage needed
    }
    let vic_id = openvtc_core::join::invitation_id(vic)?;
    match config
        .build_subject_linkage(subject, Some(admin_vta), vic_id, presenter_did)
        .await
    {
        Ok(linkage) => Some(linkage),
        Err(e) => {
            debug!(subject = %subject, error = %e, "subject-linkage proof unavailable");
            None
        }
    }
}

/// Idempotency decision (R-B-9): is there already a *live* (Active/Pending)
/// membership for this VTC?
///
/// Pure decision peeled out of step 1 of [`run_join_sequence`]; a `true` result
/// surfaces the "already a member" failure instead of submitting a duplicate.
/// Delegates to [`Account::live_community`] so the live/inactive policy stays in
/// one place.
fn is_duplicate_membership(config: &Config, vtc_did: &str) -> bool {
    config
        .account
        .live_community(&vtc_did.to_string())
        .is_some()
}

/// Build the `Pending` [`CommunityRecord`] recorded on a successful submit.
///
/// Pure decision peeled out of step 9 of [`run_join_sequence`]; delegates to
/// [`CommunityRecord::new_pending`] so the record shape stays defined in core.
fn build_pending_record(
    vtc_did: String,
    display_name: Option<String>,
    sub_context_id: String,
    persona_id: PersonaId,
    request_id: uuid::Uuid,
    now: chrono::DateTime<Utc>,
) -> CommunityRecord {
    CommunityRecord::new_pending(
        vtc_did,
        display_name,
        sub_context_id,
        persona_id,
        request_id,
        now,
    )
}

/// Run the automated mint → sub-context → join-submit → persist sequence.
///
/// All progress and errors land in `state.join`. On success
/// `state.join.completed` is `CompletedOK` and `created_community` holds the new
/// pending record; on any failure it is `CompletedFail` with the error logged.
///
/// `minted_persona` is written as soon as the persona is minted-and-persisted so
/// the caller can roll it back if the whole future is cancelled (R15) before the
/// persona is bound to a community.
#[allow(clippy::too_many_arguments)]
async fn run_join_sequence(
    handler: &StateHandler,
    state: &mut State,
    tdk: &TDK,
    config: &mut Config,
    admin_vta: Option<&VtaClient>,
    profile: &str,
    vtc_did: String,
    choice: JoinIdentityChoice,
    minted_persona: &mut Option<PersonaId>,
    prior_friendly_name: &str,
) {
    // Idempotency (R-B-9) was already enforced at submit, before the identity
    // choice — no re-check here.

    // The mint + join sequence needs the admin VTA session.
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

    // Resolve the persona to present: reuse an existing account persona (R-B-3)
    // or mint a fresh, self-contained one (D6). Only a *minted* persona is
    // recorded in `minted_persona` for rollback — a reused persona pre-exists and
    // must never be rolled back.
    let (persona_id, persona_did) = match choice {
        JoinIdentityChoice::Reuse(persona_id) => match config.identities.get(&persona_id) {
            Some(ident) => {
                let did = ident.persona_did().to_string();
                state.join.info(format!("Reusing persona {did}…"));
                let _ = handler.state_tx.send(state.clone());
                (persona_id, did)
            }
            None => {
                state
                    .join
                    .fail("Selected persona is unavailable — cannot reuse it.");
                return;
            }
        },
        JoinIdentityChoice::Mint => {
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

            // 5. Persist the persona into the account. `mint_persona_into` writes the
            // persona record + runtime identity + key info to disk *immediately* (a
            // synchronous `Config::save`), so from here until the community record is
            // persisted (step 9) the on-disk config holds a persona with no community.
            // Record its id so a cancel (R15) or later failure can roll it back.
            let persona_id =
                match Config::mint_persona_into(config, &state.setup, tdk, profile).await {
                    Ok(id) => id,
                    Err(e) => {
                        state.join.fail(format!("Failed to save persona: {e}"));
                        return;
                    }
                };
            *minted_persona = Some(persona_id);
            let persona_did = state.setup.webvh_address.did.clone();
            state.join.info(format!("Persona created: {persona_did}"));
            let _ = handler.state_tx.send(state.clone());
            (persona_id, persona_did)
        }
    };
    // Only a freshly-minted persona is rolled back on a later failure; a reused
    // persona pre-existed and is left intact.
    let minted = minted_persona.is_some();

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
                if minted {
                    rollback_minted_persona(
                        config,
                        persona_id,
                        state,
                        profile,
                        prior_friendly_name,
                    );
                }
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
        if minted {
            rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
        }
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
        if minted {
            rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
        }
        return;
    };
    let (applicant_did, persona_profile, persona_mediator) = match config
        .identities
        .get(&persona_id)
    {
        Some(ident) => (
            ident.persona_did().to_string(),
            ident.profile().clone(),
            ident.mediator_did.clone().unwrap_or_default(),
        ),
        None => {
            state
                .join
                .fail("Persona identity unavailable after mint — cannot submit.");
            if minted {
                rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
            }
            return;
        }
    };
    // #2: resolve the VIC to present for THIS community. A VIC's issuer is the
    // community's VTC DID, so a presentable invitation must match `vtc_did` and
    // be unexpired — presenting a mismatched or expired one only earns a VTC
    // rejection (and reads as a failed invitation rather than an open request).
    // An explicitly loaded VIC (--invitation / paste) is still stored in the
    // vault regardless (its durable home), but only *presented* when it matches;
    // otherwise we fall back to a community-matched VIC the vault already holds,
    // else submit as an open request. Setting `state.invitation_credential` to
    // the resolved VIC keeps the VP, the linkage proof, and the summary all
    // consistent with what is actually presented. All vault calls are
    // best-effort — the join proceeds regardless.
    let loaded = state.invitation_credential.take();
    let mut presentable: Option<serde_json::Value> = None;
    if state.join.present_invitation {
        // The operator chose to present an invitation (or one was available and
        // they accepted the default). Resolve the one to present.
        if let Some(vic) = loaded {
            if let Err(e) = admin_vta.cred_vault_receive(vic.clone(), None).await {
                debug!(error = %e, "storing invitation in the VTA vault failed (continuing)");
            }
            if !openvtc_core::join::invitation_matches_community(&vic, &vtc_did) {
                state.join.info(
                    "Loaded invitation is for a different community — \
                     looking for one that matches…",
                );
            } else if openvtc_core::join::invitation_is_expired(&vic, Utc::now()) {
                state
                    .join
                    .info("Loaded invitation has expired — looking for a valid one…");
            } else {
                presentable = Some(vic);
            }
        }
        if presentable.is_none() {
            presentable = load_invitation_from_vault(admin_vta, &vtc_did).await;
        }
    } else if let Some(vic) = loaded {
        // The operator chose to join *without* an invitation. Still store a
        // loaded VIC in the vault (its durable home) but present nothing — this
        // is what honours the choice over the vault fallback above.
        if let Err(e) = admin_vta.cred_vault_receive(vic, None).await {
            debug!(error = %e, "storing invitation in the VTA vault failed (continuing)");
        }
        state
            .join
            .info("Joining without an invitation — submitting an open request (awaiting approval).");
    }
    // Completeness gate before presenting: a VIC resolved from the vault may
    // predate the ingest-time validation (or have lost fields in storage). An
    // incomplete VIC is unusable — the VTC can't extract it and silently refers
    // the join to a moderator — so drop it here and fall to an open request with
    // a clear reason, rather than presenting junk.
    if let Some(vic) = &presentable
        && let Err(why) = openvtc_core::join::validate_invitation_credential(vic)
    {
        state.join.info(format!(
            "Resolved invitation is incomplete ({why}) — submitting as an open request instead."
        ));
        presentable = None;
    }
    state.invitation_credential = presentable;
    state.join.has_invitation = state.invitation_credential.is_some();
    state.join.presented_invitation =
        state
            .invitation_credential
            .as_ref()
            .map(|vic| PresentedInvitation {
                id: openvtc_core::join::invitation_id(vic)
                    .unwrap_or_default()
                    .to_string(),
                subject: openvtc_core::join::invitation_subject(vic).map(str::to_string),
            });

    // Present the holder VP. When a matching, unexpired invitation (VIC) is
    // resolved it rides in the VP's `verifiableCredential` array; the VTC
    // verifies it and auto-admits on a valid, trusted, unconsumed invitation (no
    // manual approval). With no presentable invitation the join is an open
    // request the community reviews and approves manually.
    if state.invitation_credential.is_some() {
        state
            .join
            .info("Presenting your invitation credential to the community…");
    } else if state.join.present_invitation {
        // Wanted to present one, but none resolved to a usable VIC.
        state.join.info(
            "No valid invitation for this community — \
             submitting as an open request (awaiting approval).",
        );
    }
    // (When the operator chose to join without an invitation, the note was
    // already surfaced above where the VIC was suppressed.)
    let _ = handler.state_tx.send(state.clone());
    // Subject-linkage (#1b): when the presenting DID differs from the VIC
    // subject, prove the subject authorized this presenter (signed with the
    // subject persona's key). On the join-as-subject path (#1a) this is `None`.
    let linkage = build_linkage_proof(config, admin_vta, state, &applicant_did).await;
    let vp = openvtc_core::join::build_join_vp(
        &applicant_did,
        state.invitation_credential.as_ref(),
        linkage.as_ref(),
    );
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
            rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
            return;
        }
    };

    // 9. Record the pending membership and persist.
    let record = build_pending_record(
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
    prior_friendly_name: &str,
) {
    config.account.personas.remove(&persona_id);
    config.identities.remove(&persona_id);
    if let Some(keys) = &state.setup.did_keys {
        config.key_info.remove(&keys.signing.secret.id);
        config.key_info.remove(&keys.authentication.secret.id);
        config.key_info.remove(&keys.decryption.secret.id);
    }
    // `mint_persona_into` set `public.friendly_name` to the attempted community's
    // persona name; restore the pre-mint value so a failed/cancelled join doesn't
    // leave the self-display name pointing at a community we never joined.
    config.public.friendly_name = prior_friendly_name.to_string();
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

/// Race a sequence future against the interrupt channel (R15).
///
/// Returns `None` if `sequence` completed first, or `Some(interrupted)` if an
/// interrupt arrived while it was still running — in which case `sequence` is
/// DROPPED (cancelled at its current `.await` point) by the `select!`. Dropping
/// the future is what makes Ctrl-C / Exit take effect within ~1 s even while a
/// network await is parked; the caller is responsible for any state cleanup the
/// dropped future may have left behind (e.g. a persisted-but-unbound persona).
async fn race_against_interrupt<F>(
    sequence: F,
    interrupt_rx: &mut broadcast::Receiver<Interrupted>,
) -> Option<Interrupted>
where
    F: std::future::Future<Output = ()>,
{
    tokio::select! {
        () = sequence => None,
        Ok(interrupted) = interrupt_rx.recv() => Some(interrupted),
    }
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

#[cfg(test)]
mod tests {
    //! R15: these tests cover the *select-against-interrupt wiring* in
    //! isolation — i.e. that an interrupt delivered while the join sequence is
    //! still running wins the race, drops the sequence future, and surfaces the
    //! interrupt. The full end-to-end cancel-safety property (a Ctrl-C against a
    //! live/unreachable VTA leaves no persisted-but-unbound persona) needs a real
    //! `StateHandler` + `TDK` + VTA session and is NOT unit-testable here; it is
    //! covered by manual verification and the in-code rollback at the cancel site
    //! (`join_flow` → `rollback_minted_persona` when `!persona_referenced`).

    use super::race_against_interrupt;
    use super::{
        build_pending_record, is_duplicate_membership, joined_session, validate_join_input,
    };
    use crate::Interrupted;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::join::JoinState;
    use openvtc_core::config::account::{CommunityRecord, CommunityStatus, PersonaId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::broadcast;

    // ---- Pure-decision tests (peeled out of the join sequence) ----

    /// `validate_join_input` trims and rejects empties; otherwise returns the
    /// cleaned DID. Table-driven over (raw input, expected).
    #[test]
    fn validate_join_input_table() {
        let cases: &[(&str, Option<&str>)] = &[
            ("", None),
            ("   ", None),
            ("\t\n", None),
            ("did:webvh:example", Some("did:webvh:example")),
            ("  did:webvh:example  ", Some("did:webvh:example")),
            ("\tdid:peer:abc\n", Some("did:peer:abc")),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                validate_join_input(raw).as_deref(),
                *expected,
                "validate_join_input({raw:?})"
            );
        }
    }

    /// `is_duplicate_membership` mirrors `Account::live_community`: live
    /// (Active/Pending) memberships are duplicates; inactive ones and unknown
    /// DIDs are not. Table-driven over the membership status.
    #[test]
    fn is_duplicate_membership_table() {
        // (status to register for "did:vtc:known", is_duplicate?)
        let cases: &[(Option<CommunityStatus>, bool)] = &[
            (None, false),
            (
                Some(CommunityStatus::Pending {
                    request_id: uuid::Uuid::new_v4(),
                }),
                true,
            ),
            (Some(CommunityStatus::Active), true),
            (Some(CommunityStatus::Left), false),
            (Some(CommunityStatus::Rejected), false),
            (Some(CommunityStatus::Removed), false),
            (Some(CommunityStatus::Expired), false),
        ];
        let vtc = "did:vtc:known";
        for (status, expected) in cases {
            let mut config = test_config();
            if let Some(status) = status {
                let mut rec = CommunityRecord::new_pending(
                    vtc.to_string(),
                    None,
                    "ctx/slug".to_string(),
                    PersonaId::new(),
                    uuid::Uuid::new_v4(),
                    chrono::Utc::now(),
                );
                rec.status = status.clone();
                config.account.communities.insert(vtc.to_string(), rec);
            }
            assert_eq!(
                is_duplicate_membership(&config, vtc),
                *expected,
                "is_duplicate_membership for status {status:?}"
            );
            // An unrelated DID is never a duplicate regardless of registered state.
            assert!(
                !is_duplicate_membership(&config, "did:vtc:other"),
                "unknown DID is not a duplicate (status {status:?})"
            );
        }
    }

    /// `build_pending_record` produces a `Pending` record carrying the submit
    /// inputs (vtc/display name/sub-context/persona/request id/requested_at).
    #[test]
    fn build_pending_record_carries_inputs() {
        let persona = PersonaId::new();
        let request_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let rec = build_pending_record(
            "did:vtc:c".to_string(),
            Some("Community".to_string()),
            "top/slug".to_string(),
            persona,
            request_id,
            now,
        );
        assert_eq!(rec.vtc_did, "did:vtc:c");
        assert_eq!(rec.display_name.as_deref(), Some("Community"));
        assert_eq!(rec.sub_context_id, "top/slug");
        assert_eq!(rec.persona_ref, persona);
        assert_eq!(rec.requested_at, Some(now));
        assert!(rec.is_live(), "a fresh Pending record is live");
        match rec.status {
            CommunityStatus::Pending { request_id: got } => {
                assert_eq!(got, request_id, "request id is carried into the status");
            }
            other => panic!("expected Pending status, got {other:?}"),
        }
    }

    #[test]
    fn joined_session_extracted_only_on_success() {
        // No persisted community → nothing for the runtime loop to register (R-B-5).
        let mut js = JoinState::default();
        assert!(joined_session(&js).is_none());

        // A successful sequence leaves the record + persona did → a session.
        let persona = PersonaId::new();
        let rec = build_pending_record(
            "did:vtc:c".to_string(),
            None,
            "top/slug".to_string(),
            persona,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
        );
        js.created_community = Some(rec);
        js.created_persona_did = Some("did:webvh:persona".to_string());

        let joined = joined_session(&js).expect("a persisted community yields a session");
        assert_eq!(joined.persona_id, persona);
        assert_eq!(joined.persona_did, "did:webvh:persona");
        assert_eq!(joined.vtc_did, "did:vtc:c");
    }

    #[tokio::test]
    async fn completes_when_no_interrupt() {
        let (_tx, mut rx) = broadcast::channel::<Interrupted>(4);
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = ran.clone();
        let outcome = race_against_interrupt(
            async move {
                ran2.store(true, Ordering::SeqCst);
            },
            &mut rx,
        )
        .await;
        assert!(outcome.is_none(), "no interrupt → sequence wins the race");
        assert!(
            ran.load(Ordering::SeqCst),
            "sequence future ran to completion"
        );
    }

    #[tokio::test]
    async fn interrupt_cancels_pending_sequence() {
        let (tx, mut rx) = broadcast::channel::<Interrupted>(4);
        // Deliver the interrupt before the race so the recv arm is immediately
        // ready; the sequence is a never-completing future, so the only way to
        // return is via the interrupt arm dropping it.
        tx.send(Interrupted::UserInt).expect("send interrupt");
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = completed.clone();
        let outcome = race_against_interrupt(
            async move {
                std::future::pending::<()>().await;
                // Unreachable: the future is dropped at the await above.
                completed2.store(true, Ordering::SeqCst);
            },
            &mut rx,
        )
        .await;
        assert!(
            matches!(outcome, Some(Interrupted::UserInt)),
            "interrupt wins and is surfaced: {outcome:?}"
        );
        assert!(
            !completed.load(Ordering::SeqCst),
            "pending sequence future was dropped, not run to completion"
        );
    }

    #[tokio::test]
    async fn surfaces_os_sigint_variant() {
        let (tx, mut rx) = broadcast::channel::<Interrupted>(4);
        tx.send(Interrupted::OsSigInt).expect("send interrupt");
        let outcome = race_against_interrupt(std::future::pending::<()>(), &mut rx).await;
        assert!(
            matches!(outcome, Some(Interrupted::OsSigInt)),
            "the specific interrupt variant propagates: {outcome:?}"
        );
    }
}
