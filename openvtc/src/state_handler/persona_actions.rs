//! Identity-pane business logic: what each key does to the pane's state, and
//! which of them need the agent.
//!
//! Split the way the architecture asks for it. [`apply`] is pure — it takes
//! `&mut State` and an action, mutates the pane, and *names* any network work
//! as a [`PersonaEffect`] rather than doing it. The loop spawns that off-thread
//! and folds the result back in through [`PersonaOutcome::apply`], on the loop
//! thread, so the single-mutator invariant holds and every decision this module
//! makes is testable without a `VtaClient`.
//!
//! # One domain for the whole pane
//!
//! Reads and writes share [`DispatchDomain::PersonaManage`], so a listing
//! cannot overtake the write that invalidated it. A write asks for a re-read by
//! setting `refresh_queued` rather than starting one, because its own outcome
//! is still holding the domain — the same shape the VIC manager uses.
//!
//! # Questions are asked once, and correctly
//!
//! Deleting an attribute a profile references is refused by the VTA unless the
//! caller cascades; deleting a profile a face presents is refused unless the
//! caller unbinds. Neither refusal is *discovered* here. The profile listing
//! already says which attributes are referenced and the binding map already
//! says which profiles are presented, so the prompt names the real consequence
//! the first time it is put. Asking "delete this?", being refused, and then
//! asking "delete it and edit three profiles?" trains a holder to answer the
//! second question with the first one's reasoning.

use std::collections::HashMap;

use openvtc_core::persona::{
    binding, disclosure,
    pool::{self, AttributeDraft, PoolAttribute},
    profile::{self, ProfileDetail, ProfileSummary},
};
use vta_sdk::client::VtaClient;

use crate::state_handler::actions::PersonaAction;
use crate::state_handler::main_page::content::{
    AttributeField, AttributeForm, BindPicker, PersonaConfirm, PersonaMode, PersonaTab,
    ProfileForm, ProfileFormFocus, VALUE_TYPES,
};
use crate::state_handler::persona_binding_refresh::{self, BindingTarget};
use crate::state_handler::state::State;

/// What an action needs beyond the state change [`apply`] already made.
pub(crate) enum PersonaEffect {
    /// Nothing — a pure view change.
    None,
    /// Re-read the agent-served tabs.
    Read,
    /// One round-trip, already resolved to its arguments on the loop thread.
    Job(PersonaJob),
}

/// A single persona round-trip.
pub(crate) enum PersonaJob {
    AttributePut(AttributeDraft),
    AttributeDelete {
        attribute_id: String,
        cascade: bool,
    },
    ProfilePut {
        profile_id: Option<String>,
        name: String,
        live_refs: Vec<String>,
        other_entries: Vec<vta_sdk::protocols::persona::ProfileEntry>,
        expected_version: Option<u64>,
    },
    ProfileDelete {
        profile_id: String,
        unbind: bool,
    },
    /// Read one profile — to show what it presents, or to fill the editor.
    ProfileGet {
        profile_id: String,
        /// `true` fills the editor: it needs the entries, not the values, so it
        /// does not ask the VTA to resolve them. A read that decrypts the pool
        /// to populate a form the holder may cancel is a read that did not need
        /// to happen.
        edit: bool,
    },
    /// Decide what one face presents in one context.
    Bind {
        context_id: String,
        persona_did: String,
        profile_id: Option<String>,
        community: String,
    },
}

// ---------------------------------------------------------------------------
// The reducer
// ---------------------------------------------------------------------------

/// Apply one identity-pane action. Pure: mutates the pane and returns the
/// network work the loop still owes.
pub(crate) fn apply(state: &mut State, action: &PersonaAction) -> PersonaEffect {
    match action {
        PersonaAction::TabNext | PersonaAction::TabPrev => {
            let p = &mut state.main_page.content_panel.personas;
            p.tab = match action {
                PersonaAction::TabNext => p.tab.next(),
                _ => p.tab.prev(),
            };
            // Leaving a tab drops what was armed or opened on it. A `y` is
            // answered on the screen that asked, never two tabs later.
            p.confirm = PersonaConfirm::None;
            p.open_profile = None;
            p.status_message = None;
            // Read on arrival, once. The agent-served tabs are not polled: a
            // pane nobody has opened should not be asking the agent about the
            // holder's identity every few seconds.
            if p.tab.needs_agent() && !p.loaded && !p.loading {
                return PersonaEffect::Read;
            }
            PersonaEffect::None
        }
        PersonaAction::Select(index) => {
            let p = &mut state.main_page.content_panel.personas;
            match p.tab {
                PersonaTab::Faces => p.face_selected = *index,
                PersonaTab::Attributes => p.attribute_selected = *index,
                PersonaTab::Profiles => p.profile_selected = *index,
                PersonaTab::Communities => p.membership_selected = *index,
                PersonaTab::Disclosures => p.disclosure_selected = *index,
            }
            PersonaEffect::None
        }
        PersonaAction::Refresh => PersonaEffect::Read,
        PersonaAction::ToggleValues => {
            let p = &mut state.main_page.content_panel.personas;
            p.show_values = !p.show_values;
            // A re-read, not a redraw: a listing fetched without values does
            // not hold them. Flipping a display flag over data already in
            // memory would mean the values had been read all along.
            PersonaEffect::Read
        }

        // ── Attributes ───────────────────────────────────────────────────
        PersonaAction::AttributeNew => {
            let p = &mut state.main_page.content_panel.personas;
            p.mode = PersonaMode::Attribute(AttributeForm::default());
            PersonaEffect::None
        }
        PersonaAction::AttributeEdit(index) => {
            let p = &mut state.main_page.content_panel.personas;
            let Some(attr) = p.attributes.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            if !attr.provenance.is_editable_here() {
                // Refused with the reason, not with a form that would fail on
                // save. See `pool`'s module header.
                if let pool::AttributeEdit::Refused(why) =
                    pool::AttributeEdit::refusal(attr.provenance)
                {
                    p.status_message = Some(why);
                }
                return PersonaEffect::None;
            }
            p.mode = PersonaMode::Attribute(form_for(&attr));
            // The editor was opened without a value in hand if the listing was
            // fetched without one, and saving would then blank it. Fetch the
            // values so the form starts from what is actually stored.
            if !p.show_values {
                p.show_values = true;
                return PersonaEffect::Read;
            }
            PersonaEffect::None
        }
        PersonaAction::AttributeDeleteArm(index) => {
            let p = &mut state.main_page.content_panel.personas;
            let Some(attr) = p.attributes.get(*index) else {
                return PersonaEffect::None;
            };
            // Referenced by a profile? Then the only delete that will succeed
            // is the cascading one, and that is the question to put.
            let cascade = p
                .profiles
                .iter()
                .any(|profile| profile.referenced.contains(&attr.attribute_id));
            p.confirm = PersonaConfirm::DeleteAttribute {
                attribute_id: attr.attribute_id.clone(),
                name: attr.display_name().to_string(),
                cascade,
            };
            PersonaEffect::None
        }

        // ── Profiles ─────────────────────────────────────────────────────
        PersonaAction::ProfileOpen(index) | PersonaAction::ProfileEdit(index) => {
            let edit = matches!(action, PersonaAction::ProfileEdit(_));
            let p = &mut state.main_page.content_panel.personas;
            let Some(profile) = p.profiles.get(*index) else {
                return PersonaEffect::None;
            };
            PersonaEffect::Job(PersonaJob::ProfileGet {
                profile_id: profile.profile_id.clone(),
                edit,
            })
        }
        PersonaAction::ProfileClose => {
            state.main_page.content_panel.personas.open_profile = None;
            PersonaEffect::None
        }
        PersonaAction::ProfileNew => {
            state.main_page.content_panel.personas.mode =
                PersonaMode::Profile(ProfileForm::default());
            PersonaEffect::None
        }
        PersonaAction::ProfileDeleteArm(index) => {
            let p = &mut state.main_page.content_panel.personas;
            let Some(profile) = p.profiles.get(*index) else {
                return PersonaEffect::None;
            };
            // Presented by a face somewhere? Deleting then leaves that face
            // presenting nothing, which the prompt has to say.
            let unbind = p
                .bindings
                .values()
                .any(|b| b.profile_id.as_deref() == Some(profile.profile_id.as_str()));
            p.confirm = PersonaConfirm::DeleteProfile {
                profile_id: profile.profile_id.clone(),
                name: profile.display_name().to_string(),
                unbind,
            };
            PersonaEffect::None
        }

        // ── Communities ──────────────────────────────────────────────────
        PersonaAction::BindOpen(index) => {
            let p = &mut state.main_page.content_panel.personas;
            let Some(membership) = p.memberships.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            // Start on what is bound now, so ⏎ on an unchanged picker is a
            // no-op rather than a silent unbind.
            let current = p.binding_for(&membership).profile_id;
            let cursor = current
                .and_then(|id| p.profiles.iter().position(|x| x.profile_id == id))
                .map_or(0, |i| i + 1);
            p.mode = PersonaMode::Bind(BindPicker {
                context_id: membership.sub_context_id.clone(),
                persona_did: membership.persona_did.clone(),
                community: membership.community_name.clone(),
                face_label: membership.face_label.clone(),
                cursor,
                working: false,
                error: None,
            });
            PersonaEffect::None
        }
        PersonaAction::UnbindArm(index) => {
            let p = &mut state.main_page.content_panel.personas;
            let Some(m) = p.memberships.get(*index) else {
                return PersonaEffect::None;
            };
            p.confirm = PersonaConfirm::Unbind {
                context_id: m.sub_context_id.clone(),
                persona_did: m.persona_did.clone(),
                community: m.community_name.clone(),
            };
            PersonaEffect::None
        }

        // ── The confirmation slot ────────────────────────────────────────
        PersonaAction::ConfirmNo => {
            state.main_page.content_panel.personas.confirm = PersonaConfirm::None;
            PersonaEffect::None
        }
        PersonaAction::ConfirmYes => confirm_yes(state),

        // ── Forms ────────────────────────────────────────────────────────
        PersonaAction::FormKey(key) => {
            use tui_input::backend::crossterm::EventHandler;
            let p = &mut state.main_page.content_panel.personas;
            let event = crossterm::event::Event::Key(*key);
            match &mut p.mode {
                PersonaMode::Attribute(form) => {
                    match form.field {
                        AttributeField::ClaimType => form.claim_type.handle_event(&event),
                        AttributeField::Label => form.label.handle_event(&event),
                        AttributeField::Value => form.value.handle_event(&event),
                        // The type is a choice, not a text field: ←/→ move it
                        // and a keystroke here is not an edit.
                        AttributeField::ValueType => None,
                    };
                }
                PersonaMode::Profile(form) => {
                    if form.focus == ProfileFormFocus::Name {
                        form.name.handle_event(&event);
                    }
                }
                PersonaMode::Bind(_) | PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormField(forwards) => {
            let p = &mut state.main_page.content_panel.personas;
            match &mut p.mode {
                PersonaMode::Attribute(form) => {
                    form.field = if *forwards {
                        form.field.next()
                    } else {
                        form.field.prev()
                    };
                }
                PersonaMode::Profile(form) => {
                    form.focus = match form.focus {
                        ProfileFormFocus::Name => ProfileFormFocus::Entries,
                        ProfileFormFocus::Entries => ProfileFormFocus::Name,
                    };
                }
                PersonaMode::Bind(_) | PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormCycle(forwards) => {
            let attribute_count = state.main_page.content_panel.personas.attributes.len();
            let option_count = state.main_page.content_panel.personas.profiles.len() + 1;
            let p = &mut state.main_page.content_panel.personas;
            match &mut p.mode {
                PersonaMode::Attribute(form) => {
                    if form.field == AttributeField::ValueType {
                        let n = VALUE_TYPES.len();
                        form.value_type = if *forwards {
                            (form.value_type + 1) % n
                        } else {
                            (form.value_type + n - 1) % n
                        };
                    }
                }
                PersonaMode::Profile(form) => {
                    form.cursor = step(form.cursor, attribute_count, *forwards);
                }
                PersonaMode::Bind(picker) => {
                    picker.cursor = step(picker.cursor, option_count, *forwards);
                }
                PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormToggleEntry => {
            let attribute_id = {
                let p = &state.main_page.content_panel.personas;
                match &p.mode {
                    PersonaMode::Profile(form) => p
                        .attributes
                        .get(form.cursor)
                        .map(|a| a.attribute_id.clone()),
                    _ => None,
                }
            };
            let p = &mut state.main_page.content_panel.personas;
            if let (PersonaMode::Profile(form), Some(id)) = (&mut p.mode, attribute_id) {
                match form.ticked.iter().position(|x| *x == id) {
                    Some(i) => {
                        form.ticked.remove(i);
                    }
                    // Appended, so tick order is presentation order — the
                    // profile shows its claims in the order they were chosen.
                    None => form.ticked.push(id),
                }
            }
            PersonaEffect::None
        }
        PersonaAction::FormCancel => {
            state.main_page.content_panel.personas.mode = PersonaMode::View;
            PersonaEffect::None
        }
        PersonaAction::FormSubmit => form_submit(state),
    }
}

/// Answer the armed question.
///
/// Every arm acts on what the question named, not on where it sat: a listing
/// that arrived while the prompt was on screen cannot redirect the answer onto
/// a row the operator never selected.
fn confirm_yes(state: &mut State) -> PersonaEffect {
    let p = &mut state.main_page.content_panel.personas;
    let confirm = std::mem::replace(&mut p.confirm, PersonaConfirm::None);
    match confirm {
        // A face deletion is not answered here — the pane arms the question and
        // the existing identity-deletion path answers it. See the key handler.
        PersonaConfirm::None | PersonaConfirm::DeleteFace(_) => PersonaEffect::None,
        PersonaConfirm::DeleteAttribute {
            attribute_id,
            cascade,
            ..
        } => PersonaEffect::Job(PersonaJob::AttributeDelete {
            attribute_id,
            cascade,
        }),
        PersonaConfirm::DeleteProfile {
            profile_id, unbind, ..
        } => PersonaEffect::Job(PersonaJob::ProfileDelete { profile_id, unbind }),
        PersonaConfirm::Unbind {
            context_id,
            persona_did,
            community,
        } => PersonaEffect::Job(PersonaJob::Bind {
            context_id,
            persona_did,
            profile_id: None,
            community,
        }),
    }
}

/// Validate and submit whichever form is open.
fn form_submit(state: &mut State) -> PersonaEffect {
    let profiles: Vec<ProfileSummary> = state
        .main_page
        .content_panel
        .personas
        .profiles
        .iter()
        .cloned()
        .collect();
    let p = &mut state.main_page.content_panel.personas;

    match &mut p.mode {
        PersonaMode::View => PersonaEffect::None,
        PersonaMode::Attribute(form) => {
            let claim_type = form.claim_type.value().trim().to_string();
            if claim_type.is_empty() {
                // Named rather than generic: the type is the one field with no
                // sensible default, because it is what a verifier matches on.
                form.error = Some("A type is required — e.g. email.work.".to_string());
                return PersonaEffect::None;
            }
            let value_type = pool::value_type_from_str(VALUE_TYPES[form.value_type]);
            let value = match pool::parse_typed_value(form.value.value(), value_type) {
                Ok(value) => value,
                Err(why) => {
                    form.error = Some(why);
                    return PersonaEffect::None;
                }
            };
            let label = form.label.value().trim();
            form.error = None;
            form.working = true;
            PersonaEffect::Job(PersonaJob::AttributePut(AttributeDraft {
                attribute_id: form.attribute_id.clone(),
                expected_version: form.expected_version,
                claim_type,
                label: (!label.is_empty()).then(|| label.to_string()),
                value,
                value_type,
            }))
        }
        PersonaMode::Profile(form) => {
            let name = form.name.value().trim().to_string();
            if name.is_empty() {
                form.error = Some("A name is required — \"Work\", \"Gaming\".".to_string());
                return PersonaEffect::None;
            }
            form.error = None;
            form.working = true;
            PersonaEffect::Job(PersonaJob::ProfilePut {
                profile_id: form.profile_id.clone(),
                name,
                live_refs: form.ticked.clone(),
                other_entries: form.preserved.clone(),
                expected_version: form.expected_version,
            })
        }
        PersonaMode::Bind(picker) => {
            // Row 0 is "nothing"; the rest index the profile list.
            let profile_id = picker
                .cursor
                .checked_sub(1)
                .and_then(|i| profiles.get(i))
                .map(|profile| profile.profile_id.clone());
            picker.error = None;
            picker.working = true;
            PersonaEffect::Job(PersonaJob::Bind {
                context_id: picker.context_id.clone(),
                persona_did: picker.persona_did.clone(),
                profile_id,
                community: picker.community.clone(),
            })
        }
    }
}

/// Give an open form back to the operator after a request that never left.
///
/// A form marked `working` is waiting on an answer, and if the request was
/// never sent there is no answer coming: the form would stay locked, showing
/// "Saving…" over an edit nobody is saving, until the pane was closed. Both
/// callers are the paths where the loop declines to spawn — no admin session,
/// and the domain already busy.
pub(crate) fn release_form(state: &mut State, reason: String) {
    let p = &mut state.main_page.content_panel.personas;
    match &mut p.mode {
        PersonaMode::Attribute(form) => {
            form.working = false;
            form.error = Some(reason);
        }
        PersonaMode::Profile(form) => {
            form.working = false;
            form.error = Some(reason);
        }
        PersonaMode::Bind(picker) => {
            picker.working = false;
            picker.error = Some(reason);
        }
        PersonaMode::View => p.status_message = Some(reason),
    }
}

/// Prefill the editor from an existing attribute.
fn form_for(attr: &PoolAttribute) -> AttributeForm {
    AttributeForm {
        attribute_id: Some(attr.attribute_id.clone()),
        expected_version: Some(attr.version),
        claim_type: tui_input::Input::new(attr.claim_type.clone()),
        label: tui_input::Input::new(attr.label.clone().unwrap_or_default()),
        value_type: VALUE_TYPES
            .iter()
            .position(|t| *t == attr.value_type)
            .unwrap_or(0),
        value: tui_input::Input::new(match &attr.value {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        }),
        field: AttributeField::default(),
        error: None,
        working: false,
    }
}

/// Move a cursor one step, stopping at the ends rather than wrapping: a list
/// that jumps from bottom to top under a held arrow key loses the operator's
/// place.
fn step(cursor: usize, len: usize, forwards: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if forwards {
        (cursor + 1).min(len - 1)
    } else {
        cursor.saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// The jobs
// ---------------------------------------------------------------------------

/// How much of the disclosure history one read asks for.
///
/// The record is append-only and never trimmed, so "all of it" is a query that
/// gets slower for the life of the account. A page of the newest releases is
/// what the pane can show and what the holder opens it to see; the whole
/// history is a `pnm persona disclosure history` question.
pub(crate) const DISCLOSURE_PAGE: u64 = 100;

/// One backgrounded read of everything the agent-served tabs show.
pub(crate) struct PersonaReadJob {
    pub(crate) admin_vta: VtaClient,
    pub(crate) include_values: bool,
    pub(crate) targets: Vec<BindingTarget>,
}

impl PersonaReadJob {
    /// The targets a read should ask about: one per membership.
    pub(crate) fn targets(state: &State) -> Vec<BindingTarget> {
        state
            .main_page
            .content_panel
            .personas
            .memberships
            .iter()
            .filter(|m| !m.sub_context_id.is_empty() && !m.persona_did.is_empty())
            .map(|m| (m.sub_context_id.clone(), m.persona_did.clone()))
            .collect()
    }

    /// I/O only.
    pub(crate) async fn run(self) -> PersonaOutcome {
        let attributes = pool::list(&self.admin_vta, self.include_values)
            .await
            .map_err(|e| format!("{e}"));
        let profiles = profile::list(&self.admin_vta)
            .await
            .map_err(|e| format!("{e}"));
        let disclosures = match std::num::NonZeroU64::new(DISCLOSURE_PAGE) {
            Some(limit) => disclosure::history(&self.admin_vta, limit)
                .await
                .map_err(|e| format!("{e}")),
            None => Ok(Vec::new()),
        };
        let bindings = persona_binding_refresh::resolve_batch(self.admin_vta, self.targets).await;
        PersonaOutcome::Read {
            attributes,
            profiles,
            disclosures,
            bindings,
            include_values: self.include_values,
        }
    }
}

/// One backgrounded write (or single-profile read).
pub(crate) struct PersonaJobRun {
    pub(crate) admin_vta: VtaClient,
    pub(crate) job: PersonaJob,
}

impl PersonaJobRun {
    /// I/O only.
    pub(crate) async fn run(self) -> PersonaOutcome {
        let client = self.admin_vta;
        match self.job {
            PersonaJob::AttributePut(draft) => PersonaOutcome::Written {
                verb: "Saved attribute",
                error: pool::put(&client, draft)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::AttributeDelete {
                attribute_id,
                cascade,
            } => PersonaOutcome::Written {
                verb: "Deleted attribute",
                error: pool::delete(&client, &attribute_id, cascade)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::ProfilePut {
                profile_id,
                name,
                live_refs,
                other_entries,
                expected_version,
            } => PersonaOutcome::Written {
                verb: "Saved profile",
                error: profile::put(
                    &client,
                    profile_id.as_deref(),
                    &name,
                    &live_refs,
                    &other_entries,
                    expected_version,
                )
                .await
                .err()
                .map(|e| format!("{e}")),
            },
            PersonaJob::ProfileDelete { profile_id, unbind } => PersonaOutcome::Written {
                verb: "Deleted profile",
                error: profile::delete(&client, &profile_id, unbind)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::ProfileGet { profile_id, edit } => PersonaOutcome::ProfileRead {
                edit,
                result: profile::get(&client, &profile_id, !edit)
                    .await
                    .map_err(|e| format!("{e}")),
            },
            PersonaJob::Bind {
                context_id,
                persona_did,
                profile_id,
                community,
            } => PersonaOutcome::Bound {
                community,
                cleared: profile_id.is_none(),
                error: binding::set(&client, &context_id, &persona_did, profile_id.as_deref())
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The outcomes
// ---------------------------------------------------------------------------

/// What a persona job produced. Data only; applied on the loop thread.
pub(crate) enum PersonaOutcome {
    Read {
        attributes: Result<Vec<PoolAttribute>, String>,
        profiles: Result<Vec<ProfileSummary>, String>,
        disclosures: Result<Vec<disclosure::DisclosureRow>, String>,
        bindings: HashMap<BindingTarget, openvtc_core::persona::binding::BindingSummary>,
        include_values: bool,
    },
    Written {
        verb: &'static str,
        error: Option<String>,
    },
    ProfileRead {
        edit: bool,
        result: Result<ProfileDetail, String>,
    },
    Bound {
        community: String,
        cleared: bool,
        error: Option<String>,
    },
}

impl PersonaOutcome {
    /// Fold the result into the pane, on the loop thread.
    pub(crate) fn apply(self, state: &mut State) {
        let p = &mut state.main_page.content_panel.personas;
        p.loading = false;

        match self {
            PersonaOutcome::Read {
                attributes,
                profiles,
                disclosures,
                bindings,
                include_values,
            } => {
                // A listing for a filter the operator has since flipped is
                // dropped: they pressed `v` while it was in flight, so it
                // answers the old question and a fresh job is already queued.
                if include_values != p.show_values {
                    return;
                }
                // The first failure is the one shown, and it is shown *instead*
                // of an empty list — the whole reason `load_error` exists.
                p.load_error = attributes
                    .as_ref()
                    .err()
                    .or(profiles.as_ref().err())
                    .or(disclosures.as_ref().err())
                    .cloned();
                if let Ok(list) = attributes {
                    p.attribute_selected = p.attribute_selected.min(list.len().saturating_sub(1));
                    p.attributes = list.into();
                }
                if let Ok(list) = profiles {
                    p.profile_selected = p.profile_selected.min(list.len().saturating_sub(1));
                    p.profiles = list.into();
                }
                if let Ok(list) = disclosures {
                    p.disclosure_selected = p.disclosure_selected.min(list.len().saturating_sub(1));
                    p.disclosures = list.into();
                }
                // Merged, not replaced: a read only carries the targets it was
                // given, and replacing would blank every row it did not cover —
                // which reads on screen as those faces having stopped
                // presenting anything.
                p.bindings.extend(bindings);
                if p.load_error.is_none() {
                    p.loaded = true;
                }
            }

            PersonaOutcome::Written { verb, error } => {
                // The store is authoritative and has just been invalidated, so
                // ask for a re-read either way. A failed write is exactly when
                // a stale list misleads most: its state is now unknown.
                p.refresh_queued = true;
                match error {
                    None => {
                        p.mode = PersonaMode::View;
                        p.status_message = Some(format!("{verb}."));
                        state.main_page.log(format!("{verb}."));
                    }
                    Some(e) => {
                        // Into the form when one is open, so the holder keeps
                        // what they typed and can fix it.
                        match &mut p.mode {
                            PersonaMode::Attribute(form) => {
                                form.working = false;
                                form.error = Some(e.clone());
                            }
                            PersonaMode::Profile(form) => {
                                form.working = false;
                                form.error = Some(e.clone());
                            }
                            _ => p.status_message = Some(e.clone()),
                        }
                        state
                            .main_page
                            .log_error(format!("{verb} failed"), e.as_str());
                    }
                }
            }

            PersonaOutcome::ProfileRead { edit, result } => match result {
                Ok(detail) => {
                    if edit {
                        if detail.is_editable_here() {
                            p.mode = PersonaMode::Profile(ProfileForm {
                                profile_id: Some(detail.summary.profile_id.clone()),
                                expected_version: Some(detail.summary.version),
                                name: tui_input::Input::new(detail.summary.name.clone()),
                                ticked: detail.live_refs.clone(),
                                cursor: 0,
                                focus: ProfileFormFocus::Name,
                                preserved: detail.other_entries.clone(),
                                error: None,
                                working: false,
                            });
                        } else {
                            // Refused rather than opened: saving could not
                            // round-trip an entry this build cannot read, and a
                            // save that silently drops one is invisible.
                            p.status_message = Some(detail.refusal());
                        }
                    } else {
                        p.open_profile = Some(detail);
                    }
                }
                Err(e) => {
                    p.status_message = Some(e.clone());
                    state
                        .main_page
                        .log_error("Reading the profile failed", e.as_str());
                }
            },

            PersonaOutcome::Bound {
                community,
                cleared,
                error,
            } => {
                p.refresh_queued = true;
                match error {
                    None => {
                        p.mode = PersonaMode::View;
                        let msg = if cleared {
                            format!("{community} is now shown nothing.")
                        } else {
                            format!("Updated what {community} is shown.")
                        };
                        p.status_message = Some(msg.clone());
                        state.main_page.log(msg);
                    }
                    Some(e) => {
                        if let PersonaMode::Bind(picker) = &mut p.mode {
                            picker.working = false;
                            picker.error = Some(e.clone());
                        } else {
                            p.status_message = Some(e.clone());
                        }
                        state
                            .main_page
                            .log_error("Changing what a face presents failed", e.as_str());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{PersonaMembership, PersonasState};
    use openvtc_core::persona::binding::BindingSummary;
    use openvtc_core::persona::pool::ProvenanceKind;

    fn attribute(id: &str) -> PoolAttribute {
        PoolAttribute {
            attribute_id: id.to_string(),
            claim_type: "email.work".to_string(),
            value_type: "string".to_string(),
            version: 4,
            ..PoolAttribute::default()
        }
    }

    fn state_with(personas: PersonasState) -> State {
        let mut state = State::default();
        state.main_page.content_panel.personas = personas;
        state
    }

    fn personas(state: &State) -> &PersonasState {
        &state.main_page.content_panel.personas
    }

    /// Deleting an attribute a profile uses asks the cascading question *first*.
    ///
    /// The listing already says which attributes are referenced, so there is no
    /// reason to put a question the VTA is going to refuse and then put a
    /// different one — a holder who has already answered "yes, delete it"
    /// answers the follow-up with the first question's reasoning.
    #[test]
    fn a_referenced_attribute_arms_the_cascading_question_directly() {
        let mut state = state_with(PersonasState {
            attributes: vec![attribute("01A"), attribute("01B")].into(),
            profiles: vec![ProfileSummary {
                profile_id: "01P".into(),
                name: "Work".into(),
                referenced: vec!["01A".into()],
                ..ProfileSummary::default()
            }]
            .into(),
            ..PersonasState::default()
        });

        apply(&mut state, &PersonaAction::AttributeDeleteArm(0));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteAttribute {
                attribute_id: "01A".into(),
                name: "email.work".into(),
                cascade: true
            }
        );

        apply(&mut state, &PersonaAction::AttributeDeleteArm(1));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteAttribute {
                attribute_id: "01B".into(),
                name: "email.work".into(),
                cascade: false
            },
            "an unreferenced attribute needs no cascade"
        );
    }

    /// Same rule one layer up: deleting a profile a face presents asks the
    /// unbinding question, because that is what will actually happen.
    #[test]
    fn a_presented_profile_arms_the_unbinding_question() {
        let mut bindings = HashMap::new();
        bindings.insert(
            ("ctx".to_string(), "did:webvh:example.com:alice".to_string()),
            BindingSummary {
                bound: true,
                profile_id: Some("01P".into()),
                ..BindingSummary::default()
            },
        );
        let mut state = state_with(PersonasState {
            profiles: vec![
                ProfileSummary {
                    profile_id: "01P".into(),
                    ..ProfileSummary::default()
                },
                ProfileSummary {
                    profile_id: "01Q".into(),
                    ..ProfileSummary::default()
                },
            ]
            .into(),
            bindings,
            ..PersonasState::default()
        });

        apply(&mut state, &PersonaAction::ProfileDeleteArm(0));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteProfile {
                profile_id: "01P".into(),
                name: "(unnamed profile)".into(),
                unbind: true
            }
        );
        apply(&mut state, &PersonaAction::ProfileDeleteArm(1));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteProfile {
                profile_id: "01Q".into(),
                name: "(unnamed profile)".into(),
                unbind: false
            }
        );
    }

    /// A listing that lands while a question is on screen cannot redirect the
    /// answer.
    ///
    /// The prompt is armed against the attribute the operator selected, and a
    /// refresh (or another surface's write) can reorder the pool underneath it
    /// before they press `y`. An index into the old listing would then name a
    /// different attribute in the new one — deleting something they never
    /// selected while showing them the name of something else.
    #[test]
    fn an_armed_delete_survives_the_list_moving_underneath_it() {
        let mut state = state_with(PersonasState {
            attributes: vec![attribute("01A"), attribute("01B")].into(),
            ..PersonasState::default()
        });

        apply(&mut state, &PersonaAction::AttributeDeleteArm(0));

        // A read lands, and the pool comes back in a different order.
        PersonaOutcome::Read {
            attributes: Ok(vec![attribute("01B"), attribute("01A")]),
            profiles: Ok(Vec::new()),
            disclosures: Ok(Vec::new()),
            bindings: HashMap::new(),
            include_values: false,
        }
        .apply(&mut state);

        match apply(&mut state, &PersonaAction::ConfirmYes) {
            PersonaEffect::Job(PersonaJob::AttributeDelete { attribute_id, .. }) => {
                assert_eq!(
                    attribute_id, "01A",
                    "the armed attribute is the one deleted"
                )
            }
            _ => panic!("expected a delete"),
        }
    }

    /// A credential-backed attribute does not open an editor. The refusal is
    /// the point: retyping its value would manufacture an attested claim out of
    /// a typed string.
    #[test]
    fn a_credential_backed_attribute_refuses_the_editor() {
        let mut attr = attribute("01A");
        attr.provenance = ProvenanceKind::CredentialBacked;
        let mut state = state_with(PersonasState {
            attributes: vec![attr].into(),
            show_values: true,
            ..PersonasState::default()
        });

        apply(&mut state, &PersonaAction::AttributeEdit(0));

        assert!(matches!(personas(&state).mode, PersonaMode::View));
        assert!(
            personas(&state)
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("comes from a credential")),
            "the refusal has to say why"
        );
    }

    /// Opening the editor when the listing was fetched without values re-reads
    /// with them. Without this the form would open empty and save a blank over
    /// a value the holder never saw.
    #[test]
    fn editing_without_values_in_hand_asks_for_them() {
        let mut state = state_with(PersonasState {
            attributes: vec![attribute("01A")].into(),
            show_values: false,
            ..PersonasState::default()
        });

        let effect = apply(&mut state, &PersonaAction::AttributeEdit(0));

        assert!(matches!(effect, PersonaEffect::Read));
        assert!(personas(&state).show_values);
        assert!(matches!(personas(&state).mode, PersonaMode::Attribute(_)));
    }

    /// Toggling values is a re-read, not a redraw — a listing fetched without
    /// values does not hold them.
    #[test]
    fn toggling_values_re_reads() {
        let mut state = State::default();
        let effect = apply(&mut state, &PersonaAction::ToggleValues);
        assert!(matches!(effect, PersonaEffect::Read));
        assert!(personas(&state).show_values);
    }

    /// A read that answers a question the operator has already changed is
    /// dropped rather than flashed — the same rule the VIC listing follows.
    #[test]
    fn a_superseded_read_is_discarded() {
        let mut state = state_with(PersonasState {
            attributes: vec![attribute("01A")].into(),
            show_values: true,
            ..PersonasState::default()
        });

        PersonaOutcome::Read {
            attributes: Ok(vec![attribute("01B"), attribute("01C")]),
            profiles: Ok(Vec::new()),
            disclosures: Ok(Vec::new()),
            bindings: HashMap::new(),
            include_values: false,
        }
        .apply(&mut state);

        assert_eq!(
            personas(&state).attributes.len(),
            1,
            "the superseded listing must not apply"
        );
    }

    /// A failed read keeps the previous list and records why — it must never
    /// leave the pane claiming the holder has no attributes.
    #[test]
    fn a_failed_read_keeps_the_list_and_says_why() {
        let mut state = state_with(PersonasState {
            attributes: vec![attribute("01A")].into(),
            loaded: true,
            ..PersonasState::default()
        });

        PersonaOutcome::Read {
            attributes: Err("connection refused".to_string()),
            profiles: Ok(Vec::new()),
            disclosures: Ok(Vec::new()),
            bindings: HashMap::new(),
            include_values: false,
        }
        .apply(&mut state);

        assert_eq!(personas(&state).attributes.len(), 1);
        assert_eq!(
            personas(&state).load_error.as_deref(),
            Some("connection refused")
        );
    }

    /// A write asks for a re-read whether it succeeded or failed. After a
    /// failure the store's state is unknown, which is when a stale list is most
    /// misleading.
    #[test]
    fn every_write_asks_for_a_re_read() {
        for error in [None, Some("refused".to_string())] {
            let mut state = State::default();
            PersonaOutcome::Written {
                verb: "Saved attribute",
                error,
            }
            .apply(&mut state);
            assert!(personas(&state).refresh_queued);
        }
    }

    /// A request the loop declines to send hands the form back.
    ///
    /// The form is marked `working` the moment it is submitted, and that flag
    /// is what locks the keyboard. If the loop then declines to spawn — no
    /// admin session, or the domain already busy — nothing is coming back to
    /// clear it, and the form sits on "Saving…" over an edit nobody is saving.
    #[test]
    fn a_request_that_never_left_unlocks_the_form() {
        let mut state = state_with(PersonasState {
            mode: PersonaMode::Attribute(AttributeForm {
                working: true,
                ..AttributeForm::default()
            }),
            ..PersonasState::default()
        });

        release_form(&mut state, "no session".to_string());

        match &personas(&state).mode {
            PersonaMode::Attribute(form) => {
                assert!(!form.working);
                assert_eq!(form.error.as_deref(), Some("no session"));
            }
            _ => panic!("the form must stay open"),
        }
    }

    /// The picker is the same: it locks itself on submit and has to be given
    /// back if the write never went.
    #[test]
    fn a_request_that_never_left_unlocks_the_picker() {
        let mut state = state_with(PersonasState {
            mode: PersonaMode::Bind(BindPicker {
                working: true,
                ..BindPicker::default()
            }),
            ..PersonasState::default()
        });

        release_form(&mut state, "busy".to_string());

        match &personas(&state).mode {
            PersonaMode::Bind(picker) => {
                assert!(!picker.working);
                assert_eq!(picker.error.as_deref(), Some("busy"));
            }
            _ => panic!("the picker must stay open"),
        }
    }

    /// A failed save keeps the form open with the reason on it, so the holder
    /// does not lose what they typed.
    #[test]
    fn a_failed_save_keeps_the_form_and_its_contents() {
        let mut state = state_with(PersonasState {
            mode: PersonaMode::Attribute(AttributeForm {
                claim_type: tui_input::Input::new("email.work".into()),
                working: true,
                ..AttributeForm::default()
            }),
            ..PersonasState::default()
        });

        PersonaOutcome::Written {
            verb: "Saved attribute",
            error: Some("version conflict".to_string()),
        }
        .apply(&mut state);

        match &personas(&state).mode {
            PersonaMode::Attribute(form) => {
                assert_eq!(form.claim_type.value(), "email.work");
                assert!(!form.working, "the form has to become editable again");
                assert_eq!(form.error.as_deref(), Some("version conflict"));
            }
            _ => panic!("the form must stay open"),
        }
    }

    /// An empty type is refused before the round-trip, because it is the one
    /// field with no sensible default: it is what a verifier matches on.
    #[test]
    fn a_typeless_attribute_is_refused_locally() {
        let mut state = state_with(PersonasState {
            mode: PersonaMode::Attribute(AttributeForm::default()),
            ..PersonasState::default()
        });

        let effect = apply(&mut state, &PersonaAction::FormSubmit);

        assert!(matches!(effect, PersonaEffect::None));
        match &personas(&state).mode {
            PersonaMode::Attribute(form) => {
                assert!(form.error.as_deref().is_some_and(|e| e.contains("type")));
                assert!(!form.working, "nothing was sent, so nothing is in flight");
            }
            _ => panic!("the form must stay open"),
        }
    }

    /// The picker opens on what is bound now, so pressing ⏎ without moving
    /// leaves the binding alone instead of silently clearing it.
    #[test]
    fn the_picker_opens_on_the_current_binding() {
        let membership = PersonaMembership {
            community_name: "Acme".into(),
            sub_context_id: "ctx".into(),
            persona_did: "did:webvh:example.com:alice".into(),
            ..PersonaMembership::default()
        };
        let mut bindings = HashMap::new();
        bindings.insert(
            ("ctx".to_string(), membership.persona_did.clone()),
            BindingSummary {
                bound: true,
                profile_id: Some("01Q".into()),
                ..BindingSummary::default()
            },
        );
        let mut state = state_with(PersonasState {
            memberships: vec![membership].into(),
            profiles: vec![
                ProfileSummary {
                    profile_id: "01P".into(),
                    ..ProfileSummary::default()
                },
                ProfileSummary {
                    profile_id: "01Q".into(),
                    ..ProfileSummary::default()
                },
            ]
            .into(),
            bindings,
            ..PersonasState::default()
        });

        apply(&mut state, &PersonaAction::BindOpen(0));

        match &personas(&state).mode {
            // Row 0 is "nothing", so the second profile is row 2.
            PersonaMode::Bind(picker) => {
                assert_eq!(picker.cursor, 2);
                // Named, not indexed: the membership list is rebuilt from
                // `Config` on every sync, and an inbound message is enough to
                // reorder it while the picker is open. An index would then send
                // the holder's identity to a community they were not looking at.
                assert_eq!(picker.context_id, "ctx");
                assert_eq!(picker.persona_did, "did:webvh:example.com:alice");
            }
            _ => panic!("the picker must be open"),
        }
    }

    /// An unbound face opens the picker on "nothing", which is where it
    /// already is.
    #[test]
    fn an_unbound_face_opens_the_picker_on_nothing() {
        let mut state = state_with(PersonasState {
            memberships: vec![PersonaMembership::default()].into(),
            ..PersonasState::default()
        });
        apply(&mut state, &PersonaAction::BindOpen(0));
        match &personas(&state).mode {
            PersonaMode::Bind(picker) => assert_eq!(picker.cursor, 0),
            _ => panic!("the picker must be open"),
        }
    }

    /// Ticking appends, so the order the holder chose is the order the profile
    /// presents.
    #[test]
    fn ticking_preserves_the_order_entries_were_chosen_in() {
        let mut state = state_with(PersonasState {
            attributes: vec![attribute("01A"), attribute("01B"), attribute("01C")].into(),
            mode: PersonaMode::Profile(ProfileForm {
                focus: ProfileFormFocus::Entries,
                ..ProfileForm::default()
            }),
            ..PersonasState::default()
        });

        apply(&mut state, &PersonaAction::FormCycle(true)); // → 01B
        apply(&mut state, &PersonaAction::FormToggleEntry);
        apply(&mut state, &PersonaAction::FormCycle(false)); // → 01A
        apply(&mut state, &PersonaAction::FormToggleEntry);

        match &personas(&state).mode {
            PersonaMode::Profile(form) => {
                assert_eq!(form.ticked, vec!["01B".to_string(), "01A".to_string()])
            }
            _ => panic!("the form must be open"),
        }

        // And ticking again removes it.
        apply(&mut state, &PersonaAction::FormToggleEntry);
        match &personas(&state).mode {
            PersonaMode::Profile(form) => assert_eq!(form.ticked, vec!["01B".to_string()]),
            _ => panic!("the form must be open"),
        }
    }

    /// Editing a profile this build cannot fully read is refused rather than
    /// opened. A save from that form could not round-trip the entry it could
    /// not parse, and dropping it would be invisible.
    #[test]
    fn a_profile_with_unreadable_entries_refuses_the_editor() {
        let mut state = State::default();
        PersonaOutcome::ProfileRead {
            edit: true,
            result: Ok(ProfileDetail {
                unreadable_entries: 1,
                ..ProfileDetail::default()
            }),
        }
        .apply(&mut state);

        assert!(matches!(personas(&state).mode, PersonaMode::View));
        assert!(
            personas(&state)
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("cannot read"))
        );
    }

    /// Moving tabs drops what was armed or opened on the one being left: a `y`
    /// belongs to the screen that asked the question.
    #[test]
    fn changing_tab_disarms_the_confirmation() {
        let mut state = state_with(PersonasState {
            tab: PersonaTab::Attributes,
            confirm: PersonaConfirm::DeleteAttribute {
                attribute_id: "01A".into(),
                name: "email.work".into(),
                cascade: false,
            },
            ..PersonasState::default()
        });

        apply(&mut state, &PersonaAction::TabNext);

        assert_eq!(personas(&state).tab, PersonaTab::Profiles);
        assert_eq!(personas(&state).confirm, PersonaConfirm::None);
    }

    /// The agent-served tabs read on first arrival and not again — the pane is
    /// not a poller.
    #[test]
    fn an_agent_tab_reads_once_on_arrival() {
        let mut state = State::default();
        // Faces → Attributes: needs the agent, nothing loaded yet.
        assert!(matches!(
            apply(&mut state, &PersonaAction::TabNext),
            PersonaEffect::Read
        ));

        state.main_page.content_panel.personas.loaded = true;
        assert!(matches!(
            apply(&mut state, &PersonaAction::TabNext),
            PersonaEffect::None
        ));
    }
}
