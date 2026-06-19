//! State-B "join a community" flow state (R-A-5 Stage 4).
//!
//! Holds the transient UI/progress state for the two-page join flow:
//! `VtcEnterDid` (the operator pastes the community VTC DID) and `JoinProgress`
//! (a live log of the automated persona-mint → sub-context → join-submit
//! sequence). Persona-mint working fields are reused from
//! [`SetupState`](crate::state_handler::setup_sequence::SetupState) on
//! `State.setup`; this struct only tracks the join-specific surface.

use openvtc_core::config::account::{CommunityRecord, PersonaId};

use crate::state_handler::setup_sequence::{Completion, MessageType};

/// Which page of the join flow is currently active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JoinPage {
    /// Operator enters the community (VTC) DID.
    #[default]
    EnterDid,
    /// Choose the identity to present (R-B-3 / D1): reuse an existing persona or
    /// mint a fresh one. Skipped when the account has no personas yet.
    IdentityChoice,
    /// Automated mint + join sequence progress / result.
    Progress,
}

/// One selectable existing persona on the identity-choice page (R-B-3).
#[derive(Clone, Debug)]
pub struct PersonaOption {
    /// Stable persona id, the reuse target.
    pub id: PersonaId,
    /// Human label (the persona's label, or a shortened DID).
    pub label: String,
    /// The persona's `did:webvh` (shown as detail).
    pub did: String,
    /// Display names of communities this persona is *already* presented to —
    /// drives the cross-community linkage warning (D1).
    pub linked_communities: Vec<String>,
}

/// Transient state for the join flow.
#[derive(Clone, Debug, Default)]
pub struct JoinState {
    /// Active page within the join flow.
    pub page: JoinPage,
    /// Display name resolved from the VTC DID document (best-effort).
    pub display_name: Option<String>,
    /// The VTC DID awaiting an identity choice (set on `EnterDid` submit, read
    /// when the chosen identity launches the sequence).
    pub pending_vtc: Option<String>,
    /// Existing personas offered for reuse on the identity-choice page (R-B-3).
    pub persona_options: Vec<PersonaOption>,
    /// Highlighted row on the identity-choice page. `0..persona_options.len()`
    /// indexes a reuse option; `persona_options.len()` is the "mint new" row.
    pub identity_selected: usize,
    /// When `Some(id)`, the cross-community linkage warning for reusing that
    /// persona is shown and awaiting `y`/`n` confirmation (D1).
    pub reuse_confirm: Option<PersonaId>,
    /// True while the background mint+join sequence is running. Locks input.
    pub processing: bool,
    /// Progress / error log shown on the `JoinProgress` page.
    pub messages: Vec<MessageType>,
    /// Overall outcome of the sequence.
    pub completed: Completion,
    /// The pending community record created on success (for the success page).
    pub created_community: Option<CommunityRecord>,
    /// The DID of the persona presented for this community, shown on the success
    /// page alongside the community DID.
    pub created_persona_did: Option<String>,
    /// Whether an invitation credential (VIC) was supplied at launch and will be
    /// presented with this join. Mirrored from the top-level
    /// [`State`](crate::state_handler::state::State) when the flow opens (it
    /// survives `reset`, which is called once at open) so the entry page can show
    /// the operator that their invitation will be used.
    pub has_invitation: bool,
    /// True when the operator explicitly cleared a loaded VIC on the entry page,
    /// so the status text reads "joining without an invitation" rather than the
    /// generic "no VIC" tip. Distinguishes a deliberate clear from never having
    /// had one; re-pasting a VIC (`JoinPasteVic`) flips it back to `false`.
    pub vic_cleared: bool,
}

impl JoinState {
    /// Reset to a fresh `EnterDid` page (called when the flow opens).
    pub fn reset(&mut self) {
        *self = JoinState::default();
    }

    /// The index of the "mint a new identity" row (one past the reuse options).
    pub fn mint_row(&self) -> usize {
        self.persona_options.len()
    }

    /// Whether the highlighted identity-choice row is the "mint new" row.
    pub fn mint_row_selected(&self) -> bool {
        self.identity_selected >= self.persona_options.len()
    }

    /// Append an info message to the progress log.
    pub fn info(&mut self, msg: impl Into<String>) {
        self.messages.push(MessageType::Info(msg.into()));
    }

    /// Append an error message and mark the sequence failed.
    pub fn fail(&mut self, msg: impl Into<String>) {
        self.messages.push(MessageType::Error(msg.into()));
        self.completed = Completion::CompletedFail;
        self.processing = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt() -> PersonaOption {
        PersonaOption {
            id: PersonaId::new(),
            label: "p".to_string(),
            did: "did:webvh:x".to_string(),
            linked_communities: Vec::new(),
        }
    }

    #[test]
    fn vic_cleared_defaults_false_and_resets() {
        let mut js = JoinState::default();
        assert!(!js.vic_cleared);
        js.vic_cleared = true;
        js.has_invitation = true;
        js.reset();
        assert!(!js.vic_cleared);
        assert!(!js.has_invitation);
    }

    #[test]
    fn mint_row_sits_past_the_reuse_options() {
        let mut js = JoinState::default();
        // No personas: the only row is "mint", at index 0.
        assert_eq!(js.mint_row(), 0);
        assert!(js.mint_row_selected());

        js.persona_options = vec![opt(), opt()];
        assert_eq!(js.mint_row(), 2);
        js.identity_selected = 0;
        assert!(!js.mint_row_selected());
        js.identity_selected = 1;
        assert!(!js.mint_row_selected());
        js.identity_selected = 2;
        assert!(js.mint_row_selected());
    }
}
