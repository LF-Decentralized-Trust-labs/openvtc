//! State-B "join a community" flow state (R-A-5 Stage 4).
//!
//! Holds the transient UI/progress state for the two-page join flow:
//! `VtcEnterDid` (the operator pastes the community VTC DID) and `JoinProgress`
//! (a live log of the automated persona-mint → sub-context → join-submit
//! sequence). Persona-mint working fields are reused from
//! [`SetupState`](crate::state_handler::setup_sequence::SetupState) on
//! `State.setup`; this struct only tracks the join-specific surface.

use openvtc_core::config::account::{CommunityRecord, PersonaId};
use serde_json::Value;

use crate::state_handler::setup_sequence::{Completion, MessageType};

/// Which page of the join flow is currently active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JoinPage {
    /// Operator enters the community (VTC) DID.
    #[default]
    EnterDid,
    /// Choose whether to present an available invitation (VIC) for this
    /// community, or join as an open request. Shown only when a VIC is actually
    /// available (loaded-and-matching or held in the vault); skipped otherwise.
    InvitationChoice,
    /// Choose the identity to present (R-B-3 / D1): reuse an existing persona or
    /// mint a fresh one. Skipped when the account has no personas yet.
    IdentityChoice,
    /// Automated mint + join sequence progress / result.
    Progress,
}

/// Summary of the invitation credential (VIC) actually presented with a join,
/// shown on the success page so the operator can tell *whether* and *which*
/// invitation was used (vs. an open request awaiting manual approval). `None` on
/// the join state means no VIC was presented.
#[derive(Clone, Debug)]
pub struct PresentedInvitation {
    /// The VIC's top-level `id` (its consumption / linkage handle).
    pub id: String,
    /// The persona DID the VIC is bound to (`credentialSubject.id`), if present.
    pub subject: Option<String>,
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
    /// Count of valid invitations (VICs) for the community being joined that are
    /// bound to this persona — shown as a badge so the operator can pick the
    /// identity that holds a usable invitation.
    pub valid_vic_count: usize,
}

/// A valid invitation (VIC) available to present for the community being joined,
/// with the fields shown on the invitation-choice step and the body to present.
#[derive(Clone, Debug)]
pub struct AvailableVic {
    /// The VIC's top-level `id`.
    pub id: String,
    /// The persona DID it is bound to (`credentialSubject.id`), if present —
    /// used to group invitations under each persona.
    pub subject: Option<String>,
    /// Validity-window start (`validFrom`, RFC 3339), shown as "Issued".
    pub valid_from: String,
    /// Validity-window end (`validUntil`, RFC 3339), shown as "Expires".
    pub valid_until: String,
    /// The signed VIC body, presented verbatim when this one is chosen.
    pub body: Value,
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
    /// The invitation actually presented to the community, resolved at submit
    /// time (community-matched + unexpired). `Some` drives the success page's
    /// "Invitation: Presented" detail; `None` reads as an open request. Distinct
    /// from [`has_invitation`](Self::has_invitation), which reflects what was
    /// *loaded* on the entry page before community matching.
    pub presented_invitation: Option<PresentedInvitation>,
    /// True when the operator explicitly cleared a loaded VIC on the entry page,
    /// so the status text reads "joining without an invitation" rather than the
    /// generic "no VIC" tip. Distinguishes a deliberate clear from never having
    /// had one; re-pasting a VIC (`JoinPasteVic`) flips it back to `false`.
    pub vic_cleared: bool,
    /// All valid invitations (VICs) for the community being joined, across
    /// personas — collected once after the VTC DID is entered and used to badge
    /// each persona with its count on the identity step.
    pub available_vics: Vec<AvailableVic>,
    /// The chosen persona's invitations, listed on the
    /// [`InvitationChoice`](JoinPage::InvitationChoice) page (a subset of
    /// [`available_vics`](Self::available_vics) bound to that persona).
    pub invitation_options: Vec<AvailableVic>,
    /// Which persona the invitation step is choosing for — the reuse target the
    /// join launches with once the invitation choice is made.
    pub invitation_for_persona: Option<PersonaId>,
    /// Highlighted row on the invitation-choice page: `0..invitation_options.len()`
    /// selects a specific invitation to present; `invitation_options.len()` is the
    /// trailing "join without it" row.
    pub invitation_use_selected: usize,
    /// The committed invitation decision, read by the join sequence. `true`
    /// presents the chosen VIC (set into `State.invitation_credential`); `false`
    /// submits an open request. Set when the invitation choice is made, or
    /// directly (false) on paths with no available invitation.
    pub present_invitation: bool,
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
            valid_vic_count: 0,
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
