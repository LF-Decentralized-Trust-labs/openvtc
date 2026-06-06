//! State-B "join a community" flow state (R-A-5 Stage 4).
//!
//! Holds the transient UI/progress state for the two-page join flow:
//! `VtcEnterDid` (the operator pastes the community VTC DID) and `JoinProgress`
//! (a live log of the automated persona-mint → sub-context → join-submit
//! sequence). Persona-mint working fields are reused from
//! [`SetupState`](crate::state_handler::setup_sequence::SetupState) on
//! `State.setup`; this struct only tracks the join-specific surface.

use openvtc_core::config::account::CommunityRecord;

use crate::state_handler::setup_sequence::{Completion, MessageType};

/// Which page of the join flow is currently active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JoinPage {
    /// Operator enters the community (VTC) DID.
    #[default]
    EnterDid,
    /// Automated mint + join sequence progress / result.
    Progress,
}

/// Transient state for the join flow.
#[derive(Clone, Debug, Default)]
pub struct JoinState {
    /// Active page within the join flow.
    pub page: JoinPage,
    /// Display name resolved from the VTC DID document (best-effort).
    pub display_name: Option<String>,
    /// True while the background mint+join sequence is running. Locks input.
    pub processing: bool,
    /// Progress / error log shown on the `JoinProgress` page.
    pub messages: Vec<MessageType>,
    /// Overall outcome of the sequence.
    pub completed: Completion,
    /// The pending community record created on success (for the success page).
    pub created_community: Option<CommunityRecord>,
    /// The DID of the persona minted for this community, shown on the success
    /// page alongside the community DID.
    pub created_persona_did: Option<String>,
}

impl JoinState {
    /// Reset to a fresh `EnterDid` page (called when the flow opens).
    pub fn reset(&mut self) {
        *self = JoinState::default();
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
