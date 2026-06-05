//! The State-B "join a community" flow UI (R-A-5 Stage 4).
//!
//! A small two-page [`Component`] mirroring [`SetupFlow`](super::setup_flow):
//! `VtcEnterDid` collects the community DID, then `JoinProgress` shows the
//! automated mint + join sequence. The page selection is driven by
//! [`JoinState.page`](crate::state_handler::join::JoinState::page); the VTC DID
//! `Input` lives on this component (mirroring how `vta_enter_did` holds its
//! input), and persists across re-renders via `move_with_state`.

use crate::{
    state_handler::{
        actions::Action,
        join::{JoinPage, JoinState},
        state::State,
    },
    ui::{
        component::{Component, ComponentRender},
        pages::join_flow::{join_progress::JoinProgress, vtc_enter_did::VtcEnterDid},
    },
};
use crossterm::event::{KeyEvent, KeyEventKind};
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;
use tui_input::Input;

pub mod join_progress;
pub mod vtc_enter_did;

/// Handles the join flow sequence.
#[derive(Clone)]
pub struct JoinFlow {
    /// Action sender.
    pub action_tx: UnboundedSender<Action>,

    /// The community (VTC) DID input (page 1). Held on the component so it
    /// survives re-renders without round-tripping through the watch channel.
    pub vtc_did: Input,

    // Page handlers (zero-sized — they read from `props.state`).
    pub vtc_enter_did: VtcEnterDid,
    pub join_progress: JoinProgress,

    /// State-mapped join props.
    pub props: Props,
}

#[derive(Clone)]
pub struct Props {
    pub state: JoinState,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            state: state.join.clone(),
        }
    }
}

impl Component for JoinFlow {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        JoinFlow {
            action_tx,
            vtc_did: Input::default(),
            vtc_enter_did: VtcEnterDid,
            join_progress: JoinProgress,
            props: Props::from(state),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        JoinFlow {
            props: Props::from(state),
            ..self
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        match self.props.state.page {
            JoinPage::EnterDid => VtcEnterDid::handle_key_event(self, key),
            JoinPage::Progress => JoinProgress::handle_key_event(self, key),
        }
    }

    fn handle_paste_event(&mut self, text: &str) {
        // Paste the whole DID at once (instant for long did:webvh strings).
        if self.props.state.page == JoinPage::EnterDid && !self.props.state.processing {
            self.vtc_did = Input::new(text.trim().to_string());
        }
    }
}

impl ComponentRender<()> for JoinFlow {
    fn render(&self, frame: &mut Frame, _props: ()) {
        match self.props.state.page {
            JoinPage::EnterDid => {
                self.vtc_enter_did
                    .render(&self.props.state, &self.vtc_did, frame)
            }
            JoinPage::Progress => self.join_progress.render(&self.props.state, frame),
        }
    }
}
