#[cfg(feature = "openpgp-card")]
use std::sync::Arc;

#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;

use crate::state_handler::{join::JoinState, main_page::MainPageState, setup_sequence::SetupState};

/// State holds the state of the application
#[derive(Default, Debug, Clone)]
pub struct State {
    pub active_page: ActivePage,
    pub main_page: MainPageState,
    pub setup: SetupState,
    /// State-B "join a community" flow (R-A-5 Stage 4).
    pub join: JoinState,
    pub connection: ConnectionState,

    /// The community the main page is currently scoped to (D10 / R-C-6/7) — the
    /// "working context". The community-scoped panels (inbox / relationships /
    /// VRCs) and outbound actions resolve through this rather than through a
    /// single global persona. `None` means no active community (State-A, or every
    /// membership inactive); the main page shows its "no active community" state.
    ///
    /// Runtime-only (not persisted): re-defaulted from the account on each launch
    /// via [`State::reconcile_selected_community`].
    ///
    /// A *membership* reference — the community DID plus the presented persona —
    /// since a community may hold more than one membership (one per persona). The
    /// persona half is the working persona that scopes the panels.
    pub selected_community: Option<(
        openvtc_core::config::account::VtcDid,
        openvtc_core::config::account::PersonaId,
    )>,

    /// Rotating-tip index for the startup loading screen, advanced as startup
    /// steps stream so the tip changes during the load/connect.
    pub tip_index: usize,

    /// Hierarchical, timed startup tasks shown on the loading screen, in order.
    /// Each major task carries its own sub-steps; a step is marked Done (with
    /// its duration) when the next step begins, and a major is stamped with its
    /// combined wall-clock span when the next major begins, so the user sees
    /// exactly which task — and which sub-step — is slow.
    pub loading: Vec<LoadingTask>,

    /// True once phase 1 (config + VTA) has finished successfully. The loading
    /// screen then offers "Press Enter to continue" while phase-2 community
    /// connections already run in the background; pressing Enter reveals the
    /// main page.
    pub loading_complete: bool,

    /// Hardware Token Admin Pin (Arc-wrapped so clones share one allocation)
    #[cfg(feature = "openpgp-card")]
    pub token_admin_pin: Option<Arc<SecretString>>,

    /// True when the user needs to physically touch their hardware token.
    /// Not gated behind the openpgp-card feature so the StateHandler's
    /// select loop can update it unconditionally regardless of build config.
    pub token_touch_pending: bool,

    /// A Verifiable Invitation Credential (VIC) the operator supplied at launch
    /// via `--invitation <file>`, to be presented when joining a community. The
    /// VTC verifies it and auto-admits on a valid, trusted, unconsumed invite.
    /// Runtime-only (never persisted); injected by `main` into the
    /// [`StateHandler`](crate::state_handler::StateHandler)'s initial state.
    pub invitation_credential: Option<serde_json::Value>,
}

impl State {
    /// Keep [`State::selected_community`] valid against the current account
    /// (D10): drop a selection that is no longer an Active membership (e.g. it
    /// was left, rejected, or deleted), then default to the deterministic
    /// working community when none is selected. Idempotent; called whenever the
    /// account may have changed so the working context never dangles.
    pub fn reconcile_selected_community(
        &mut self,
        account: &openvtc_core::config::account::Account,
    ) {
        if let Some((vtc, persona)) = &self.selected_community
            && !account
                .membership(vtc, *persona)
                .is_some_and(|c| c.status.is_active())
        {
            self.selected_community = None;
        }
        if self.selected_community.is_none() {
            self.selected_community = account.default_working_membership();
        }
    }
}

/// Lifecycle state of a single loading task or sub-step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StepStatus {
    /// Known ahead of time but not started yet.
    #[default]
    Queued,
    /// Currently in progress.
    Running,
    /// Finished successfully.
    Done,
    /// The startup failed while this step was running.
    Failed,
}

/// A major startup task with its own timed sub-steps. The major's `duration` is
/// the combined wall-clock span (start of first child → end of last), stamped
/// when the next major begins; each child carries its own time.
#[derive(Clone, Debug)]
pub struct LoadingTask {
    /// The major task name (e.g. "Identity").
    pub label: String,
    /// Lifecycle state of the major as a whole.
    pub status: StepStatus,
    /// Wall-clock time the major's first sub-step started, `HH:MM:SS`.
    pub started: Option<String>,
    /// Combined duration once the major is Done. `None` while running/queued.
    pub duration: Option<std::time::Duration>,
    /// Ordered sub-steps under this major.
    pub children: Vec<LoadingStep>,
}

/// One timed sub-step of a [`LoadingTask`], shown on the loading screen.
#[derive(Clone, Debug)]
pub struct LoadingStep {
    /// What the step is doing (the progress message).
    pub label: String,
    /// Lifecycle state of this sub-step.
    pub status: StepStatus,
    /// Wall-clock time the step started, `HH:MM:SS`. `None` while queued.
    pub started: Option<String>,
    /// How long the step took, once completed. `None` while queued/running.
    pub duration: Option<std::time::Duration>,
}

/// Drives the hierarchical loading model from streamed `(major, sub)` progress
/// events. Held by the StateHandler loop alongside `State.loading`; tracks the
/// `Instant` each running step/major started so durations can be stamped
/// without storing `Instant`s in the (Clone, serialisable-ish) state.
#[derive(Default)]
pub struct LoadingProgress {
    /// When the currently-running sub-step began.
    step_start: Option<std::time::Instant>,
    /// When the currently-running major began (its first sub-step's start).
    major_start: Option<std::time::Instant>,
}

impl LoadingProgress {
    /// Record that sub-step `sub` of major task `major` is now starting.
    ///
    /// Finalises the previously-running sub-step (and, when the major changes,
    /// the previous major) with their durations, then appends/opens the new
    /// major/sub as `Running`. Returns the index of the tip the loading screen
    /// should advance to (the caller bumps `tip_index`).
    pub fn begin(&mut self, loading: &mut Vec<LoadingTask>, major: &str, sub: &str) {
        let now = std::time::Instant::now();
        let clock = chrono::Local::now().format("%H:%M:%S").to_string();

        // Finalise the previous running sub-step.
        if let Some(start) = self.step_start
            && let Some(prev) = loading
                .last_mut()
                .and_then(|m| m.children.last_mut())
                .filter(|s| s.status == StepStatus::Running)
        {
            prev.status = StepStatus::Done;
            prev.duration = Some(now.duration_since(start));
        }

        let same_major = loading.last().is_some_and(|m| m.label == major);
        if !same_major {
            // Close out the previous major with its combined span.
            if let Some(mstart) = self.major_start
                && let Some(prev) = loading.last_mut()
            {
                prev.status = StepStatus::Done;
                prev.duration = Some(now.duration_since(mstart));
            }
            loading.push(LoadingTask {
                label: major.to_string(),
                status: StepStatus::Running,
                started: Some(clock.clone()),
                duration: None,
                children: Vec::new(),
            });
            self.major_start = Some(now);
        }

        if let Some(m) = loading.last_mut() {
            m.children.push(LoadingStep {
                label: sub.to_string(),
                status: StepStatus::Running,
                started: Some(clock),
                duration: None,
            });
        }
        self.step_start = Some(now);
    }

    /// Mark the whole sequence finished: stamp the final running sub-step and
    /// its major as Done with their durations.
    pub fn finish(&mut self, loading: &mut [LoadingTask]) {
        if let Some(m) = loading.last_mut() {
            if let Some(start) = self.step_start
                && let Some(s) = m
                    .children
                    .last_mut()
                    .filter(|s| s.status == StepStatus::Running)
            {
                s.status = StepStatus::Done;
                s.duration = Some(start.elapsed());
            }
            if let Some(mstart) = self.major_start
                && m.status == StepStatus::Running
            {
                m.status = StepStatus::Done;
                m.duration = Some(mstart.elapsed());
            }
        }
        self.step_start = None;
        self.major_start = None;
    }

    /// Mark the currently-running sub-step (and its major) as Failed — the
    /// startup errored mid-step.
    pub fn fail(&mut self, loading: &mut [LoadingTask]) {
        if let Some(m) = loading.last_mut() {
            if m.status == StepStatus::Running {
                m.status = StepStatus::Failed;
            }
            if let Some(s) = m
                .children
                .last_mut()
                .filter(|s| s.status == StepStatus::Running)
            {
                s.status = StepStatus::Failed;
            }
        }
        self.step_start = None;
        self.major_start = None;
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub enum ActivePage {
    /// The startup loading screen, shown while config loads and the mediator
    /// connection is established (default so the first frame isn't a blank,
    /// not-yet-interactive main page).
    #[default]
    Loading,
    /// The main application page with menu, content panels, and activity log.
    Main,
    /// The setup wizard flow (comprised of multiple sequential screens).
    Setup,
    /// The State-B "join a community" flow (R-A-5 Stage 4).
    Join,
}

/// Tracks the state of the DIDComm mediator connection.
#[derive(Clone, Debug, Default)]
pub struct ConnectionState {
    /// Current mediator connection status.
    pub status: MediatorStatus,
    /// Whether the DIDComm message loop is actively running.
    pub messaging_active: bool,
}

#[derive(Clone, Debug, Default)]
pub enum MediatorStatus {
    /// Status has not been determined yet.
    #[default]
    Unknown,
    /// Mediator is initializing with a progress message.
    Initializing(String),
    /// Actively connecting to the mediator.
    Connecting,
    /// Successfully connected.
    Connected,
    /// Connection failed with an error description.
    Failed(String),
    /// The account has no active community/persona yet (State A, R-A-5/R-C-7):
    /// there is no DID to open a DIDComm session for. The app runs without
    /// messaging until the user joins a community.
    NoActiveCommunity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openvtc_core::config::account::{Account, CommunityRecord, PersonaId};
    use uuid::Uuid;

    #[test]
    fn reconcile_defaults_to_active_then_clears_when_it_leaves() {
        let mut account = Account::default();
        let pid = PersonaId::new();
        let now = Utc::now();
        let mut active = CommunityRecord::new_pending(
            "did:web:vtc-a".into(),
            None,
            "openvtc/a".into(),
            pid,
            Uuid::new_v4(),
            now,
        );
        active.activate(now);
        account.add_membership(active);

        let mut state = State::default();
        assert_eq!(state.selected_community, None);

        // With one active community and no selection, reconcile defaults to it.
        state.reconcile_selected_community(&account);
        assert_eq!(
            state.selected_community,
            Some(("did:web:vtc-a".to_string(), pid))
        );

        // Once it leaves (no longer active), the stale selection is dropped and
        // there is nothing to default to → no active community.
        account
            .membership_mut("did:web:vtc-a", pid)
            .unwrap()
            .leave();
        state.reconcile_selected_community(&account);
        assert_eq!(state.selected_community, None);
    }
}
