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

    /// Rotating-tip index for the startup loading screen, advanced as startup
    /// steps stream so the tip changes during the load/connect.
    pub tip_index: usize,

    /// Timed startup steps shown on the loading screen, in order. Each entry is
    /// marked done (with its duration) when the next step begins, so the user
    /// sees exactly which step is slow.
    pub loading_steps: Vec<LoadingStep>,

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
}

/// One timed step of the startup sequence, shown on the loading screen.
#[derive(Clone, Debug)]
pub struct LoadingStep {
    /// What the step is doing (the progress message).
    pub label: String,
    /// Wall-clock time the step started, `HH:MM:SS`.
    pub started: String,
    /// How long the step took, once completed. `None` while still running.
    pub duration: Option<std::time::Duration>,
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
