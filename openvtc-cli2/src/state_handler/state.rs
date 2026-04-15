#[cfg(feature = "openpgp-card")]
use std::sync::Arc;

#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;

use crate::state_handler::{main_page::MainPageState, setup_sequence::SetupState};

/// State holds the state of the application
#[derive(Default, Debug, Clone)]
pub struct State {
    pub active_page: ActivePage,
    pub main_page: MainPageState,
    pub setup: SetupState,
    pub connection: ConnectionState,

    /// Hardware Token Admin Pin (Arc-wrapped so clones share one allocation)
    #[cfg(feature = "openpgp-card")]
    pub token_admin_pin: Option<Arc<SecretString>>,

    /// True when the user needs to physically touch their hardware token.
    /// Not gated behind the openpgp-card feature so the StateHandler's
    /// select loop can update it unconditionally regardless of build config.
    pub token_touch_pending: bool,
}

#[derive(Default, Debug, Clone, Copy)]
pub enum ActivePage {
    /// The main application page with menu, content panels, and activity log.
    #[default]
    Main,
    /// The setup wizard flow (comprised of multiple sequential screens).
    Setup,
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
}
