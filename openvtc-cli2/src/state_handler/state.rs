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

    /// Hardware Token Admin Pin
    #[cfg(feature = "openpgp-card")]
    pub token_admin_pin: Option<SecretString>,

    /// True when the user needs to physically touch their hardware token.
    /// Not gated behind the openpgp-card feature so the StateHandler's
    /// select loop can update it unconditionally regardless of build config.
    pub token_touch_pending: bool,
}

#[derive(Default, Debug, Clone, Copy)]
pub enum ActivePage {
    #[default]
    Main,
    // Setup is comprised of multiple screens, handled in setup_page module
    Setup,
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionState {
    pub status: MediatorStatus,
    pub last_ping_latency_ms: Option<u128>,
    pub messaging_active: bool,
}

#[derive(Clone, Debug, Default)]
pub enum MediatorStatus {
    #[default]
    Unknown,
    Initializing(String),
    Connecting,
    Connected {
        latency_ms: u128,
    },
    Failed(String),
}
