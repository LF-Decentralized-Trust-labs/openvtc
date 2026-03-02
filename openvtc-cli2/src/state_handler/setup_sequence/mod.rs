// ****************************************************************************
// Setup Sequence Pages
// ****************************************************************************

#[cfg(feature = "openpgp-card")]
use ::openpgp_card::{Card, state::Open};
use affinidi_tdk::did_common::Document;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use openvtc::config::PersonaDIDKeys;
use secrecy::SecretVec;
use vta_sdk::webvh::WebvhServerRecord;
use std::fmt;
use std::sync::Arc;
#[cfg(feature = "openpgp-card")]
use tokio::sync::Mutex;

pub mod config;
pub mod did_keys;
#[cfg(feature = "openpgp-card")]
pub mod openpgp_card;
pub mod vta;

/// Setup flow has many pages, they are listed here
#[derive(Debug, Clone, Copy, Default)]
pub enum SetupPage {
    #[default]
    StartAsk,
    ConfigImport, // Optional path where user will import existing config
    VtaCredentialPaste,
    VtaAuthenticate,
    VtaKeysFetch,
    DIDKeysShow,
    DidKeysExportAsk,
    DidKeysExportInputs,
    DidKeysExportShow,

    /// Optional PGP Token setup occurs here
    #[cfg(feature = "openpgp-card")]
    TokenStart,
    #[cfg(feature = "openpgp-card")]
    TokenSelect,
    #[cfg(feature = "openpgp-card")]
    TokenFactoryReset,
    #[cfg(feature = "openpgp-card")]
    TokenSetTouch,
    #[cfg(feature = "openpgp-card")]
    TokenSetCardholderName,

    UnlockCodeAsk,
    UnlockCodeSet,
    UnlockCodeWarn,
    MediatorAsk,
    MediatorCustom,
    WebvhServerSelect,
    WebvhServerProgress,
    UserName,
    WebVHAddress,
    FinalPage,
}

// ****************************************************************************
// State Management for the Setup Sequence
//
// All setup state is kept in a single struct
// ****************************************************************************

#[derive(Clone, Default, Debug)]
pub struct SetupState {
    pub active_page: SetupPage,

    pub config_import: ConfigImport,

    /// VTA setup state
    pub vta: VtaSetupState,

    /// DID Keys
    pub did_keys: Option<PersonaDIDKeys>,

    /// Contains the PGP formatted export of DID keys if user selected to export
    pub did_keys_export: DIDKeysExportState,

    /// How is the config protected?
    pub protection: ConfigProtection,

    /// PGP Hardware Tokens that are connected
    #[cfg(feature = "openpgp-card")]
    pub tokens: DetectedTokens,

    /// Hardware Token Reset State
    #[cfg(feature = "openpgp-card")]
    pub token_reset: FactoryResetToken,

    /// Hardware Touch Policy
    #[cfg(feature = "openpgp-card")]
    pub token_set_touch: TokenSetTouchPolicy,

    /// Hardware Cardholder Name
    #[cfg(feature = "openpgp-card")]
    pub token_cardholder_name: TokenSetCardholderName,

    /// WebVH server DID creation state
    pub webvh_server: WebvhServerState,

    /// Has the user selected to use a custom Mediator?
    pub custom_mediator: Option<String>,

    /// What username is the user using?
    pub username: String,

    /// What address to use for WebVH?
    pub webvh_address: WebVHAddress,

    pub final_page: FinalSetupPage,
}

/// VTA-specific setup state
#[derive(Clone, Default, Debug)]
pub struct VtaSetupState {
    pub credential_bundle_raw: Option<String>,
    pub vta_url: String,
    pub vta_did: String,
    pub credential_did: String,
    pub authenticated: bool,
    pub access_token: Option<String>,
    pub messages: Vec<MessageType>,
    pub completed: Completion,
    pub context_id: Option<String>,
    pub update_secret: Option<Secret>,
    pub next_update_secret: Option<Secret>,
    /// WebVH servers available from this VTA
    pub webvh_servers: Vec<WebvhServerRecord>,
    /// Whether user chose to use a webvh-server for DID hosting
    pub use_webvh_server: bool,
}

/// How is the configuration protected?
#[derive(Clone, Default)]
pub enum ConfigProtection {
    #[default]
    PlainText,
    Token(String),
    /// Is a SHA256 digest of the input passcode
    Passcode(Arc<SecretVec<u8>>),
}

impl std::fmt::Debug for ConfigProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigProtection::PlainText => write!(f, "ConfigProtection::PlainText"),
            ConfigProtection::Token(token_id) => {
                write!(f, "ConfigProtection::Token({})", token_id)
            }
            ConfigProtection::Passcode(_) => write!(f, "ConfigProtection::Passcode(****)"),
        }
    }
}

/// Helps format messages from backend to the frontend
#[derive(Clone, Debug)]
pub enum MessageType {
    Info(String),
    Error(String),
}

/// Completion States for tasks
#[derive(Clone, Debug, Default)]
pub enum Completion {
    #[default]
    NotFinished,
    CompletedOK,
    CompletedFail,
}

/// State relating to importing configuration
#[derive(Clone, Default, Debug)]
pub struct ConfigImport {
    pub completed: Completion,
    pub messages: Vec<MessageType>,
}

/// Update messages as the Key export works through
#[derive(Clone, Debug, Default)]
pub struct DIDKeysExportState {
    pub messages: Vec<String>,
    pub exported: Option<String>,
}

/// State relating to detecting attached hardware tokens
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default)]
pub struct DetectedTokens {
    pub tokens: Vec<Arc<Mutex<Card<Open>>>>,
    pub messages: Vec<String>,
}

#[cfg(feature = "openpgp-card")]
impl fmt::Debug for DetectedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DetectedTokens {{ tokens: {}, messages: {:?} }}",
            self.tokens.len(),
            self.messages
        )
    }
}

/// State relating to factory reset of hardware token
/// Also contains writing keys to the token
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default, Debug)]
pub struct FactoryResetToken {
    pub completed_reset: bool,
    pub completed_writing: bool,
    pub messages: Vec<MessageType>,
}

/// State relating to token touch policy
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default, Debug)]
pub struct TokenSetTouchPolicy {
    pub completed: bool,
    pub messages: Vec<MessageType>,
}

/// State relating to token cardholder name
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default, Debug)]
pub struct TokenSetCardholderName {
    pub completed: bool,
    pub messages: Vec<MessageType>,
}

/// State for creating a DID via a WebVH server
#[derive(Clone, Default, Debug)]
pub struct WebvhServerState {
    pub completed: Completion,
    pub messages: Vec<MessageType>,
    pub selected_server_id: String,
    pub custom_path: Option<String>,
    pub did: String,
    pub document: Document,
    pub mnemonic: String,
}

/// WebVH DID State
#[derive(Clone, Default, Debug)]
pub struct WebVHAddress {
    pub completed: Completion,
    pub messages: Vec<MessageType>,
    pub did: String,
    pub document: Document,
}

/// Final Setup Page State
#[derive(Clone, Default, Debug)]
pub struct FinalSetupPage {
    pub completed: Completion,
    pub messages: Vec<MessageType>,
}
