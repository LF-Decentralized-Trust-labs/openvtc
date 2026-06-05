// ****************************************************************************
// Setup Sequence Pages
// ****************************************************************************

#[cfg(feature = "openpgp-card")]
use ::openpgp_card::{Card, state::Open};
use affinidi_tdk::did_common::Document;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use openvtc_core::config::PersonaDIDKeys;
use secrecy::SecretBox;
use std::fmt;
use std::sync::Arc;
#[cfg(feature = "openpgp-card")]
use tokio::sync::Mutex;
use vta_sdk::provision_client::{AdminCredentialReply, DiagEntry, EphemeralSetupKey, Protocol};
use vta_sdk::webvh::WebvhServerRecord;

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
    /// Online provisioning entry — operator enters the VTA DID.
    VtaEnterDid,
    /// Operator runs `pnm contexts create … --admin-did <setup>` and presses Enter.
    VtaAclInstructions,
    /// Live diagnostics list while `provision_client::run_connection_test` runs.
    VtaProvisioning,
    VtaKeysFetch,
    DIDKeysShow,
    DidKeysExportAsk,
    DidKeysExportInputs,
    DidKeysExportShow,
    /// Asks whether to configure did-git-sign before running the install.
    DidGitSignAsk,
    /// Auto-configures did-git-sign for the freshly-provisioned persona.
    DidGitSignSetup,

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
    // R-A-5: persona-minting pages. Unreachable from State-A setup (which ends at
    // protection → account creation); reconstructed by the State-B join flow
    // (Stage 4). `#[allow(dead_code)]` until then.
    #[allow(dead_code)]
    MediatorAsk,
    MediatorCustom,
    #[allow(dead_code)]
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

    /// Result of the auto-configured did-git-sign install.
    pub did_git_sign: DidGitSignSetupState,

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
///
/// `Debug` is implemented manually because `EphemeralSetupKey` doesn't expose
/// `Debug` (and shouldn't — its private key would otherwise leak into logs).
#[derive(Clone, Default)]
pub struct VtaSetupState {
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
    /// Ephemeral did:key minted at VtaEnterDid; used as the admin DID the
    /// operator authorises via `pnm contexts create --admin-did …`.
    /// `Arc` because `EphemeralSetupKey` isn't `Clone` and `SetupState`
    /// derives `Clone` for the watch channel.
    pub setup_key: Option<Arc<EphemeralSetupKey>>,
    /// Live diagnostics list streamed from `provision_client::run_connection_test`.
    pub diagnostics: Vec<DiagEntry>,
    /// Admin credential issued by the VTA on successful provisioning. The
    /// `admin_did` becomes the new `credential_did` and the matching private
    /// key is what `challenge_response` re-authenticates with.
    pub admin_credential: Option<AdminCredentialReply>,
    /// Transport the bootstrap actually used. `Some(Protocol::DidComm)` means
    /// downstream calls must reuse DIDComm (the VTA may not advertise REST at
    /// all); `Some(Protocol::Rest)` means REST. `None` until provisioning
    /// completes.
    pub protocol: Option<Protocol>,
    /// DIDComm mediator DID, captured from `VtaEvent::Connected` when the
    /// chosen transport is DIDComm. Required to open further DIDComm sessions
    /// post-bootstrap.
    pub mediator_did: Option<String>,
}

impl fmt::Debug for VtaSetupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VtaSetupState")
            .field("vta_url", &self.vta_url)
            .field("vta_did", &self.vta_did)
            .field("credential_did", &self.credential_did)
            .field("authenticated", &self.authenticated)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("messages", &self.messages)
            .field("completed", &self.completed)
            .field("context_id", &self.context_id)
            .field(
                "update_secret",
                &self.update_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "next_update_secret",
                &self.next_update_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("webvh_servers", &self.webvh_servers)
            .field("use_webvh_server", &self.use_webvh_server)
            .field(
                "setup_key",
                &self
                    .setup_key
                    .as_ref()
                    .map(|k| format!("<setup_key did={}>", k.did)),
            )
            .field("diagnostics", &self.diagnostics)
            .field(
                "admin_credential",
                &self
                    .admin_credential
                    .as_ref()
                    .map(|a| format!("<admin_did={}>", a.admin_did)),
            )
            .field("protocol", &self.protocol)
            .field("mediator_did", &self.mediator_did)
            .finish()
    }
}

/// How is the configuration protected?
#[derive(Clone, Default)]
pub enum ConfigProtection {
    #[default]
    PlainText,
    #[cfg(feature = "openpgp-card")]
    Token(String),
    /// Is a SHA256 digest of the input passcode
    Passcode(Arc<SecretBox<Vec<u8>>>),
}

impl std::fmt::Debug for ConfigProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigProtection::PlainText => write!(f, "ConfigProtection::PlainText"),
            #[cfg(feature = "openpgp-card")]
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

/// Result of the automatic did-git-sign install during setup.
#[derive(Clone, Default, Debug)]
pub struct DidGitSignSetupState {
    pub completed: Completion,
    pub messages: Vec<MessageType>,
    pub config_path: Option<String>,
    pub ssh_public_key: Option<String>,
    /// `Some(prev)` when a `--global` `user.signingKey` was shadowed by
    /// the local install; surfaced to the operator so it isn't a surprise.
    pub overridden_global_signing_key: Option<String>,
}

/// Update messages as the Key export works through
#[derive(Clone, Default)]
pub struct DIDKeysExportState {
    pub messages: Vec<String>,
    /// PGP-armored private key block — must never appear in Debug output
    pub exported: Option<String>,
}

impl fmt::Debug for DIDKeysExportState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DIDKeysExportState")
            .field("messages", &self.messages)
            .field("exported", &self.exported.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
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
    /// Chosen WebVH path mode: `.well-known` root, an explicit label, or
    /// server auto-assignment.
    pub path_mode: vta_sdk::protocols::did_management::create::WebvhPathMode,
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
