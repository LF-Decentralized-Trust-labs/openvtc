#[cfg(feature = "openpgp-card")]
use std::sync::Arc;

#[cfg(feature = "openpgp-card")]
use openpgp_card::{Card, state::Open};
use openvtc_core::config::PersonaDIDKeys;
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
#[cfg(feature = "openpgp-card")]
use tokio::sync::Mutex;

use crate::{
    Interrupted,
    state_handler::{
        main_page::{MainPanel, menu::MainMenu},
        setup_sequence::{ConfigProtection, SetupPage},
    },
    ui::pages::setup_flow::{SetupFlow, did_keys_export_inputs::DIDKeysExportInputs},
};

// ============================================================================
// Domain sub-enums
// ============================================================================

#[allow(dead_code)]
pub enum InboxAction {
    SelectTask(usize),
    OpenDetail(usize),
    AcceptRelationship {
        task_id: String,
        generate_r_did: bool,
    },
    RejectRelationship {
        task_id: String,
        reason: Option<String>,
    },
    AcceptVrc {
        task_id: String,
    },
    AcceptVrcRequest {
        task_id: String,
    },
    RejectVrcRequest {
        task_id: String,
        reason: Option<String>,
    },
    DismissTask {
        task_id: String,
    },
    ClearAll,
    Back,
}

#[allow(dead_code)]
pub enum RelationshipAction {
    Select(usize),
    OpenDetail(usize),
    StartNewRequest,
    SubmitRequest {
        did: String,
        alias: String,
        reason: Option<String>,
        generate_r_did: bool,
    },
    CancelNewRequest,
    Ping {
        remote_p_did: String,
    },
    Remove {
        remote_p_did: String,
    },
    Back,
    InputUpdate {
        field: usize,
        value: String,
    },
    ToggleRDid,
    /// Switch focus to a specific form field by index
    FocusField(usize),
    /// Begin editing the alias for a relationship
    StartEditAlias {
        index: usize,
        current_alias: String,
    },
    /// Update the alias input text during editing
    EditAliasUpdate(String),
    /// Submit the edited alias for a relationship
    EditAlias {
        remote_p_did: String,
        alias: String,
    },
    /// Cancel alias editing
    CancelEditAlias {
        index: usize,
    },
    /// Request a VRC from a relationship partner
    RequestVrc {
        remote_p_did: String,
    },
}

#[allow(dead_code)]
pub enum CredentialAction {
    SwitchTab,
    Select(usize),
    OpenDetail(usize),
    Back,
    StartNewRequest,
    SelectRelationship(usize),
    SubmitRequest {
        relationship_p_did: String,
        reason: Option<String>,
    },
    CancelNewRequest,
    ReasonUpdate(String),
    Remove {
        vrc_id: String,
    },
}

#[allow(dead_code)]
pub enum ContactAction {
    Add { did: String, alias: Option<String> },
    Remove { did: String },
}

#[allow(dead_code)]
pub enum SettingsAction {
    Select(usize),
    StartEdit,
    FieldUpdate(String),
    FormFieldUpdate {
        field: usize,
        value: String,
    },
    FormTabSwitch,
    ProtectionOptionSelect(usize),
    ProtectionStartInput,
    ProtectionPassphraseLen(usize),
    ProtectionConfirmLen(usize),
    ProtectionTabSwitch(usize),
    PassphraseLen(usize),
    SubmitEdit {
        value: String,
    },
    CancelEdit,
    ExportConfig {
        path: String,
        passphrase: String,
    },
    ImportConfig {
        path: String,
        passphrase: String,
    },
    ChangeProtection,
    SetPassphrase {
        passphrase: String,
    },
    RemovePassphrase,
    ReconnectMediator,
    /// Open the wipe-profile confirmation dialog from the Settings menu.
    WipeProfileStart,
    /// Update the live "type WIPE to confirm" input on the wipe dialog.
    WipeProfileInput(String),
    /// Operator typed `WIPE` and pressed Enter — actually nuke the profile.
    WipeProfileConfirm,
    #[cfg(feature = "openpgp-card")]
    TokenManagement,
    #[cfg(feature = "openpgp-card")]
    TokenDetect,
    #[cfg(feature = "openpgp-card")]
    TokenFactoryReset,
    #[cfg(feature = "openpgp-card")]
    TokenBack,
    /// Clipboard copy result message for display on the status panel.
    ClipboardCopied(String),
}

// ============================================================================
// Top-level Action enum
// ============================================================================

// Some variants (e.g. ContactAction::Add, ContactAction::Remove) are defined
// for the handler but not yet wired to UI construction; others are gated behind
// cfg features.
#[allow(dead_code)]
pub enum Action {
    Exit,

    /// An unrecoverable error has occurred on the UX Side
    UXError(Interrupted),

    /// Make MainMenu active
    /// This is used from the setup flow to switch back to the main menu
    ActivateMainMenu,

    /// A main menu item has been selected
    MainMenuSelected(MainMenu),

    /// Active Panel switched to
    MainPanelSwitch(MainPanel),

    // Domain actions (grouped into sub-enums)
    Inbox(InboxAction),
    Relationship(RelationshipAction),
    Credential(CredentialAction),
    Contact(ContactAction),
    Settings(SettingsAction),

    // ************************************************************************
    // SETUP Pages
    /// Import existing Config
    /// Filename, config_unlock_passphrase, new_unlock_passphrase
    ImportConfig(String, String, String),

    /// How is the Config file protected?
    /// 1. Send the Protection Method
    /// 2. The next page to render
    SetProtection(ConfigProtection, SetupPage),

    /// Sets the DID Persona Keys
    SetDIDKeys(Box<PersonaDIDKeys>),

    /// Export DID Private keys as PGP Armored file
    ExportDIDKeys(DIDKeysExportInputs),

    /// Auto-configure did-git-sign for the freshly-provisioned persona.
    /// Fired on entry to the `DidGitSignSetup` page.
    DidGitSignInstall,

    // ************************************************************************
    // VTA Actions
    /// Submit the VTA DID. Triggers URL resolution + ephemeral setup-key mint
    /// for the new online provisioning flow.
    VtaSubmitDid(String),

    /// Operator finished the PNM ACL grant — kick off
    /// `provision_client::run_connection_test` to bootstrap. Carries the
    /// context id the operator typed on the AclInstructions screen so it
    /// matches what they ran `pnm contexts create --id …` with.
    VtaStartProvision(String),

    /// Create keys via VTA service
    VtaCreateKeys,

    // ************************************************************************
    // PGP Hardware token Specific Actions
    /// Fetches PGP Hardware Tokens that are connected
    #[cfg(feature = "openpgp-card")]
    GetTokens,

    /// Set the Admin PIN Code for the Hardware Token
    /// Token ID, Admin PIN
    #[cfg(feature = "openpgp-card")]
    SetAdminPin(String, SecretString),

    /// Set the Touch Policy
    #[cfg(feature = "openpgp-card")]
    SetTouchPolicy(Option<Arc<Mutex<Card<Open>>>>),

    /// Set the Cardholdername
    #[cfg(feature = "openpgp-card")]
    SetTokenName(Option<Arc<Mutex<Card<Open>>>>, String),

    /// Factory Reset Hardware Token
    #[cfg(feature = "openpgp-card")]
    FactoryReset(Option<Arc<Mutex<Card<Open>>>>),

    /// Write Keys
    #[cfg(feature = "openpgp-card")]
    TokenWriteKeys(Option<Arc<Mutex<Card<Open>>>>),

    // ************************************************************************
    /// Create a DID via a WebVH server (server_id, optional custom path)
    WebvhServerCreateDid(String, Option<String>),

    /// Using a custom mediator DID
    SetCustomMediator(String),

    /// What username to be known as
    SetUsername(String),

    /// Creates the initial WebVH DID
    CreateWebVHDID(String),

    /// Resets the state of the WebVH DID
    ResetWebVHDID,

    /// Attempts to resolve a WebVH DID
    ResolveWebVHDID(String),

    /// Final setup step completed, sends the whole setup flow
    SetupCompleted(Box<SetupFlow>),
}
