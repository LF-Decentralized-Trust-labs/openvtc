#[cfg(feature = "openpgp-card")]
use std::sync::Arc;

#[cfg(feature = "openpgp-card")]
use openpgp_card::{Card, state::Open};
use openvtc::config::PersonaDIDKeys;
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

    // ************************************************************************
    // VTA Actions
    /// Submit a VTA credential bundle (base64 encoded)
    VtaSubmitCredential(String),

    /// Authenticate with VTA service
    VtaAuthenticate,

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

    // ************************************************************************
    // INBOX Actions
    /// Select a task by index in the inbox list
    InboxSelectTask(usize),

    /// Accept an inbound relationship request
    InboxAcceptRelationship {
        task_id: String,
    },

    /// Reject an inbound relationship request
    InboxRejectRelationship {
        task_id: String,
        reason: Option<String>,
    },

    /// Accept a received VRC (store it)
    InboxAcceptVrc {
        task_id: String,
    },

    /// Accept an inbound VRC request (issue a VRC back to the requester)
    InboxAcceptVrcRequest {
        task_id: String,
    },

    /// Reject an inbound VRC request
    InboxRejectVrcRequest {
        task_id: String,
        reason: Option<String>,
    },

    /// Dismiss/remove a task from the inbox
    InboxDismissTask {
        task_id: String,
    },

    /// Clear all tasks from the inbox
    InboxClearAll,

    /// Return from task detail to the inbox list
    InboxBack,

    // ************************************************************************
    // RELATIONSHIP Actions
    /// Select a relationship by index
    RelationshipSelect(usize),

    /// Open the new-request form
    RelationshipStartNewRequest,

    /// Submit a new relationship request
    RelationshipSubmitRequest {
        did: String,
        alias: String,
        reason: Option<String>,
        generate_r_did: bool,
    },

    /// Cancel the new-request form
    RelationshipCancelNewRequest,

    /// Send a trust-ping to a relationship
    RelationshipPing {
        remote_p_did: String,
    },

    /// Remove a relationship
    RelationshipRemove {
        remote_p_did: String,
    },

    /// Return from detail view to the list
    RelationshipBack,

    /// Update a text input field in the new-request form (field index, new value)
    RelationshipInputUpdate {
        field: usize,
        value: String,
    },

    // ************************************************************************
    // CREDENTIAL Actions
    /// Switch between Received/Issued tabs
    CredentialSwitchTab,

    /// Select a credential by index (high-bit = open detail)
    CredentialSelect(usize),

    /// Return from detail or new-request to list
    CredentialBack,

    /// Start the new VRC request flow (pick a relationship)
    CredentialStartNewRequest,

    /// Select a relationship for the VRC request (index into established relationships)
    CredentialSelectRelationship(usize),

    /// Submit the VRC request
    CredentialSubmitRequest {
        relationship_p_did: String,
        reason: Option<String>,
    },

    /// Cancel the new VRC request
    CredentialCancelNewRequest,

    /// Update reason input in the new-request form
    CredentialReasonUpdate(String),

    /// Remove a VRC by ID
    CredentialRemove {
        vrc_id: String,
    },

    // ************************************************************************
    // SETTINGS Actions
    /// Select a settings item by index
    SettingsSelect(usize),

    /// Start editing the selected field
    SettingsStartEdit,

    /// Submit the edited value
    SettingsSubmitEdit {
        value: String,
    },

    /// Cancel editing
    SettingsCancelEdit,

    /// Update the text input during editing
    SettingsEditUpdate(String),

    /// Export config to file
    SettingsExportConfig {
        path: String,
        passphrase: String,
    },

    /// Open the change protection sub-screen
    SettingsChangeProtection,

    /// Set a passphrase for config protection
    SettingsSetPassphrase {
        passphrase: String,
    },

    /// Remove passphrase protection (revert to keyring only)
    SettingsRemovePassphrase,

    /// Open the token management sub-screen in settings
    #[cfg(feature = "openpgp-card")]
    SettingsTokenManagement,

    /// Detect connected hardware tokens
    #[cfg(feature = "openpgp-card")]
    SettingsTokenDetect,

    /// Factory reset a detected token
    #[cfg(feature = "openpgp-card")]
    SettingsTokenFactoryReset,

    /// Return from token management to settings view
    #[cfg(feature = "openpgp-card")]
    SettingsTokenBack,
}
