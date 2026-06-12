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
    /// Arm the confirmation for dismissing a single task (R25).
    ConfirmDismiss {
        task_id: String,
    },
    /// Arm the confirmation for clearing all tasks (R25).
    ConfirmClearAll,
    /// Cancel a pending dismiss/clear-all confirmation (R25).
    CancelConfirm,
    Back,
}

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
    /// Arm the confirmation for removing a relationship (R25).
    ConfirmRemove {
        remote_p_did: String,
    },
    /// Cancel a pending relationship-removal confirmation (R25).
    CancelRemove,
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
    /// Arm the confirmation for removing a credential (R25).
    ConfirmRemove {
        vrc_id: String,
    },
    /// Cancel a pending credential-removal confirmation (R25).
    CancelRemove,
}

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
    // Manual mediator-reconnect path: handler is live, but the Settings UI does
    // not yet expose a control that emits it.
    #[allow(dead_code)]
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

pub enum Action {
    Exit,

    /// An unrecoverable error has occurred on the UX Side.
    // Error-propagation channel: handled in every action loop, but no producer
    // emits it yet (the UX side currently fails via `Interrupted` directly).
    #[allow(dead_code)]
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
    Settings(SettingsAction),

    /// Dismiss the startup loading screen (Enter, once loading has completed) and
    /// reveal the main page. Phase-2 connections are already running in the
    /// background by this point.
    DismissLoading,

    // ************************************************************************
    // JOIN flow (R-A-5 Stage 4 — State-B "join a community")
    /// Open the join flow (pressing `j` on the Communities panel). Handled in
    /// both the degraded loop (State-A first join) and the runtime select loop.
    StartJoin,

    /// Submit the entered community VTC DID — kicks off the automated
    /// persona-mint + sub-context + join-submit sequence.
    JoinSubmitVtc(String),

    /// Cancel the join flow and return to the main page.
    JoinCancel,

    /// Move the Communities-list selection to this index.
    CommunitySelect(usize),

    /// Arm a removal confirmation for the community at this index (the panel
    /// prompts for y/n before anything is deleted).
    CommunityConfirmDelete(usize),

    /// Dismiss a pending removal confirmation without deleting.
    CommunityCancelDelete,

    /// Remove the community at this index in the Communities list (withdraws a
    /// live/pending membership, then deletes the record). Only sent after the
    /// user confirms.
    DeleteCommunity(usize),

    /// Move the Context-Identities (VTA DID manager) selection to this index.
    DidSelect(usize),

    /// Arm a removal confirmation for the context DID at this index.
    DidConfirmDelete(usize),

    /// Dismiss a pending DID removal confirmation without deleting.
    DidCancelDelete,

    /// Delete the orphan context DID at this index — removes it at the VTA and
    /// locally. Only sent after the user confirms; guarded to unbound personas.
    DeleteDid(usize),

    // ************************************************************************
    // SETUP Pages
    /// Import existing Config
    /// Filename, config_unlock_passphrase, new_unlock_passphrase
    ImportConfig(String, String, String),

    /// How is the Config file protected?
    /// 1. Send the Protection Method
    /// 2. The next page to render
    SetProtection(ConfigProtection, SetupPage),

    /// Sets the DID Persona Keys.
    // Handled by the setup wizard, but no page constructs it under the current
    // online provisioning flow; retained for the manual key-set setup path.
    #[allow(dead_code)]
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
    /// Create a DID via a WebVH server (server_id, path mode)
    WebvhServerCreateDid(
        String,
        vta_sdk::protocols::did_management::create::WebvhPathMode,
    ),

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
