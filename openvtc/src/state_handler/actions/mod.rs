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

    /// Submit the entered community VTC DID. With existing personas this opens
    /// the identity-choice page (R-B-3); with none it kicks off the mint+join
    /// sequence directly.
    JoinSubmitVtc(String),

    /// Move the identity-choice highlight to this row (reuse option, or the
    /// trailing "mint new" row).
    JoinIdentitySelect(usize),

    /// Commit the highlighted identity choice: "mint new" launches the sequence;
    /// a reuse option arms the cross-community linkage warning (R-B-3 / D1).
    JoinIdentityChoose,

    /// Confirm reusing the highlighted persona (after the linkage warning) and
    /// launch the join sequence with it.
    JoinReuseConfirm,

    /// Dismiss the reuse linkage warning without choosing.
    JoinReuseCancel,

    /// Move the invitation-choice highlight: `0` = use the invitation, `1` =
    /// join without it.
    JoinInvitationSelect(usize),

    /// Commit the highlighted invitation choice and proceed to identity
    /// selection (or mint).
    JoinInvitationChoose,

    /// Cancel the join flow and return to the main page.
    JoinCancel,

    /// Pasted text on the join entry page that looks like an invitation
    /// credential (VIC) JSON — validated + stashed into the join flow.
    JoinPasteVic(String),

    /// Clear the loaded invitation credential on the join entry page so the
    /// join proceeds without a VIC (explicit "ignore it" choice).
    JoinClearVic,

    /// Move the Communities-list selection to this index.
    CommunitySelect(usize),

    /// Make the Active community at this index the working context (D10 / R-C-6):
    /// the community-scoped main page (relationships/inbox/VRCs/identity) switches
    /// to its persona. No-op for a non-Active (read-only) community.
    SetActiveCommunity(usize),

    /// Arm a removal confirmation for the community at this index (the panel
    /// prompts for y/n before anything is deleted).
    CommunityConfirmDelete(usize),

    /// Dismiss a pending removal confirmation without deleting.
    CommunityCancelDelete,

    /// Remove the community at this index in the Communities list (withdraws a
    /// live/pending membership, then deletes the record). Only sent after the
    /// user confirms.
    DeleteCommunity(usize),

    /// Toggle the favourite (★) flag on the community at this Communities-list
    /// display index (R-C-4). Favourites sort to the top and the flag persists.
    ToggleFavourite(usize),

    /// Acknowledge a terminal-outcome community (Rejected / Removed / Expired) at
    /// this display index, clearing its actions-required badge (R-S-2).
    AcknowledgeCommunity(usize),

    /// Arm a leave confirmation for the Active community at this index (the panel
    /// prompts y/n before sending the self-removal).
    CommunityConfirmLeave(usize),

    /// Dismiss a pending leave confirmation without leaving.
    CommunityCancelLeave,

    /// Leave the Active community at this index: send `MEMBER_SELF_REMOVE`, then
    /// set it `Left` and deregister its session (R-L-1 / R-S-3). Only sent after
    /// the user confirms.
    LeaveCommunity(usize),

    /// Arm a cancel confirmation for the Pending join at this index (the panel
    /// prompts y/n before withdrawing).
    CommunityConfirmWithdraw(usize),

    /// Dismiss a pending cancel confirmation without withdrawing.
    CommunityCancelWithdraw,

    /// Cancel the Pending join at this index: best-effort notify the VTC, then
    /// set it `Withdrawn` and deregister its session so it can be deleted or
    /// re-joined. Only sent after the user confirms.
    WithdrawJoin(usize),

    /// Archive the inactive community at this index (hide from the default list,
    /// retain the record) (R-C-8).
    ArchiveCommunity(usize),

    /// Toggle whether archived communities are shown in the Communities list, so
    /// archived records stay discoverable (R-C-8).
    ToggleShowArchived,

    /// Open the quick community switcher overlay (R-C-7): a Ctrl+K popup listing
    /// the Active communities, reachable from anywhere on the main page.
    OpenCommunitySwitcher,

    /// Move the switcher overlay's highlighted entry to this index.
    CommunitySwitcherMove(usize),

    /// Switch the working context to the switcher's highlighted Active community
    /// and close the overlay (R-C-6 / R-C-7).
    CommunitySwitcherSelect,

    /// Dismiss the switcher overlay without changing the working community.
    CloseCommunitySwitcher,

    /// Move the Context-Identities (VTA DID manager) selection to this index.
    DidSelect(usize),

    /// Arm a removal confirmation for the context DID at this index.
    DidConfirmDelete(usize),

    /// Dismiss a pending DID removal confirmation without deleting.
    DidCancelDelete,

    /// Delete the orphan context DID at this index — removes it at the VTA and
    /// locally. Only sent after the user confirms; guarded to unbound personas.
    DeleteDid(usize),

    /// Open the "create a new persona DID" overlay (label-entry phase).
    /// Reachable from the top-level menu and the VTA panel.
    StartCreatePersona,

    /// Forward a key event to the create-persona label input (editing keys only;
    /// Enter/Esc are handled by the panel, not forwarded here).
    CreatePersonaInput(crossterm::event::KeyEvent),

    /// Mint the persona with the entered label: run the VTA mint sequence, then
    /// show + copy the new DID. Only sent from the overlay's label phase.
    CreatePersonaSubmit,

    /// Copy the minted persona DID to the clipboard again (Done phase).
    CreatePersonaCopy,

    /// Close the create-persona overlay.
    CreatePersonaClose,

    // ── VIC manager (VTA panel, Invitation Credentials list) ────────────────
    /// (Re)load the VIC list from the vault (async). Sent when the operator
    /// focuses the VIC list so the panel is populated without polling.
    VicRefresh,
    /// Move the VIC-list selection to this index.
    VicSelect(usize),
    /// Toggle keyboard focus between the Context Identities and VIC lists (Tab).
    VicFocusToggle,
    /// Toggle whether archived + soft-deleted VICs are listed (`i`); triggers a
    /// re-query.
    VicToggleInactive,
    /// Archive the selected VIC (async).
    VicArchive(usize),
    /// Unarchive the selected (archived) VIC (async).
    VicUnarchive(usize),
    /// Restore the selected (soft-deleted) VIC (async).
    VicRestore(usize),
    /// Arm the soft-delete confirmation for the VIC at this index.
    VicConfirmDelete(usize),
    /// Dismiss the soft-delete confirmation.
    VicCancelDelete,
    /// Soft-delete the VIC at this index (async; after confirm).
    DeleteVic(usize),
    /// Arm the irreversible-purge confirmation for the VIC at this index.
    VicConfirmPurge(usize),
    /// Dismiss the purge confirmation.
    VicCancelPurge,
    /// Irreversibly purge the VIC at this index (async; after confirm).
    PurgeVic(usize),

    /// Open the "import an invitation credential" overlay (paste phase).
    StartAddVic,
    /// Forward a key event to the add-VIC paste input (editing keys only).
    AddVicInput(crossterm::event::KeyEvent),
    /// Set the add-VIC paste input to this text (bracketed-paste path).
    AddVicPaste(String),
    /// Validate + store the pasted VIC (async). Sent from the overlay's input phase.
    AddVicSubmit,
    /// Close the add-VIC overlay.
    AddVicClose,

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
