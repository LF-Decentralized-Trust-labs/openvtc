// ****************************************************************************
// Content Panel State
// ****************************************************************************

/// Top-level state for the content panel (right side of main page).
#[derive(Clone, Debug, Default)]
pub struct ContentPanelState {
    /// Is this content panel currently focused?
    pub selected: bool,
    /// Inbox/tasks panel state
    pub inbox: InboxState,
    /// Relationships panel state
    pub relationships: RelationshipsState,
    /// Credentials (VRCs) panel state
    pub credentials: CredentialsState,
    /// Settings panel state
    pub settings: SettingsState,
    /// VTA service panel state
    pub vta: VtaState,
    /// Logs panel state
    pub logs: LogsState,
    /// Communities overview panel state
    pub communities: CommunitiesState,
}

// ****************************************************************************
// Communities State (R-C-*)
// ****************************************************************************

/// State for the Communities overview panel — the account's community
/// memberships, in display order (favourites first).
#[derive(Clone, Debug, Default)]
pub struct CommunitiesState {
    /// Display summaries of the (non-archived) communities, in display order.
    pub items: Vec<CommunitySummary>,
    /// Currently selected index in the list.
    pub selected_index: usize,
    /// Number of communities raising the actions-required indicator (R-C-3).
    pub actions_required: usize,
    /// Transient status message.
    pub status_message: Option<String>,
    /// When `Some(index)`, a removal of that community is awaiting `y`/`n`
    /// confirmation (the panel shows a prompt and other keys are suppressed).
    pub confirm_delete: Option<usize>,
}

/// Lightweight display summary of a community membership (no Arc/Mutex).
#[derive(Clone, Debug)]
pub struct CommunitySummary {
    /// Display name (resolved name, or the VTC DID when unnamed).
    pub display_name: String,
    /// Human-readable membership status (e.g. "Active", "Pending", "Left").
    pub status_label: String,
    /// Label of the persona presented to this community.
    pub persona_label: String,
    /// Member-since date (when Active), formatted; empty otherwise.
    pub member_since: String,
    /// Whether the user has starred this community (R-C-4).
    pub favourite: bool,
    /// Whether this community raises the actions-required indicator (R-C-3).
    pub needs_attention: bool,
    /// Full persona `did:webvh` presented to this community (troubleshooting
    /// detail). Empty if the `persona_ref` dangles.
    pub persona_did: String,
    /// The community's VTC `did:webvh` (troubleshooting detail).
    pub vtc_did: String,
    /// The per-community sub-context id (troubleshooting detail).
    pub sub_context_id: String,
    /// The join request id while `Pending`; empty otherwise.
    pub request_id: String,
    /// Whether the membership credential (VMC) has been received + stored.
    pub has_membership_credential: bool,
    /// Whether the role endorsement credential (VEC) has been received.
    pub has_role_credential: bool,
}

// ****************************************************************************
// VTA State
// ****************************************************************************

/// State for the VTA service information panel.
#[derive(Clone, Debug, Default)]
pub struct VtaState {
    /// Active configuration profile name
    pub profile: String,
    /// VTA context name (fetched from VTA service)
    pub context_name: Option<String>,
    /// Persona DID
    pub persona_did: String,
    /// Mediator DID
    pub mediator_did: String,
    /// VTA service URL
    pub vta_url: String,
    /// VTA service DID
    pub vta_did: String,
    /// Credential DID used for VTA authentication
    pub credential_did: String,
    /// Total number of keys managed
    pub key_count: usize,
    /// Number of persona keys
    pub persona_key_count: usize,
    /// Number of relationship keys
    pub relationship_key_count: usize,
    /// Whether the VTA key backend is in use
    pub is_vta_managed: bool,
    /// DIDs in use (persona + relationship R-DIDs)
    pub active_dids: Vec<ActiveDid>,
    /// Every persona DID minted in this context, with how many communities
    /// present it — the manageable set for the DID manager. A persona bound to
    /// zero communities is an orphan (e.g. left by a failed join).
    pub context_dids: Vec<ManagedDid>,
}

/// A persona DID in the account's context, for the DID manager view.
#[derive(Clone, Debug, Default)]
pub struct ManagedDid {
    /// The persona `did:webvh`.
    pub did: String,
    /// Optional human label.
    pub label: String,
    /// How many communities present this persona (0 ⇒ orphan).
    pub bound_communities: usize,
    /// Whether this is the account's current active persona.
    pub is_active: bool,
}

/// A DID in active use within this context.
#[derive(Clone, Debug, Default)]
pub struct ActiveDid {
    /// The DID string
    pub did: String,
    /// Human-readable label
    pub label: String,
}

// ****************************************************************************
// Inbox State
// ****************************************************************************

/// State for the inbox/tasks panel.
#[derive(Clone, Debug, Default)]
pub struct InboxState {
    /// Display summaries of all pending tasks
    pub tasks: Vec<TaskSummary>,
    /// Currently selected task index in the list
    pub selected_index: usize,
    /// When viewing a specific task's details
    pub active_task: Option<ActiveTaskView>,
    /// Transient status message (e.g., "Task accepted", "Error: ...")
    pub status_message: Option<String>,
}

/// Lightweight display summary of a task (no Arc/Mutex).
#[derive(Clone, Debug)]
pub struct TaskSummary {
    /// Task ID
    pub id: String,
    /// Human-friendly type description (e.g., "Relationship Request (Inbound)")
    pub type_display: String,
    /// Categorization for UI rendering and action dispatch
    pub kind: TaskKind,
    /// Shortened DID of the remote party (if applicable)
    pub remote_did: String,
    /// Formatted creation timestamp
    pub created: String,
}

/// Categorizes tasks for UI rendering and determining available actions.
#[derive(Clone, Debug)]
// Some variant fields (e.g. `Informational(String)`) are populated but not yet
// read by the UI — kept for future detail-view rendering.
#[allow(dead_code)]
pub enum TaskKind {
    /// Inbound relationship request awaiting accept/reject
    RelationshipRequestInbound {
        from_did: String,
        their_did: String,
        reason: Option<String>,
        /// Friendly name of the requester (if provided)
        name: Option<String>,
    },
    /// Outbound relationship request awaiting response
    RelationshipRequestOutbound { our_did: String },
    /// Inbound VRC request awaiting accept/reject
    VRCRequestInbound { reason: Option<String> },
    /// Outbound VRC request awaiting response
    VRCRequestOutbound,
    /// A VRC was issued to us, awaiting acceptance
    VRCIssued,
    /// Trust ping awaiting pong
    TrustPing,
    /// Informational task (accepted, rejected, finalized, etc.)
    Informational(String),
}

/// Detailed view of a specific task for the interaction screen.
#[derive(Clone, Debug)]
pub enum ActiveTaskView {
    RelationshipRequestInbound {
        task_id: String,
        from_did: String,
        their_did: String,
        reason: Option<String>,
        name: Option<String>,
    },
    /// Outbound relationship request — waiting for response
    RelationshipRequestOutbound {
        task_id: String,
        to_did: String,
        our_did: String,
        state: String,
    },
    VRCRequestInbound {
        task_id: String,
        from_did: String,
        reason: Option<String>,
    },
    /// Outbound VRC request — waiting for response
    VRCRequestOutbound {
        task_id: String,
        remote_did: String,
    },
    VRCIssued {
        task_id: String,
        issuer: String,
    },
    /// Generic info task (ping, pong, informational)
    Info {
        task_id: String,
        type_display: String,
        remote_did: String,
    },
}

// ****************************************************************************
// Relationships State
// ****************************************************************************

/// State for the relationships panel.
#[derive(Clone, Debug, Default)]
pub struct RelationshipsState {
    /// Display summaries of all relationships
    pub relationships: Vec<RelationshipSummary>,
    /// Currently selected index in the list
    pub selected_index: usize,
    /// Current panel mode (list, detail, new request form)
    pub mode: RelationshipsMode,
    /// Transient status message
    pub status_message: Option<String>,
}

/// Display modes for the relationships panel.
#[derive(Clone, Debug, Default)]
pub enum RelationshipsMode {
    /// Browsing the list of relationships
    #[default]
    List,
    /// Viewing details of a specific relationship.
    /// `selected_vrc`: None = relationship info shown, Some(n) = VRC at index n expanded.
    Detail {
        index: usize,
        selected_vrc: Option<usize>,
    },
    /// Editing the alias for an existing relationship
    EditAlias { index: usize, alias_input: String },
    /// Filling out a new relationship request form
    NewRequest {
        did_input: String,
        alias_input: String,
        reason_input: String,
        /// Whether to generate a random relationship DID (privacy)
        generate_r_did: bool,
        /// Which form field is currently focused (0=DID, 1=Alias, 2=Reason, 3=R-DID toggle)
        active_field: usize,
    },
}

/// Lightweight display summary of a relationship.
#[derive(Clone, Debug)]
pub struct RelationshipSummary {
    /// Remote party's persona DID
    pub remote_p_did: String,
    /// Contact alias (if set)
    pub alias: Option<String>,
    /// Human-readable state (e.g., "Established", "Request Sent")
    pub state: String,
    /// Our DID used in this relationship
    pub our_did: String,
    /// Remote party's DID for this relationship
    pub remote_did: String,
    /// Formatted creation timestamp
    pub created: String,
    /// VRCs we issued to this party
    pub vrcs_issued: Vec<RelationshipVrc>,
    /// VRCs we received from this party
    pub vrcs_received: Vec<RelationshipVrc>,
}

/// VRC info for display in the relationship detail view.
#[derive(Clone, Debug)]
pub struct RelationshipVrc {
    /// Issuer DID (shortened for display)
    pub issuer: String,
    /// Full issuer DID
    pub issuer_full: String,
    /// Subject DID (shortened for display)
    pub subject: String,
    /// Full subject DID
    pub subject_full: String,
    /// Formatted valid_from date
    pub valid_from: String,
    /// Formatted valid_until date (if set)
    pub valid_until: Option<String>,
    /// Pretty-printed JSON of the raw credential
    pub raw_json: String,
}

// ****************************************************************************
// Credentials State
// ****************************************************************************

/// State for the credentials (VRCs) panel.
#[derive(Clone, Debug, Default)]
pub struct CredentialsState {
    /// VRCs we received
    pub received: Vec<VrcSummary>,
    /// VRCs we issued
    pub issued: Vec<VrcSummary>,
    /// Which tab is active
    pub selected_tab: CredentialTab,
    /// Currently selected index in the active tab's list
    pub selected_index: usize,
    /// Current panel mode
    pub mode: CredentialsMode,
    /// Transient status message
    pub status_message: Option<String>,
}

/// Which credential tab is active.
#[derive(Clone, Debug, Default)]
pub enum CredentialTab {
    #[default]
    Received,
    Issued,
}

/// Display modes for the credentials panel.
#[derive(Clone, Debug, Default)]
pub enum CredentialsMode {
    /// Browsing the list of credentials
    #[default]
    List,
    /// Viewing details of a specific credential
    Detail { index: usize },
    /// Requesting a new VRC: selecting a relationship
    NewRequest {
        /// Index into the established relationships list
        relationship_index: usize,
        reason_input: String,
    },
}

/// Lightweight display summary of a VRC.
#[derive(Clone, Debug)]
pub struct VrcSummary {
    /// VRC identifier (proof value hash)
    pub vrc_id: String,
    /// Remote party's persona DID
    pub remote_p_did: String,
    /// Pretty-printed JSON of the raw credential
    pub raw_json: String,
    /// Contact alias (if set)
    pub alias: Option<String>,
    /// Issuer DID
    pub issuer: String,
    /// Subject DID
    pub subject: String,
    /// Formatted valid_from date
    pub valid_from: String,
    /// Formatted valid_until date (if set)
    pub valid_until: Option<String>,
}

// ****************************************************************************
// Logs State
// ****************************************************************************

/// State for the logs panel.
#[derive(Clone, Debug, Default)]
pub struct LogsState {
    /// Currently selected log entry index (0 = newest).
    /// Managed locally by the UI component, not stored in State.
    pub selected_index: usize,
    /// When true, show the full text of the selected log entry.
    pub detail_view: bool,
}

// ****************************************************************************
// Settings State
// ****************************************************************************

/// State for the settings panel.
#[derive(Clone, Debug, Default)]
pub struct SettingsState {
    /// Current friendly name
    pub friendly_name: String,
    /// Current mediator DID
    pub mediator_did: String,
    /// Current organization DID
    pub org_did: String,
    /// Persona DID (read-only display)
    pub persona_did: String,
    /// How the config is protected (Token/Encrypted/Plaintext)
    pub protection_type: String,
    /// Currently selected setting index
    pub selected_index: usize,
    /// Current panel mode
    pub mode: SettingsMode,
    /// Transient status message
    pub status_message: Option<String>,
    /// Hardware token management state
    #[cfg(feature = "openpgp-card")]
    pub token: TokenManagementState,
    /// did-git-sign install info, when this persona has been configured for
    /// git commit signing. Surfaced on the Help/Status panel so the operator
    /// can copy the SSH public key into their git host's signing-key
    /// settings.
    pub did_git_sign: Option<DidGitSignInfo>,
}

/// Snapshot of the local did-git-sign install for this persona.
#[derive(Clone, Debug)]
pub struct DidGitSignInfo {
    /// Verification method id from the SigningConfig file.
    pub did_key_id: String,
    /// Persona signing public key formatted as `ssh-ed25519 AAAA…`.
    pub ssh_public_key: String,
    /// Filesystem path to the SigningConfig the install wrote.
    pub config_path: String,
}

/// Hardware token management state.
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Debug, Default)]
pub struct TokenManagementState {
    /// Number of detected tokens
    pub detected_count: usize,
    /// Status messages from token operations
    pub messages: Vec<String>,
    /// Whether a factory reset was completed
    pub reset_completed: bool,
}

/// Display modes for the settings panel.
#[derive(Clone, Debug, Default)]
pub enum SettingsMode {
    /// Viewing settings list
    #[default]
    View,
    /// Editing the friendly name
    EditFriendlyName { input: String },
    /// Editing the mediator DID
    EditMediatorDid { input: String },
    /// Editing the org DID
    EditOrgDid { input: String },
    /// Export config form (path + passphrase length for masked display)
    ExportConfig {
        path_input: String,
        /// Length of the passphrase (actual value held only in UI component)
        passphrase_len: usize,
        active_field: usize,
    },
    /// Import config form (path + passphrase length for masked display)
    ImportConfig {
        path_input: String,
        /// Length of the passphrase (actual value held only in UI component)
        passphrase_len: usize,
        active_field: usize,
    },
    /// Changing protection level (set/remove passphrase)
    ChangeProtection {
        /// 0 = Set passphrase, 1 = Remove passphrase (keyring only)
        selected_option: usize,
        /// Length of the passphrase (actual value held only in UI component)
        passphrase_len: usize,
        /// Length of the confirm passphrase (actual value held only in UI component)
        confirm_len: usize,
        /// Which field is active (0 = option list, 1 = passphrase, 2 = confirm)
        active_field: usize,
    },
    /// Token management sub-screen
    #[cfg(feature = "openpgp-card")]
    TokenManagement { selected_index: usize },
    /// Wipe-profile confirmation. Operator must type the literal token
    /// `WIPE` (case-insensitive) into `confirm_input` before the wipe is
    /// permitted to proceed. Anything else just closes the dialog.
    WipeConfirm {
        /// Live text the operator is typing into the confirm field.
        confirm_input: String,
    },
}
