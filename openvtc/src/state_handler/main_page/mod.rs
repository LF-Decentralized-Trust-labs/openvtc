use std::collections::VecDeque;
use std::sync::Arc;

use openvtc_core::{
    config::{Config, KeyBackend, account::PersonaId},
    display::truncate_did,
    tasks::TaskType,
};

/// Whether an item owned by `item_persona` is in scope for the working community
/// whose persona is `active` (D10 / R-C-6). Tagged items match when their persona
/// is the active one. Untagged items (legacy, pre-attribution) show only when the
/// account has at most one persona, where there is no ambiguity; with multiple
/// personas an untagged item is hidden until re-tagged. With no active selection
/// (no working community), only the single/zero-persona case shows everything.
fn persona_in_scope(
    item_persona: Option<PersonaId>,
    active: Option<PersonaId>,
    persona_count: usize,
) -> bool {
    match active {
        Some(p) => item_persona == Some(p) || (item_persona.is_none() && persona_count <= 1),
        None => persona_count <= 1,
    }
}

use crate::state_handler::main_page::{
    content::{
        ContentPanelState, DidGitSignInfo, RelationshipSummary, TaskKind, TaskSummary, VrcSummary,
    },
    menu::MenuPanelState,
};

pub mod content;
pub mod menu;

/// Maximum number of activity log entries to keep in the UI.
const MAX_ACTIVITY_LOG_ENTRIES: usize = 100;

/// A single activity log entry with a short summary and optional detail.
#[derive(Clone, Debug)]
pub struct ActivityLogEntry {
    /// Short summary shown in the list view (includes timestamp).
    pub summary: String,
    /// Detailed information shown when the entry is expanded.
    /// Includes DIDComm message details, DID addresses, etc.
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MainPageState {
    /// State related to the menu panel
    pub menu_panel: MenuPanelState,

    /// State related to the content panel
    pub content_panel: ContentPanelState,

    pub config: MainMenuConfigState,

    /// Quick community-switcher overlay (R-C-7). `Some` while the Ctrl+K popup is
    /// open; `None` (the default) when closed. Lives at the page level rather
    /// than in a content panel because it floats over whichever panel is focused.
    pub switcher: Option<content::CommunitySwitcherState>,

    /// "Create a new persona DID" overlay. `Some` while open; `None` (default)
    /// when closed. Page-level (like [`switcher`](Self::switcher)) because it
    /// floats over whichever panel is focused and is reachable from both the
    /// top-level menu and the VTA panel.
    pub create_persona: Option<content::CreatePersonaState>,

    /// "Import an invitation credential" overlay for the VIC manager. `Some`
    /// while open; `None` (default) when closed. Page-level (like
    /// [`create_persona`](Self::create_persona)) because it floats over the panel.
    pub add_vic: Option<content::AddVicState>,

    /// Activity log entries shown in the bottom panel (newest last).
    ///
    /// Entries are wrapped in `Arc` so cloning `MainPageState` (which happens
    /// per frame and per event via the `State` watch channel) shares the
    /// entries by pointer rather than deep-copying each entry's summary and
    /// detail strings. Entries are immutable once written.
    pub activity_log: VecDeque<Arc<ActivityLogEntry>>,
}

impl MainPageState {
    /// Push a timestamped entry to the activity log (O(1) bounded insertion).
    pub fn log(&mut self, message: impl Into<String>) {
        self.log_detailed_inner(message.into(), None);
    }

    /// Push a timestamped entry with detailed diagnostic info.
    pub fn log_detailed(&mut self, message: impl Into<String>, detail: impl Into<String>) {
        self.log_detailed_inner(message.into(), Some(detail.into()));
    }

    fn log_detailed_inner(&mut self, message: String, detail: Option<String>) {
        if self.activity_log.len() >= MAX_ACTIVITY_LOG_ENTRIES {
            self.activity_log.pop_front();
        }
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        self.activity_log.push_back(Arc::new(ActivityLogEntry {
            summary: format!("[{}] {}", timestamp, message),
            detail,
        }));
    }

    /// Log an error with a short context line and a detailed pane containing
    /// the full alternate `Display` form (`{err:#}`) plus the `Debug`
    /// representation. Works with any `Display + Debug` error type (anyhow
    /// renders its full cause chain under `{err:#}`).
    pub fn log_error<E>(&mut self, context: impl Into<String>, err: &E)
    where
        E: std::fmt::Display + std::fmt::Debug + ?Sized,
    {
        let context = context.into();
        let summary = format!("{context}: {err}");
        let detail = format_error_detail(&context, err);
        self.log_detailed_inner(summary, Some(detail));
    }
}

/// Format an error for the log detail pane. Includes the context line, the
/// full `Display` (alternate form, which for anyhow expands the cause chain),
/// and the `Debug` representation.
#[must_use]
pub fn format_error_detail<E>(context: &str, err: &E) -> String
where
    E: std::fmt::Display + std::fmt::Debug + ?Sized,
{
    let divider = "─".repeat(context.len().min(60));
    format!("{context}\n{divider}\n\nError: {err:#}\n\nDebug:\n{err:?}")
}

impl MainPageState {
    /// Rebuilds all display state from the current Config.
    ///
    /// Called after Config is loaded at startup and after every Config mutation
    /// (message processing, user actions, etc.).
    pub fn sync_from_config(&mut self, config: &Config) {
        // Update header config
        self.config = MainMenuConfigState::from(config);

        // The working community's persona scopes the relationship/inbox/VRC
        // panels (D10 / R-C-6): only items owned by it (plus untagged legacy
        // items in a single-persona account) are shown.
        let active_persona = config.active_persona;
        let persona_count = config.account.personas.len();

        // Sync inbox tasks
        let mut inbox_tasks: Vec<TaskSummary> = config
            .private
            .tasks
            .tasks
            .values()
            .filter(|task| persona_in_scope(task.our_persona, active_persona, persona_count))
            .map(|task| {
                let kind = match &task.type_ {
                    TaskType::RelationshipRequestInbound { from, request, .. } => {
                        TaskKind::RelationshipRequestInbound {
                            from_did: sanitize_display(from, 256),
                            their_did: sanitize_display(&request.did, 256),
                            reason: request.reason.as_deref().map(|r| sanitize_display(r, 256)),
                            name: request.name.as_deref().map(|n| sanitize_display(n, 256)),
                        }
                    }
                    TaskType::RelationshipRequestOutbound { to } => {
                        let our_did = config
                            .private
                            .relationships
                            .relationships
                            .get(to)
                            .map(|rel| rel.our_did.to_string())
                            .unwrap_or_default();
                        TaskKind::RelationshipRequestOutbound { our_did }
                    }
                    TaskType::VRCRequestInbound { request, .. } => TaskKind::VRCRequestInbound {
                        reason: request.reason.as_deref().map(|r| sanitize_display(r, 256)),
                    },
                    TaskType::VRCRequestOutbound { .. } => TaskKind::VRCRequestOutbound,
                    TaskType::VRCIssued { .. } => TaskKind::VRCIssued,
                    TaskType::TrustPing { .. } => TaskKind::TrustPing,
                    TaskType::RelationshipRequestAccepted => {
                        TaskKind::Informational("Accepted".to_string())
                    }
                    TaskType::RelationshipRequestRejected => {
                        TaskKind::Informational("Rejected".to_string())
                    }
                    TaskType::RelationshipRequestFinalized => {
                        TaskKind::Informational("Finalized".to_string())
                    }
                    TaskType::TrustPong => TaskKind::Informational("Pong received".to_string()),
                    TaskType::VRCRequestRejected => {
                        TaskKind::Informational("VRC Rejected".to_string())
                    }
                    _ => TaskKind::Informational("Unknown".to_string()),
                };
                let remote_did = match &task.type_ {
                    TaskType::RelationshipRequestInbound { from, request, .. } => {
                        if let Some(ref name) = request.name {
                            sanitize_display(name, 40)
                        } else {
                            shorten_did(from, 60)
                        }
                    }
                    TaskType::RelationshipRequestOutbound { to } => shorten_did(to, 60),
                    TaskType::TrustPing { to, .. } => shorten_did(to, 60),
                    TaskType::VRCRequestInbound { remote_p_did, .. } => {
                        shorten_did(remote_p_did, 60)
                    }
                    TaskType::VRCRequestOutbound { remote_p_did } => shorten_did(remote_p_did, 60),
                    TaskType::VRCIssued { vrc } => sanitize_display(vrc.issuer(), 40),
                    _ => String::new(),
                };
                TaskSummary {
                    id: task.id.to_string(),
                    type_display: task.type_.to_string(),
                    kind,
                    remote_did: sanitize_display(&remote_did, 256),
                    created: task.created.format("%Y-%m-%d %H:%M").to_string(),
                }
            })
            .collect();
        // Sort tasks by most recent first
        inbox_tasks.sort_by(|a, b| b.created.cmp(&a.created));
        self.content_panel.inbox.tasks = inbox_tasks.into();

        // Sync relationships (scoped to the working community's persona)
        self.content_panel.relationships.relationships = config
            .private
            .relationships
            .relationships
            .iter()
            .filter(|(_, rel)| persona_in_scope(rel.our_persona, active_persona, persona_count))
            .map(|(remote_p_did, rel)| {
                let alias = config
                    .private
                    .contacts
                    .find_contact(remote_p_did)
                    .and_then(|c| c.alias.clone());
                let vrcs_issued = config
                    .private
                    .vrcs_issued
                    .get(remote_p_did)
                    .map(|m| {
                        m.values()
                            .map(|vrc| content::RelationshipVrc {
                                issuer: shorten_did(vrc.issuer(), 40),
                                issuer_full: vrc.issuer().to_string(),
                                subject: shorten_did(vrc.subject(), 40),
                                subject_full: vrc.subject().to_string(),
                                valid_from: vrc.valid_from().format("%Y-%m-%d").to_string(),
                                valid_until: vrc
                                    .valid_until()
                                    .map(|d| d.format("%Y-%m-%d").to_string()),
                                // Defer pretty-printing to detail-view render
                                // time; share the credential by Arc pointer.
                                raw_json: content::RawCredential::Vrc(Arc::clone(vrc)),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let vrcs_received = config
                    .private
                    .vrcs_received
                    .get(remote_p_did)
                    .map(|m| {
                        m.values()
                            .map(|vrc| content::RelationshipVrc {
                                issuer: shorten_did(vrc.issuer(), 40),
                                issuer_full: vrc.issuer().to_string(),
                                subject: shorten_did(vrc.subject(), 40),
                                subject_full: vrc.subject().to_string(),
                                valid_from: vrc.valid_from().format("%Y-%m-%d").to_string(),
                                valid_until: vrc
                                    .valid_until()
                                    .map(|d| d.format("%Y-%m-%d").to_string()),
                                // Defer pretty-printing to detail-view render
                                // time; share the credential by Arc pointer.
                                raw_json: content::RawCredential::Vrc(Arc::clone(vrc)),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                RelationshipSummary {
                    remote_p_did: sanitize_display(remote_p_did, 256),
                    alias: alias.as_deref().map(|a| sanitize_display(a, 256)),
                    state: rel.state.to_string(),
                    our_did: rel.our_did.to_string(),
                    remote_did: sanitize_display(&rel.remote_did, 256),
                    created: rel.created.format("%Y-%m-%d %H:%M").to_string(),
                    vrcs_issued,
                    vrcs_received,
                }
            })
            .collect();

        // Sync credentials (scoped to the working community's persona)
        self.content_panel.credentials.received = collect_vrcs(
            &config.private.vrcs_received,
            config,
            active_persona,
            persona_count,
        )
        .into();
        self.content_panel.credentials.issued = collect_vrcs(
            &config.private.vrcs_issued,
            config,
            active_persona,
            persona_count,
        )
        .into();
        self.content_panel.credentials.membership = collect_membership_creds(config).into();

        // Sync settings
        self.content_panel.settings.friendly_name = config.public.friendly_name.clone();
        self.content_panel.settings.mediator_did = config.mediator_did().to_string();
        self.content_panel.settings.org_did = config.account.org_did.clone();
        self.content_panel.settings.persona_did = config.persona_did().to_string();
        self.content_panel.settings.did_git_sign = detect_did_git_sign_info(config.persona_did());
        // Sync VTA info
        self.content_panel.vta.persona_did = config.persona_did().to_string();
        self.content_panel.vta.mediator_did = config.mediator_did().to_string();
        match &config.key_backend {
            KeyBackend::Vta {
                vta_url,
                vta_did,
                credential_did,
                ..
            } => {
                self.content_panel.vta.vta_url = vta_url.clone();
                self.content_panel.vta.vta_did = vta_did.clone();
                self.content_panel.vta.credential_did = credential_did.clone();
                self.content_panel.vta.is_vta_managed = true;
            }
            _ => {
                self.content_panel.vta.is_vta_managed = false;
            }
        }
        self.content_panel.vta.key_count = config.key_info.len();
        // Count persona vs relationship keys. With no active persona (State A)
        // there are no persona keys — and `starts_with("")` would otherwise match
        // every key, so guard on a non-empty persona DID.
        let persona_did = config.persona_did();
        self.content_panel.vta.persona_key_count = if persona_did.is_empty() {
            0
        } else {
            config
                .key_info
                .keys()
                .filter(|k| k.starts_with(persona_did))
                .count()
        };
        self.content_panel.vta.relationship_key_count =
            self.content_panel.vta.key_count - self.content_panel.vta.persona_key_count;
        // Collect active DIDs — none for a zero-persona (State-A) account.
        let mut active_dids = Vec::new();
        if !persona_did.is_empty() {
            active_dids.push(content::ActiveDid {
                did: persona_did.to_string(),
                label: "Persona".to_string(),
            });
        }
        for (remote_p_did, rel) in &config.private.relationships.relationships {
            if !config.is_persona_did(rel.our_did.as_str()) {
                let alias = config
                    .private
                    .contacts
                    .find_contact(remote_p_did)
                    .and_then(|c| c.alias.clone())
                    .unwrap_or_else(|| shorten_did(remote_p_did, 30));
                active_dids.push(content::ActiveDid {
                    did: rel.our_did.to_string(),
                    label: format!("R-DID ({})", alias),
                });
            }
        }
        self.content_panel.vta.active_dids = active_dids.into();

        // Context identities: every persona in the account, with how many
        // communities present it. A persona bound to zero communities is an
        // orphan (e.g. left by a failed join before the rollback fix) —
        // surfaced so the operator can spot and manage it.
        let mut context_dids: Vec<content::ManagedDid> = config
            .account
            .personas
            .values()
            .map(|p| content::ManagedDid {
                did: p.did.clone(),
                label: p.label.clone().unwrap_or_default(),
                bound_communities: config.account.memberships()
                    .filter(|c| c.persona_ref == p.persona_id)
                    .count(),
                is_active: p.did.as_str() == persona_did,
            })
            .collect();
        context_dids.sort_by(|a, b| a.did.cmp(&b.did));
        self.content_panel.vta.context_dids = context_dids.into();

        self.content_panel.settings.protection_type = match &config.public.protection {
            openvtc_core::config::ConfigProtectionType::Token(id) => {
                format!(
                    "Hardware Token ({})",
                    if id.len() > 20 { &id[..20] } else { id }
                )
            }
            openvtc_core::config::ConfigProtectionType::Encrypted => {
                "Passphrase Encrypted".to_string()
            }
            openvtc_core::config::ConfigProtectionType::Plaintext => {
                "Keyring Only (no additional encryption)".to_string()
            }
        };

        // Sync the Communities overview (R-C-*): display order from the model,
        // archived excluded, with the actions-required count for the badge.
        let mut community_items = Vec::new();
        let show_archived = self.content_panel.communities.show_archived;
        let now = chrono::Utc::now();
        for c in config.account.communities_for_display(show_archived) {
            let persona = config.account.personas.get(&c.persona_ref);
            let persona_label = persona
                .and_then(|p| p.label.clone())
                .or_else(|| persona.map(|p| shorten_did(&p.did, 24)))
                .unwrap_or_default();
            let request_id = match &c.status {
                openvtc_core::config::account::CommunityStatus::Pending { request_id } => {
                    request_id.to_string()
                }
                _ => String::new(),
            };
            community_items.push(content::CommunitySummary {
                display_name: c
                    .display_name
                    .clone()
                    .unwrap_or_else(|| shorten_did(&c.vtc_did, 40)),
                status_label: community_status_label(&c.status),
                persona_label,
                member_since: c
                    .member_since
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default(),
                favourite: c.favourite,
                is_active: c.status.is_active(),
                is_inactive: c.status.is_inactive(),
                is_pending: matches!(
                    c.status,
                    openvtc_core::config::account::CommunityStatus::Pending { .. }
                ),
                pending_unacknowledged: c.pending_unacknowledged(now),
                archived: c.archived,
                needs_attention: c.needs_attention(),
                persona_did: persona.map(|p| p.did.clone()).unwrap_or_default(),
                vtc_did: c.vtc_did.clone(),
                sub_context_id: c.sub_context_id.clone(),
                request_id,
                has_membership_credential: c
                    .credentials
                    .contains_key(&openvtc_core::CredentialKind::Membership),
                has_role_credential: c
                    .credentials
                    .contains_key(&openvtc_core::CredentialKind::Role),
            });
        }
        let community_count = community_items.len();
        self.content_panel.communities.actions_required = config.account.actions_required_count();
        self.content_panel.communities.items = community_items.into();
        if self.content_panel.communities.selected_index >= community_count {
            self.content_panel.communities.selected_index = community_count.saturating_sub(1);
        }
    }
}

/// Human-readable label for a community membership status (R-C-2).
fn community_status_label(status: &openvtc_core::config::account::CommunityStatus) -> String {
    use openvtc_core::config::account::CommunityStatus;
    match status {
        CommunityStatus::Pending { .. } => "Pending",
        CommunityStatus::Active => "Active",
        CommunityStatus::Left => "Left",
        CommunityStatus::Withdrawn => "Withdrawn",
        CommunityStatus::Rejected => "Rejected",
        CommunityStatus::Removed => "Removed",
        CommunityStatus::Expired => "Expired",
    }
    .to_string()
}

/// Collect VRC summaries from a Vrcs collection.
#[must_use]
fn collect_vrcs(
    vrcs: &openvtc_core::vrc::Vrcs,
    config: &Config,
    active_persona: Option<PersonaId>,
    persona_count: usize,
) -> Vec<VrcSummary> {
    let mut result = Vec::new();
    for remote_p_did in vrcs.keys() {
        // Scope to the working community: a VRC belongs to the community of the
        // relationship with its remote party (D10 / R-C-6).
        let rel_persona = config
            .private
            .relationships
            .get(remote_p_did)
            .and_then(|r| r.our_persona);
        if !persona_in_scope(rel_persona, active_persona, persona_count) {
            continue;
        }
        let alias = config
            .private
            .contacts
            .find_contact(remote_p_did)
            .and_then(|c| c.alias.clone());
        if let Some(vrc_map) = vrcs.get(remote_p_did) {
            for (vrc_id, vrc) in vrc_map {
                // Defer pretty-printing to detail-view render time; share the
                // credential by Arc pointer (it is already `Arc`-held in config).
                let raw_json = content::RawCredential::Vrc(Arc::clone(vrc));
                result.push(VrcSummary {
                    vrc_id: vrc_id.to_string(),
                    remote_p_did: sanitize_display(remote_p_did, 256),
                    raw_json,
                    alias: alias.as_deref().map(|a| sanitize_display(a, 256)),
                    issuer: sanitize_display(vrc.issuer(), 256),
                    subject: sanitize_display(vrc.subject(), 256),
                    valid_from: vrc.valid_from().format("%Y-%m-%d").to_string(),
                    valid_until: vrc.valid_until().map(|d| d.format("%Y-%m-%d").to_string()),
                });
            }
        }
    }
    result
}

/// Build display summaries for the membership (VMC) + role (VEC) credentials a
/// VTC issued to us, stored on each community record. Reuses [`VrcSummary`]:
/// `alias` carries "<community> — Membership/Role" and `remote_p_did` the VTC.
fn collect_membership_creds(config: &Config) -> Vec<VrcSummary> {
    let mut result = Vec::new();
    for c in config.account.memberships() {
        let community = c
            .display_name
            .clone()
            .unwrap_or_else(|| sanitize_display(&c.vtc_did, 64));
        for kind in openvtc_core::CredentialKind::ALL {
            let Some(vc) = c.credentials.get(kind) else {
                continue;
            };
            // `issuer` may be a bare string or an object `{ id, ... }`.
            let issuer = vc
                .get("issuer")
                .and_then(|i| {
                    i.as_str()
                        .map(str::to_string)
                        .or_else(|| i.get("id").and_then(|x| x.as_str()).map(str::to_string))
                })
                .unwrap_or_default();
            let subject = vc
                .pointer("/credentialSubject/id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let valid_from = vc
                .get("validFrom")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let valid_until = vc
                .get("validUntil")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let vc_id = vc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            // Defer pretty-printing to detail-view render time. Share the
            // already-parsed JSON value by Arc pointer (a `serde_json::Value`
            // pretty-prints identically whether done now or later).
            let raw_json = content::RawCredential::Value(Arc::new(vc.clone()));
            result.push(VrcSummary {
                vrc_id: vc_id,
                remote_p_did: sanitize_display(&c.vtc_did, 256),
                raw_json,
                alias: Some(format!("{community} — {}", kind.config_key())),
                issuer: sanitize_display(&issuer, 256),
                subject: sanitize_display(&subject, 256),
                valid_from,
                valid_until,
            });
        }
    }
    result
}

/// Returns true for unicode codepoints that can spoof or mangle TUI
/// display when rendered: bidirectional overrides, isolates, zero-width
/// spaces/joiners, BOM. These are silently stripped by [`sanitize_display`].
fn is_dangerous_format_char(c: char) -> bool {
    matches!(
        c as u32,
        // Bidi marks, embeddings, overrides
        0x200E | 0x200F |               // LRM, RLM
        0x202A..=0x202E |               // LRE, RLE, PDF, LRO, RLO
        0x2066..=0x2069 |               // LRI, RLI, FSI, PDI
        // Zero-width space / joiner / non-joiner
        0x200B..=0x200D |
        0xFEFF                          // BOM / zero-width non-breaking space
    )
}

/// Sanitize a string from an untrusted source for safe terminal display
/// and persistence (e.g. contact aliases captured from inbound messages).
///
/// Strips, in order:
///   1. ANSI CSI escape sequences (ESC `[` … letter pattern)
///   2. Other ASCII control characters, keeping space
///   3. Bidi-override / zero-width / BOM characters that allow visual
///      spoofing (e.g. RLO-flipping a contact alias to display text the
///      operator didn't approve).
///
/// Truncates to `max_len` *characters* (not bytes).
#[must_use]
pub fn sanitize_display(input: &str, max_len: usize) -> String {
    let mut stripped = String::with_capacity(input.len());
    let mut in_escape = false;
    for c in input.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        stripped.push(c);
    }
    stripped
        .chars()
        .filter(|c| (!c.is_control() || *c == ' ') && !is_dangerous_format_char(*c))
        .take(max_len)
        .collect()
}

/// Detect a did-git-sign install for the given persona DID by reading its
/// global SigningConfig and the matching allowed_signers entry. Returns
/// `None` if did-git-sign is not configured for this persona, or if the
/// state on disk is malformed.
///
/// Reads files synchronously and is cheap (single small file open + read).
/// Sourced from disk rather than re-derived from runtime key material so
/// the help screen reflects what `did-git-sign` itself would actually use
/// — i.e. if the config was hand-edited, the help view stays consistent
/// with the install.
fn detect_did_git_sign_info(persona_did: &str) -> Option<DidGitSignInfo> {
    let config_path = did_git_sign::config::SigningConfig::default_global_path().ok()?;
    let cfg = did_git_sign::config::SigningConfig::load(&config_path).ok()?;

    // Only show on the help screen if the configured signing identity
    // belongs to this persona. Avoids leaking another persona's keys when
    // multiple openvtc profiles share a host.
    let prefix = format!("{persona_did}#");
    if !cfg.did_key_id.starts_with(&prefix) {
        return None;
    }

    // Lift the SSH public key out of allowed_signers, which lives next to
    // the config and is written by `init::install`. Format is one entry
    // per line: `<principal> ssh-ed25519 <base64>`.
    let signers_path = config_path.parent()?.join("allowed_signers");
    let signers = std::fs::read_to_string(&signers_path).ok()?;
    let entry_prefix = format!("{} ssh-ed25519 ", cfg.did_key_id);
    let ssh_public_key = signers.lines().find_map(|line| {
        let line = line.trim();
        line.starts_with(&entry_prefix)
            .then(|| line.trim_start_matches(&cfg.did_key_id).trim().to_string())
    })?;

    Some(DidGitSignInfo {
        did_key_id: cfg.did_key_id,
        ssh_public_key,
        config_path: config_path.display().to_string(),
    })
}

/// Shortens a DID for display, fitting within `max_width` characters.
/// Sanitises first to drop ANSI / control bytes from untrusted input,
/// then delegates to the canonical tail-truncate helper.
#[must_use]
pub(crate) fn shorten_did(did: &str, max_width: usize) -> String {
    let sanitized = sanitize_display(did, 256);
    truncate_did(&sanitized, max_width).into_owned()
}

/// Contains config information that is shown in the main menu header
#[derive(Clone, Debug, Default)]
pub struct MainMenuConfigState {
    pub name: String,
    pub did: Arc<String>,
    /// Display name of the working (active) community, shown top-left (R-C-7a).
    /// Empty when there is no active community.
    pub community: String,
}

impl From<&Box<Config>> for MainMenuConfigState {
    fn from(config: &Box<Config>) -> Self {
        MainMenuConfigState::from(config.as_ref())
    }
}

impl From<&Config> for MainMenuConfigState {
    fn from(config: &Config) -> Self {
        // The persona identity is community-scoped: only surface it in the top
        // bar once the user is actually in a community (an Active membership). A
        // State-A account or a still-Pending join shows no persona name/DID up
        // there — the persona belongs to a community context, not the chrome.
        let in_community = config.account.memberships()
            .any(|c| c.status.is_active());
        // The working community (R-C-7a): the Active community whose persona is
        // the active one. `active_persona` is kept in lockstep with the selected
        // working community (set at launch, on reconcile, and on switch), so the
        // header name matches the persona that scopes the panels. In the rare
        // persona-reuse case (one persona across several Active communities) the
        // first in display order is shown — those communities share a context.
        let community = config
            .active_persona
            .and_then(|persona| {
                config
                    .account
                    .communities_for_display(false)
                    .into_iter()
                    .find(|c| c.status.is_active() && c.persona_ref == persona)
                    .map(|c| {
                        c.display_name
                            .clone()
                            .unwrap_or_else(|| shorten_did(&c.vtc_did, 40))
                    })
            })
            .unwrap_or_default();
        MainMenuConfigState {
            name: if in_community {
                config.public.friendly_name.clone()
            } else {
                String::new()
            },
            did: if in_community {
                config.persona_did_arc()
            } else {
                Arc::new(String::new())
            },
            community,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub enum MainPanel {
    #[default]
    MainMenu,
    ContentPanel,
}

impl MainPanel {
    /// Switches to the next panel when pressing `TAB`
    #[allow(dead_code)]
    pub fn switch(&self) -> Self {
        match self {
            MainPanel::MainMenu => MainPanel::ContentPanel,
            MainPanel::ContentPanel => MainPanel::MainMenu,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- persona_in_scope (community-scoping filter, D10/R-C-6) ---

    #[test]
    fn persona_in_scope_filters_by_active_persona() {
        let a = PersonaId::new();
        let b = PersonaId::new();

        // With a selection, only the active persona's items (and untagged items
        // in a single-persona account) are in scope.
        assert!(persona_in_scope(Some(a), Some(a), 2));
        assert!(!persona_in_scope(Some(b), Some(a), 2));
        // Untagged item: hidden when multiple personas (ambiguous)...
        assert!(!persona_in_scope(None, Some(a), 2));
        // ...but shown in a single-persona account (no ambiguity).
        assert!(persona_in_scope(None, Some(a), 1));

        // No active selection: only the single/zero-persona case shows items.
        assert!(persona_in_scope(Some(a), None, 1));
        assert!(persona_in_scope(None, None, 1));
        assert!(!persona_in_scope(Some(a), None, 2));
        assert!(!persona_in_scope(None, None, 2));
    }

    // --- sanitize_display ---

    #[test]
    fn test_sanitize_display_strips_control_chars() {
        assert_eq!(sanitize_display("hello\x00world", 256), "helloworld");
        assert_eq!(sanitize_display("hello\nworld", 256), "helloworld");
    }

    #[test]
    fn test_sanitize_display_strips_ansi_escapes() {
        assert_eq!(sanitize_display("\x1b[31mred\x1b[0m", 256), "red");
    }

    #[test]
    fn test_sanitize_display_truncates() {
        let long = "a".repeat(300);
        let result = sanitize_display(&long, 10);
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_sanitize_display_preserves_spaces() {
        assert_eq!(sanitize_display("hello world", 256), "hello world");
    }

    #[test]
    fn test_sanitize_display_empty_input() {
        assert_eq!(sanitize_display("", 256), "");
    }

    // --- shorten_did ---

    #[test]
    fn test_shorten_did_short_input() {
        let short = "did:test:abc";
        let result = shorten_did(short, 60);
        assert_eq!(result, short); // fits within 60 chars
    }

    #[test]
    fn test_shorten_did_long_input() {
        let long = "did:test:abcdefghijklmnopqrstuvwxyz";
        let result = shorten_did(long, 20);
        assert!(result.ends_with("..."));
        assert!(result.len() <= 20);
    }

    #[test]
    fn test_shorten_did_exact_fit() {
        let did = "did:test:exactly30charslongXXX";
        let result = shorten_did(did, 30);
        assert_eq!(result.len(), did.len()); // exactly fits
    }

    // --- MainPageState::log ---

    #[test]
    fn test_activity_log_bounded() {
        let mut state = MainPageState::default();
        for i in 0..MAX_ACTIVITY_LOG_ENTRIES + 10 {
            state.log(format!("entry-{}", i));
        }
        assert_eq!(state.activity_log.len(), MAX_ACTIVITY_LOG_ENTRIES);
        // Oldest entries should have been dropped
        assert!(
            state
                .activity_log
                .front()
                .unwrap()
                .summary
                .contains("entry-10")
        );
    }

    // --- MainPanel::switch ---

    #[test]
    fn test_main_panel_switch() {
        let panel = MainPanel::MainMenu;
        assert!(matches!(panel.switch(), MainPanel::ContentPanel));
        let panel = MainPanel::ContentPanel;
        assert!(matches!(panel.switch(), MainPanel::MainMenu));
    }

    // --- RawCredential lazy rendering (Part 2) ---

    /// The lazy `RawCredential::Vrc` path must pretty-print byte-identically to
    /// the previous eager `serde_json::to_string_pretty(vrc.credential())`.
    #[test]
    fn test_raw_credential_vrc_matches_eager_output() {
        use chrono::{TimeZone, Utc};
        use dtg_credentials::DTGCredential;

        let valid_from = Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap();
        let vrc = DTGCredential::new_vrc(
            "did:test:issuer".to_string(),
            "did:test:subject".to_string(),
            valid_from,
            Some(Utc.with_ymd_and_hms(2025, 6, 7, 8, 9, 10).unwrap()),
        );
        // Old eager output, computed exactly as `sync_from_config` used to.
        let eager = serde_json::to_string_pretty(vrc.credential()).unwrap();

        let lazy = content::RawCredential::Vrc(Arc::new(vrc)).to_pretty_json();
        assert_eq!(lazy, eager, "lazy VRC JSON must match the old eager output");
    }

    /// The lazy `RawCredential::Value` path (membership/role credentials) must
    /// pretty-print byte-identically to the previous eager
    /// `serde_json::to_string_pretty(vc)`.
    #[test]
    fn test_raw_credential_value_matches_eager_output() {
        let vc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:test:vtc",
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:test:member", "role": "member" }
        });
        let eager = serde_json::to_string_pretty(&vc).unwrap();

        let lazy = content::RawCredential::Value(Arc::new(vc)).to_pretty_json();
        assert_eq!(
            lazy, eager,
            "lazy membership JSON must match the old eager output"
        );
    }

    // --- Arc pointer-bump cloning (Part 1) ---

    /// Cloning `MainPageState` must share the Arc-wrapped heavy collections by
    /// pointer (a pointer bump), not deep-copy them — that is the whole point of
    /// the per-event clone optimisation.
    #[test]
    fn test_clone_shares_arc_data() {
        let mut state = MainPageState::default();
        // Populate the Arc-wrapped collections with non-empty data so the
        // pointer identity is meaningful.
        state.content_panel.inbox.tasks = vec![TaskSummary {
            id: "t1".to_string(),
            type_display: "Test".to_string(),
            kind: TaskKind::Informational("x".to_string()),
            remote_did: "did:test:remote".to_string(),
            created: "2024-01-01 00:00".to_string(),
        }]
        .into();
        state.log_detailed("summary", "detail");

        let clone = state.clone();

        // Heavy vectors share the same allocation.
        assert!(
            Arc::ptr_eq(
                &state.content_panel.inbox.tasks,
                &clone.content_panel.inbox.tasks
            ),
            "inbox tasks must be shared by pointer after clone"
        );
        // Activity-log entries share the same allocation (per-entry Arc).
        assert!(
            Arc::ptr_eq(
                state.activity_log.front().unwrap(),
                clone.activity_log.front().unwrap()
            ),
            "activity log entries must be shared by pointer after clone"
        );
    }
}
