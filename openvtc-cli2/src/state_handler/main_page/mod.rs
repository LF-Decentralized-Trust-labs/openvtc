use std::collections::VecDeque;
use std::sync::Arc;

use openvtc::{config::Config, tasks::TaskType};

use crate::state_handler::main_page::{
    content::{ContentPanelState, RelationshipSummary, TaskKind, TaskSummary, VrcSummary},
    menu::MenuPanelState,
};

pub mod content;
pub mod menu;

/// Maximum number of activity log entries to keep in the UI.
const MAX_ACTIVITY_LOG_ENTRIES: usize = 100;

#[derive(Clone, Debug, Default)]
pub struct MainPageState {
    /// State related to the menu panel
    pub menu_panel: MenuPanelState,

    /// State related to the content panel
    pub content_panel: ContentPanelState,

    pub config: MainMenuConfigState,

    /// Activity log entries shown in the bottom panel (newest last).
    pub activity_log: VecDeque<String>,
}

impl MainPageState {
    /// Push a new entry to the activity log (O(1) bounded insertion).
    pub fn log(&mut self, message: impl Into<String>) {
        if self.activity_log.len() >= MAX_ACTIVITY_LOG_ENTRIES {
            self.activity_log.pop_front();
        }
        self.activity_log.push_back(message.into());
    }
}

impl MainPageState {
    /// Rebuilds all display state from the current Config.
    ///
    /// Called after Config is loaded at startup and after every Config mutation
    /// (message processing, user actions, etc.).
    pub fn sync_from_config(&mut self, config: &Config) {
        // Update header config
        self.config = MainMenuConfigState::from(config);

        // Sync inbox tasks
        self.content_panel.inbox.tasks = config
            .private
            .tasks
            .tasks
            .values()
            .filter_map(|task_arc| {
                let task = task_arc.lock().ok()?;
                let kind = match &task.type_ {
                    TaskType::RelationshipRequestInbound { from, request, .. } => {
                        TaskKind::RelationshipRequestInbound {
                            from_did: sanitize_display(from, 256),
                            their_did: sanitize_display(&request.did, 256),
                            reason: request.reason.as_deref().map(|r| sanitize_display(r, 256)),
                            name: request.name.as_deref().map(|n| sanitize_display(n, 256)),
                        }
                    }
                    TaskType::RelationshipRequestOutbound { .. } => {
                        TaskKind::RelationshipRequestOutbound
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
                            shorten_did(from)
                        }
                    }
                    TaskType::RelationshipRequestOutbound { to } => shorten_did(to),
                    TaskType::TrustPing { to, .. } => shorten_did(to),
                    TaskType::VRCRequestInbound { relationship, .. } => {
                        if let Ok(lock) = relationship.lock() {
                            shorten_did(&lock.remote_p_did)
                        } else {
                            String::new()
                        }
                    }
                    TaskType::VRCRequestOutbound { relationship } => {
                        if let Ok(lock) = relationship.lock() {
                            shorten_did(&lock.remote_p_did)
                        } else {
                            String::new()
                        }
                    }
                    TaskType::VRCIssued { vrc } => sanitize_display(vrc.issuer(), 40),
                    _ => String::new(),
                };
                Some(TaskSummary {
                    id: task.id.to_string(),
                    type_display: task.type_.to_string(),
                    kind,
                    remote_did: sanitize_display(&remote_did, 256),
                    created: task.created.format("%Y-%m-%d %H:%M").to_string(),
                })
            })
            .collect();
        // Sort tasks by most recent first
        self.content_panel
            .inbox
            .tasks
            .sort_by(|a, b| b.created.cmp(&a.created));

        // Sync relationships
        self.content_panel.relationships.relationships = config
            .private
            .relationships
            .relationships
            .iter()
            .filter_map(|(remote_p_did, rel_arc)| {
                let rel = rel_arc.lock().ok()?;
                let alias = config
                    .private
                    .contacts
                    .find_contact(remote_p_did)
                    .and_then(|c| c.alias.clone());
                let vrc_sent = config
                    .private
                    .vrcs_issued
                    .get(remote_p_did)
                    .map_or(0, |m| m.len());
                let vrc_received = config
                    .private
                    .vrcs_received
                    .get(remote_p_did)
                    .map_or(0, |m| m.len());
                Some(RelationshipSummary {
                    remote_p_did: sanitize_display(remote_p_did, 256),
                    alias: alias.as_deref().map(|a| sanitize_display(a, 256)),
                    state: rel.state.to_string(),
                    our_did: rel.our_did.to_string(),
                    remote_did: sanitize_display(&rel.remote_did, 256),
                    created: rel.created.format("%Y-%m-%d %H:%M").to_string(),
                    vrc_sent_count: vrc_sent,
                    vrc_received_count: vrc_received,
                })
            })
            .collect();

        // Sync credentials
        self.content_panel.credentials.received =
            collect_vrcs(&config.private.vrcs_received, config);
        self.content_panel.credentials.issued = collect_vrcs(&config.private.vrcs_issued, config);

        // Sync settings
        self.content_panel.settings.friendly_name = config.public.friendly_name.clone();
        self.content_panel.settings.mediator_did = config.public.mediator_did.clone();
        self.content_panel.settings.org_did = config.public.lk_did.clone();
        self.content_panel.settings.persona_did = config.public.persona_did.to_string();
        self.content_panel.settings.protection_type = match &config.public.protection {
            openvtc::config::ConfigProtectionType::Token(id) => {
                format!(
                    "Hardware Token ({})",
                    if id.len() > 20 { &id[..20] } else { id }
                )
            }
            openvtc::config::ConfigProtectionType::Encrypted => "Passphrase Encrypted".to_string(),
            openvtc::config::ConfigProtectionType::Plaintext => {
                "Keyring Only (no additional encryption)".to_string()
            }
        };
    }
}

/// Collect VRC summaries from a Vrcs collection.
#[must_use]
fn collect_vrcs(vrcs: &openvtc::vrc::Vrcs, config: &Config) -> Vec<VrcSummary> {
    let mut result = Vec::new();
    for remote_p_did in vrcs.keys() {
        let alias = config
            .private
            .contacts
            .find_contact(remote_p_did)
            .and_then(|c| c.alias.clone());
        if let Some(vrc_map) = vrcs.get(remote_p_did) {
            for (vrc_id, vrc) in vrc_map {
                result.push(VrcSummary {
                    vrc_id: vrc_id.to_string(),
                    remote_p_did: sanitize_display(remote_p_did, 256),
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

/// Sanitize a string from an untrusted source for safe terminal display.
/// Strips ANSI escape codes and control characters, truncates to max_len.
///
/// ANSI escape sequences are stripped first so that the bracket-parameter
/// remnants (e.g. `[31m`) are not left behind when the ESC byte is removed.
#[must_use]
pub fn sanitize_display(input: &str, max_len: usize) -> String {
    // Pass 1: strip ANSI escape sequences (ESC [ ... letter pattern)
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
    // Pass 2: remove remaining control characters (keep spaces), then truncate
    stripped
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max_len)
        .collect()
}

/// Shortens a DID for display (first 20 chars + "...").
#[must_use]
fn shorten_did(did: &str) -> String {
    let sanitized = sanitize_display(did, 256);
    if sanitized.len() > 24 {
        format!("{}...", &sanitized[..20])
    } else {
        sanitized
    }
}

/// Contains config information that is shown in the main menu header
#[derive(Clone, Debug, Default)]
pub struct MainMenuConfigState {
    pub name: String,
    pub did: Arc<String>,
}

impl From<&Box<Config>> for MainMenuConfigState {
    fn from(config: &Box<Config>) -> Self {
        MainMenuConfigState {
            name: config.public.friendly_name.clone(),
            did: config.public.persona_did.clone(),
        }
    }
}

impl From<&Config> for MainMenuConfigState {
    fn from(config: &Config) -> Self {
        MainMenuConfigState {
            name: config.public.friendly_name.clone(),
            did: config.public.persona_did.clone(),
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
        let result = shorten_did(short);
        assert_eq!(result, short); // not shortened
    }

    #[test]
    fn test_shorten_did_long_input() {
        let long = "did:test:abcdefghijklmnopqrstuvwxyz";
        let result = shorten_did(long);
        assert!(result.ends_with("..."));
        assert!(result.len() < long.len());
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
        assert!(state.activity_log.front().unwrap().contains("entry-10"));
    }

    // --- MainPanel::switch ---

    #[test]
    fn test_main_panel_switch() {
        let panel = MainPanel::MainMenu;
        assert!(matches!(panel.switch(), MainPanel::ContentPanel));
        let panel = MainPanel::ContentPanel;
        assert!(matches!(panel.switch(), MainPanel::MainMenu));
    }
}
