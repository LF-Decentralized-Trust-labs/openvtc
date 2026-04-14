use std::sync::Arc;

use openvtc::{config::Config, tasks::TaskType};

use crate::state_handler::main_page::{
    content::{ContentPanelState, RelationshipSummary, TaskKind, TaskSummary, VrcSummary},
    menu::MenuPanelState,
};

pub mod content;
pub mod menu;

/// Holds all state related info for the main page
#[derive(Clone, Debug, Default)]
pub struct MainPageState {
    /// State related to the menu panel
    pub menu_panel: MenuPanelState,

    /// State related to the content panel
    pub content_panel: ContentPanelState,

    pub config: MainMenuConfigState,
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
                            from_did: from.to_string(),
                            their_did: request.did.clone(),
                            reason: request.reason.clone(),
                        }
                    }
                    TaskType::RelationshipRequestOutbound { .. } => {
                        TaskKind::RelationshipRequestOutbound
                    }
                    TaskType::VRCRequestInbound { request, .. } => TaskKind::VRCRequestInbound {
                        reason: request.reason.clone(),
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
                    TaskType::RelationshipRequestInbound { from, .. } => shorten_did(from),
                    TaskType::RelationshipRequestOutbound { to } => shorten_did(to),
                    TaskType::TrustPing { to, .. } => shorten_did(to),
                    _ => String::new(),
                };
                Some(TaskSummary {
                    id: task.id.to_string(),
                    type_display: task.type_.to_string(),
                    kind,
                    remote_did,
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
                    remote_p_did: remote_p_did.to_string(),
                    alias,
                    state: rel.state.to_string(),
                    our_did: rel.our_did.to_string(),
                    remote_did: rel.remote_did.to_string(),
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
                    remote_p_did: remote_p_did.to_string(),
                    alias: alias.clone(),
                    issuer: vrc.issuer().to_string(),
                    subject: vrc.subject().to_string(),
                    valid_from: vrc.valid_from().format("%Y-%m-%d").to_string(),
                    valid_until: vrc.valid_until().map(|d| d.format("%Y-%m-%d").to_string()),
                });
            }
        }
    }
    result
}

/// Shortens a DID for display (first 20 chars + "...").
fn shorten_did(did: &str) -> String {
    if did.len() > 24 {
        format!("{}...", &did[..20])
    } else {
        did.to_string()
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
