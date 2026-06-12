use crate::colors::{
    COLOR_BORDER, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::{
    state_handler::{
        actions::{Action, CredentialAction, InboxAction, RelationshipAction, SettingsAction},
        main_page::{MainPageState, MainPanel, content::ActiveTaskView, menu::MainMenu},
        state::{ConnectionState, MediatorStatus, State},
    },
    ui::component::{Component, ComponentRender},
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use openvtc_core::display::truncate_did_centered;
use ratatui::{
    Frame,
    layout::{
        Alignment,
        Constraint::{Length, Min, Percentage},
        Layout,
    },
    style::Stylize,
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{Block, Paragraph},
};
use std::cell::Cell;
use tokio::sync::mpsc::UnboundedSender;

pub mod components;

/// MainPage handles the UI and the state of the primary openvtc interface
pub struct MainPage {
    /// Action sender
    pub action_tx: UnboundedSender<Action>,

    /// State Mapped MainPage Props
    props: Props,

    /// Secure passphrase buffer — never cloned into State
    passphrase_buffer: String,
    /// Secure confirm passphrase buffer — never cloned into State
    confirm_buffer: String,
    /// Logs panel selected index (local to UI, not in State)
    logs_selected: usize,
    /// Whether the logs panel is showing the detail view of a selected entry
    logs_detail_view: bool,
    /// Vertical scroll offset (in wrapped lines) applied to the content panel.
    /// Mutated by the key handler; clamped at render time.
    content_scroll: u16,
    /// Max reachable scroll offset from the most recent render — written by
    /// render (via `Cell`) and read by the key handler to clamp PageDown/End.
    content_scroll_max: Cell<u16>,
    /// Identifier for the active content view (menu + mode). When it changes
    /// across frames, we reset `content_scroll` so a fresh view starts at top.
    last_view_id: String,
}

/// Number of lines to scroll per PageUp / PageDown press.
const CONTENT_PAGE: u16 = 10;

struct Props {
    main_page: MainPageState,
    connection: ConnectionState,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            main_page: state.main_page.clone(),
            connection: state.connection.clone(),
        }
    }
}

impl Component for MainPage {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        MainPage {
            action_tx: action_tx.clone(),
            // set the props
            props: Props::from(state),
            passphrase_buffer: String::new(),
            confirm_buffer: String::new(),
            logs_selected: 0,
            logs_detail_view: false,
            content_scroll: 0,
            content_scroll_max: Cell::new(0),
            last_view_id: view_id(&state.main_page),
        }
        .move_with_state(state)
    }

    fn move_with_state(mut self, state: &State) -> Self
    where
        Self: Sized,
    {
        let new_id = view_id(&state.main_page);
        if new_id != self.last_view_id {
            // Switching menu or mode (e.g. list → detail) starts the new view
            // at the top, even if the previous view was scrolled down.
            self.content_scroll = 0;
            self.last_view_id = new_id;
        }
        self.props = Props::from(state);
        self
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Content panel key handling (when content panel is focused)
        let content_selected = self.props.main_page.content_panel.selected;
        if content_selected && self.handle_content_key_event(key) {
            return;
        }

        match key.code {
            KeyCode::F(10) => {
                let _ = self.action_tx.send(Action::Exit);
            }
            KeyCode::Up if self.props.main_page.menu_panel.selected => {
                let _ = self.action_tx.send(Action::MainMenuSelected(
                    self.props.main_page.menu_panel.selected_menu.prev(),
                ));
            }
            KeyCode::Down if self.props.main_page.menu_panel.selected => {
                let _ = self.action_tx.send(Action::MainMenuSelected(
                    self.props.main_page.menu_panel.selected_menu.next(),
                ));
            }
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                let next_panel = match self.props.main_page.menu_panel.selected {
                    true => MainPanel::ContentPanel,
                    false => MainPanel::MainMenu,
                };
                let _ = self.action_tx.send(Action::MainPanelSwitch(next_panel));
            }
            KeyCode::Enter => {
                if self.props.main_page.menu_panel.selected_menu == MainMenu::Quit {
                    let _ = self.action_tx.send(Action::Exit);
                } else if self.props.main_page.menu_panel.selected {
                    let _ = self
                        .action_tx
                        .send(Action::MainPanelSwitch(MainPanel::ContentPanel));
                }
            }
            _ => {}
        }
    }

    fn handle_paste_event(&mut self, text: &str) {
        use crate::state_handler::main_page::content::{
            CredentialsMode, RelationshipsMode, SettingsMode,
        };

        if !self.props.main_page.content_panel.selected {
            return;
        }

        let menu = self.props.main_page.menu_panel.selected_menu.clone();
        let trimmed = text.trim();

        match menu {
            MainMenu::Relationships => {
                if let RelationshipsMode::EditAlias { alias_input, .. } =
                    &self.props.main_page.content_panel.relationships.mode
                {
                    let updated = format!("{}{}", alias_input, trimmed);
                    let _ = self.action_tx.send(Action::Relationship(
                        RelationshipAction::EditAliasUpdate(updated),
                    ));
                    return;
                }
                if let RelationshipsMode::NewRequest {
                    did_input,
                    alias_input,
                    reason_input,
                    active_field,
                    ..
                } = &self.props.main_page.content_panel.relationships.mode
                {
                    // Paste into the currently active field
                    let current = match active_field {
                        0 => format!("{}{}", did_input, trimmed),
                        1 => format!("{}{}", alias_input, trimmed),
                        2 => format!("{}{}", reason_input, trimmed),
                        _ => return,
                    };
                    let _ = self.action_tx.send(Action::Relationship(
                        RelationshipAction::InputUpdate {
                            field: *active_field,
                            value: current,
                        },
                    ));
                }
            }
            MainMenu::Credentials => {
                if let CredentialsMode::NewRequest { reason_input, .. } =
                    &self.props.main_page.content_panel.credentials.mode
                {
                    let updated = format!("{}{}", reason_input, trimmed);
                    let _ = self
                        .action_tx
                        .send(Action::Credential(CredentialAction::ReasonUpdate(updated)));
                }
            }
            MainMenu::Settings => {
                match &self.props.main_page.content_panel.settings.mode {
                    SettingsMode::EditFriendlyName { input }
                    | SettingsMode::EditMediatorDid { input }
                    | SettingsMode::EditOrgDid { input } => {
                        let updated = format!("{}{}", input, trimmed);
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::FieldUpdate(updated)));
                    }
                    SettingsMode::ExportConfig {
                        path_input,
                        active_field,
                        ..
                    }
                    | SettingsMode::ImportConfig {
                        path_input,
                        active_field,
                        ..
                    } => {
                        if *active_field == 0 {
                            let updated = format!("{}{}", path_input, trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate {
                                    field: 0,
                                    value: updated,
                                },
                            ));
                        } else {
                            // Passphrase field — append to secure buffer
                            self.passphrase_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::PassphraseLen(self.passphrase_buffer.len()),
                            ));
                        }
                    }
                    SettingsMode::ChangeProtection { active_field, .. } => {
                        if *active_field == 1 {
                            self.passphrase_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionPassphraseLen(
                                    self.passphrase_buffer.len(),
                                ),
                            ));
                        } else if *active_field == 2 {
                            self.confirm_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionConfirmLen(self.confirm_buffer.len()),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// ****************************************************************************
// Content panel key event handling
// ****************************************************************************
impl MainPage {
    /// Handle key events when the content panel is focused.
    /// Returns true if the event was consumed.
    fn handle_content_key_event(&mut self, key: KeyEvent) -> bool {
        // Vertical scroll for the content panel is handled centrally here,
        // before per-menu dispatch, so it works uniformly on every view
        // without conflicting with Up/Down selection bindings.
        match key.code {
            KeyCode::PageUp => {
                let max = self.content_scroll_max.get();
                let cur = self.content_scroll.min(max);
                self.content_scroll = cur.saturating_sub(CONTENT_PAGE);
                return true;
            }
            KeyCode::PageDown => {
                let max = self.content_scroll_max.get();
                self.content_scroll = self.content_scroll.saturating_add(CONTENT_PAGE).min(max);
                return true;
            }
            KeyCode::Home => {
                self.content_scroll = 0;
                return true;
            }
            KeyCode::End => {
                self.content_scroll = self.content_scroll_max.get();
                return true;
            }
            _ => {}
        }

        let menu = self.props.main_page.menu_panel.selected_menu.clone();

        match menu {
            MainMenu::Inbox => self.handle_inbox_key(key),
            MainMenu::Relationships => self.handle_relationships_key(key),
            MainMenu::Credentials => self.handle_credentials_key(key),
            MainMenu::Settings => self.handle_settings_key(key),
            MainMenu::Logs => self.handle_logs_key(key),
            MainMenu::Help => self.handle_help_key(key),
            MainMenu::Communities => self.handle_communities_key(key),
            MainMenu::Vta => self.handle_vta_key(key),
            _ => false,
        }
    }

    /// VTA Service / DID-manager keys: ↑/↓ move the Context-Identities
    /// selection, `d`/Del removes the selected **orphan** (unbound) DID after a
    /// y/n confirmation. Returns true if consumed.
    fn handle_vta_key(&mut self, key: KeyEvent) -> bool {
        let vta = &self.props.main_page.content_panel.vta;
        let count = vta.context_dids.len();
        let selected = vta.did_selected_index;

        // A deletion confirmation is pending: only y/Enter confirms; anything
        // else cancels.
        if let Some(idx) = vta.confirm_delete_did {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::DeleteDid(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::DidCancelDelete);
                }
            }
            return true;
        }

        match key.code {
            KeyCode::Up if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::DidSelect(selected.saturating_sub(1)));
                true
            }
            KeyCode::Down if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::DidSelect((selected + 1).min(count - 1)));
                true
            }
            KeyCode::Char('d') | KeyCode::Delete if selected < count => {
                // Only orphan (unbound) personas are removable — a persona
                // serving a community must not be deleted out from under it.
                if vta
                    .context_dids
                    .get(selected)
                    .is_some_and(|d| d.bound_communities == 0)
                {
                    let _ = self.action_tx.send(Action::DidConfirmDelete(selected));
                }
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    /// Communities overview keys (R-A-5 Stage 4): `j` starts the join flow
    /// (incl. from the empty state), ↑/↓ move the selection, `d`/Del removes the
    /// selected community. Returns true if consumed.
    fn handle_communities_key(&mut self, key: KeyEvent) -> bool {
        let comms = &self.props.main_page.content_panel.communities;
        let count = comms.items.len();
        let selected = comms.selected_index;

        // A removal confirmation is pending: only confirm (y/Enter) or cancel
        // (n/Esc) apply; every other key is swallowed so nothing slips through.
        if let Some(idx) = comms.confirm_delete {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::DeleteCommunity(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::CommunityCancelDelete);
                }
            }
            return true;
        }

        match key.code {
            KeyCode::Char('j') => {
                let _ = self.action_tx.send(Action::StartJoin);
                true
            }
            KeyCode::Up if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySelect(selected.saturating_sub(1)));
                true
            }
            KeyCode::Down if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySelect((selected + 1).min(count - 1)));
                true
            }
            KeyCode::Char('d') | KeyCode::Delete if selected < count => {
                let _ = self
                    .action_tx
                    .send(Action::CommunityConfirmDelete(selected));
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    fn handle_inbox_key(&mut self, key: KeyEvent) -> bool {
        let inbox = &self.props.main_page.content_panel.inbox;

        // If viewing a task detail, handle detail keys
        if let Some(active_task) = &inbox.active_task {
            // Extract what we need before borrowing self mutably
            let task_id = match active_task {
                ActiveTaskView::RelationshipRequestInbound { task_id, .. }
                | ActiveTaskView::VRCRequestInbound { task_id, .. }
                | ActiveTaskView::VRCIssued { task_id, .. }
                | ActiveTaskView::RelationshipRequestOutbound { task_id, .. }
                | ActiveTaskView::VRCRequestOutbound { task_id, .. }
                | ActiveTaskView::Info { task_id, .. } => task_id.clone(),
            };
            let is_rel_inbound = matches!(
                active_task,
                ActiveTaskView::RelationshipRequestInbound { .. }
            );
            let is_vrc_issued = matches!(active_task, ActiveTaskView::VRCIssued { .. });
            let is_vrc_request_inbound =
                matches!(active_task, ActiveTaskView::VRCRequestInbound { .. });

            return match key.code {
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::Inbox(InboxAction::Back));
                    true
                }
                KeyCode::Char('A') if is_rel_inbound => {
                    let _ = self
                        .action_tx
                        .send(Action::Inbox(InboxAction::AcceptRelationship {
                            task_id,
                            generate_r_did: true,
                        }));
                    true
                }
                KeyCode::Char('a') => {
                    if is_rel_inbound {
                        let _ =
                            self.action_tx
                                .send(Action::Inbox(InboxAction::AcceptRelationship {
                                    task_id,
                                    generate_r_did: false,
                                }));
                    } else if is_vrc_issued {
                        let _ = self
                            .action_tx
                            .send(Action::Inbox(InboxAction::AcceptVrc { task_id }));
                    } else if is_vrc_request_inbound {
                        let _ = self
                            .action_tx
                            .send(Action::Inbox(InboxAction::AcceptVrcRequest { task_id }));
                    }
                    true
                }
                KeyCode::Char('r') => {
                    if is_rel_inbound {
                        let _ =
                            self.action_tx
                                .send(Action::Inbox(InboxAction::RejectRelationship {
                                    task_id,
                                    reason: None,
                                }));
                    } else if is_vrc_request_inbound {
                        let _ = self
                            .action_tx
                            .send(Action::Inbox(InboxAction::RejectVrcRequest {
                                task_id,
                                reason: None,
                            }));
                    }
                    true
                }
                KeyCode::Char('d') => {
                    let _ = self
                        .action_tx
                        .send(Action::Inbox(InboxAction::DismissTask { task_id }));
                    true
                }
                _ => false,
            };
        }

        // Task list navigation
        let selected = inbox.selected_index;
        let task_count = inbox.tasks.len();

        match key.code {
            KeyCode::Up if selected > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::SelectTask(selected - 1)));
                true
            }
            KeyCode::Down if selected + 1 < task_count => {
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::SelectTask(selected + 1)));
                true
            }
            KeyCode::Enter if selected < task_count => {
                // All task types have detail views — let the state handler build it
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::OpenDetail(selected)));
                true
            }
            KeyCode::Char('d') if selected < task_count => {
                let task_id = inbox.tasks[selected].id.clone();
                let _ = self
                    .action_tx
                    .send(Action::Inbox(InboxAction::DismissTask { task_id }));
                true
            }
            KeyCode::Char('c') if task_count > 0 => {
                let _ = self.action_tx.send(Action::Inbox(InboxAction::ClearAll));
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    fn handle_relationships_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::RelationshipsMode;

        let rels = &self.props.main_page.content_panel.relationships;

        match &rels.mode {
            RelationshipsMode::NewRequest {
                did_input,
                alias_input,
                reason_input,
                generate_r_did,
                active_field,
            } => {
                // Form input handling
                let active_field = *active_field;
                let generate_r_did = *generate_r_did;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::CancelNewRequest));
                        true
                    }
                    KeyCode::Tab => {
                        // Cycle through fields 0->1->2->3->0
                        let next = (active_field + 1) % 4;
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::FocusField(next)));
                        true
                    }
                    KeyCode::Up if active_field > 0 => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::FocusField(active_field - 1),
                        ));
                        true
                    }
                    KeyCode::Down if active_field < 3 => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::FocusField(active_field + 1),
                        ));
                        true
                    }
                    KeyCode::Char(' ') if active_field == 3 => {
                        // Toggle the generate_r_did boolean
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::ToggleRDid));
                        true
                    }
                    KeyCode::Enter if active_field == 3 => {
                        // Submit from the last field
                        let did = did_input.clone();
                        let alias = alias_input.clone();
                        let reason = if reason_input.trim().is_empty() {
                            None
                        } else {
                            Some(reason_input.clone())
                        };
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::SubmitRequest {
                                did,
                                alias,
                                reason,
                                generate_r_did,
                            },
                        ));
                        true
                    }
                    code if active_field < 3 => {
                        let current = match active_field {
                            0 => did_input,
                            1 => alias_input,
                            _ => reason_input,
                        };
                        match edit_text(code, current) {
                            Some(value) => {
                                let _ = self.action_tx.send(Action::Relationship(
                                    RelationshipAction::InputUpdate {
                                        field: active_field,
                                        value,
                                    },
                                ));
                                true
                            }
                            None => false,
                        }
                    }
                    _ => false,
                }
            }
            RelationshipsMode::Detail {
                index,
                selected_vrc,
            } => {
                let index = *index;
                let current_vrc = *selected_vrc;
                match key.code {
                    KeyCode::Down => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let total = rel.vrcs_issued.len() + rel.vrcs_received.len();
                            if total > 0 {
                                let next = match current_vrc {
                                    None => Some(0),
                                    Some(n) if n + 1 < total => Some(n + 1),
                                    other => other,
                                };
                                if let RelationshipsMode::Detail {
                                    selected_vrc: ref mut sv,
                                    ..
                                } = self.props.main_page.content_panel.relationships.mode
                                {
                                    *sv = next;
                                }
                            }
                        }
                        true
                    }
                    KeyCode::Up => {
                        let next = match current_vrc {
                            Some(0) => None,
                            Some(n) => Some(n - 1),
                            None => None,
                        };
                        if let RelationshipsMode::Detail {
                            selected_vrc: ref mut sv,
                            ..
                        } = self.props.main_page.content_panel.relationships.mode
                        {
                            *sv = next;
                        }
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::Back));
                        true
                    }
                    KeyCode::Char('e') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let current = rel.alias.clone().unwrap_or_default();
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::StartEditAlias {
                                    index,
                                    current_alias: current,
                                },
                            ));
                        }
                        true
                    }
                    KeyCode::Char('p') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::Ping {
                                    remote_p_did: rel.remote_p_did.clone(),
                                },
                            ));
                        }
                        true
                    }
                    KeyCode::Char('d') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::Remove {
                                    remote_p_did: rel.remote_p_did.clone(),
                                },
                            ));
                        }
                        true
                    }
                    KeyCode::Char('v') => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::RequestVrc {
                                    remote_p_did: rel.remote_p_did.clone(),
                                },
                            ));
                        }
                        true
                    }
                    _ => false,
                }
            }
            RelationshipsMode::EditAlias { index, alias_input } => {
                let index = *index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::CancelEditAlias { index },
                        ));
                        true
                    }
                    KeyCode::Enter => {
                        if let Some(rel) = rels.relationships.get(index) {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::EditAlias {
                                    remote_p_did: rel.remote_p_did.clone(),
                                    alias: alias_input.clone(),
                                },
                            ));
                        }
                        true
                    }
                    code => match edit_text(code, alias_input) {
                        Some(value) => {
                            let _ = self.action_tx.send(Action::Relationship(
                                RelationshipAction::EditAliasUpdate(value),
                            ));
                            true
                        }
                        None => false,
                    },
                }
            }
            RelationshipsMode::List => {
                let selected = rels.selected_index;
                let count = rels.relationships.len();

                match key.code {
                    KeyCode::Up if selected > 0 => {
                        let _ =
                            self.action_tx
                                .send(Action::Relationship(RelationshipAction::Select(
                                    selected - 1,
                                )));
                        true
                    }
                    KeyCode::Down if selected + 1 < count => {
                        let _ =
                            self.action_tx
                                .send(Action::Relationship(RelationshipAction::Select(
                                    selected + 1,
                                )));
                        true
                    }
                    KeyCode::Enter if selected < count => {
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::OpenDetail(selected),
                        ));
                        true
                    }
                    KeyCode::Char('n') => {
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::StartNewRequest));
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                        true
                    }
                    _ => false,
                }
            }
        }
    }

    fn handle_credentials_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::{CredentialTab, CredentialsMode};

        let creds = &self.props.main_page.content_panel.credentials;

        match &creds.mode {
            CredentialsMode::NewRequest {
                relationship_index,
                reason_input,
            } => {
                let rel_idx = *relationship_index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::CancelNewRequest));
                        true
                    }
                    KeyCode::Up if rel_idx > 0 => {
                        let _ = self.action_tx.send(Action::Credential(
                            CredentialAction::SelectRelationship(rel_idx - 1),
                        ));
                        true
                    }
                    KeyCode::Down => {
                        // Bound check happens in state handler
                        let _ = self.action_tx.send(Action::Credential(
                            CredentialAction::SelectRelationship(rel_idx + 1),
                        ));
                        true
                    }
                    KeyCode::Enter => {
                        // Get the established relationships from the relationships panel state
                        let established: Vec<_> = self
                            .props
                            .main_page
                            .content_panel
                            .relationships
                            .relationships
                            .iter()
                            .filter(|r| r.state == "Established")
                            .collect();
                        if let Some(rel) = established.get(rel_idx) {
                            let _ = self.action_tx.send(Action::Credential(
                                CredentialAction::SubmitRequest {
                                    relationship_p_did: rel.remote_p_did.clone(),
                                    reason: if reason_input.trim().is_empty() {
                                        None
                                    } else {
                                        Some(reason_input.clone())
                                    },
                                },
                            ));
                        }
                        true
                    }
                    code => match edit_text(code, reason_input) {
                        Some(r) => {
                            let _ = self
                                .action_tx
                                .send(Action::Credential(CredentialAction::ReasonUpdate(r)));
                            true
                        }
                        None => false,
                    },
                }
            }
            CredentialsMode::Detail { index } => {
                let detail_index = *index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::Back));
                        true
                    }
                    KeyCode::Char('d') => {
                        let active_list = match creds.selected_tab {
                            CredentialTab::Received => &creds.received,
                            CredentialTab::Issued => &creds.issued,
                            CredentialTab::Membership => &creds.membership,
                        };
                        // Membership/role credentials are community-bound — there
                        // is no local-only removal, so `d` is a no-op there (the
                        // Remove action won't find a matching VRC).
                        if creds.selected_tab != CredentialTab::Membership
                            && let Some(vrc) = active_list.get(detail_index)
                        {
                            let _ =
                                self.action_tx
                                    .send(Action::Credential(CredentialAction::Remove {
                                        vrc_id: vrc.vrc_id.clone(),
                                    }));
                        }
                        true
                    }
                    KeyCode::Char('c') => {
                        let active_list = match creds.selected_tab {
                            CredentialTab::Received => &creds.received,
                            CredentialTab::Issued => &creds.issued,
                            CredentialTab::Membership => &creds.membership,
                        };
                        if let Some(vrc) = active_list.get(detail_index) {
                            copy_to_clipboard(
                                &vrc.raw_json.to_pretty_json(),
                                "credential",
                                &self.action_tx,
                            );
                        }
                        true
                    }
                    _ => false,
                }
            }
            CredentialsMode::List => {
                let active_list_len = match creds.selected_tab {
                    CredentialTab::Received => creds.received.len(),
                    CredentialTab::Issued => creds.issued.len(),
                    CredentialTab::Membership => creds.membership.len(),
                };
                let selected = creds.selected_index;

                match key.code {
                    KeyCode::Tab => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::SwitchTab));
                        true
                    }
                    KeyCode::Up if selected > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::Select(selected - 1)));
                        true
                    }
                    KeyCode::Down if selected + 1 < active_list_len => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::Select(selected + 1)));
                        true
                    }
                    KeyCode::Enter if selected < active_list_len => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::OpenDetail(selected)));
                        true
                    }
                    KeyCode::Char('n') => {
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::StartNewRequest));
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                        true
                    }
                    _ => false,
                }
            }
        }
    }
    fn handle_settings_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::SettingsMode;

        let settings = &self.props.main_page.content_panel.settings;

        match &settings.mode {
            SettingsMode::EditFriendlyName { input }
            | SettingsMode::EditMediatorDid { input }
            | SettingsMode::EditOrgDid { input } => {
                let current = input.clone();
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Enter => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::SubmitEdit {
                                value: current,
                            }));
                        true
                    }
                    code => match edit_text(code, &current) {
                        Some(v) => {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::FieldUpdate(v)));
                            true
                        }
                        None => false,
                    },
                }
            }
            SettingsMode::ExportConfig {
                path_input,
                active_field,
                ..
            } => {
                let active = *active_field;
                let path = path_input.clone();
                self.handle_config_form_key(key, active, path, |path, passphrase| {
                    SettingsAction::ExportConfig { path, passphrase }
                })
            }
            SettingsMode::ChangeProtection {
                selected_option,
                active_field,
                ..
            } => {
                let active = *active_field;
                let sel = *selected_option;
                match key.code {
                    KeyCode::Esc => {
                        self.passphrase_buffer.clear();
                        self.confirm_buffer.clear();
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Up if active == 0 && sel > 0 => {
                        let _ = self.action_tx.send(Action::Settings(
                            SettingsAction::ProtectionOptionSelect(sel - 1),
                        ));
                        true
                    }
                    KeyCode::Down if active == 0 && sel < 1 => {
                        let _ = self.action_tx.send(Action::Settings(
                            SettingsAction::ProtectionOptionSelect(sel + 1),
                        ));
                        true
                    }
                    KeyCode::Enter if active == 0 => {
                        if sel == 0 {
                            // Switch to passphrase input
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::ProtectionStartInput));
                        } else {
                            // Remove passphrase
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::RemovePassphrase));
                        }
                        true
                    }
                    KeyCode::Tab if active >= 1 => {
                        let next = if active == 1 { 2 } else { 1 };
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::ProtectionTabSwitch(next)));
                        true
                    }
                    KeyCode::Up if active == 2 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::ProtectionTabSwitch(1)));
                        true
                    }
                    KeyCode::Down if active == 1 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::ProtectionTabSwitch(2)));
                        true
                    }
                    KeyCode::Enter if active == 2 => {
                        // Submit passphrase
                        if self.passphrase_buffer == self.confirm_buffer
                            && !self.passphrase_buffer.is_empty()
                        {
                            let passphrase = std::mem::take(&mut self.passphrase_buffer);
                            self.confirm_buffer.clear();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::SetPassphrase { passphrase },
                            ));
                        }
                        true
                    }
                    code if active >= 1 => {
                        // Secure passphrase / confirm buffers: apply the keystroke
                        // to the active buffer and report only its length.
                        let buffer = if active == 1 {
                            &mut self.passphrase_buffer
                        } else {
                            &mut self.confirm_buffer
                        };
                        match code {
                            KeyCode::Backspace => {
                                buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                buffer.push(c);
                            }
                            _ => return false,
                        }
                        let len = buffer.len();
                        let action = if active == 1 {
                            SettingsAction::ProtectionPassphraseLen(len)
                        } else {
                            SettingsAction::ProtectionConfirmLen(len)
                        };
                        let _ = self.action_tx.send(Action::Settings(action));
                        true
                    }
                    _ => false,
                }
            }
            #[cfg(feature = "openpgp-card")]
            SettingsMode::TokenManagement { selected_index } => {
                let sel = *selected_index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::TokenBack));
                        true
                    }
                    KeyCode::Up if sel > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(sel - 1)));
                        true
                    }
                    KeyCode::Down if sel < 1 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(sel + 1)));
                        true
                    }
                    KeyCode::Enter => {
                        match sel {
                            0 => {
                                let _ = self
                                    .action_tx
                                    .send(Action::Settings(SettingsAction::TokenDetect));
                            }
                            1 => {
                                let _ = self
                                    .action_tx
                                    .send(Action::Settings(SettingsAction::TokenFactoryReset));
                            }
                            _ => {}
                        }
                        true
                    }
                    _ => false,
                }
            }
            SettingsMode::ImportConfig {
                path_input,
                active_field,
                ..
            } => {
                let active = *active_field;
                let path = path_input.clone();
                self.handle_config_form_key(key, active, path, |path, passphrase| {
                    SettingsAction::ImportConfig { path, passphrase }
                })
            }
            SettingsMode::View => {
                let selected = settings.selected_index;
                // 0=name, 1=mediator, 2=org, 3=persona(ro), 4=protection, 5=export,
                // 6=import, [7=token w/ openpgp-card,] last=wipe.
                #[cfg(feature = "openpgp-card")]
                let token_index: usize = 7;
                #[cfg(feature = "openpgp-card")]
                let wipe_index: usize = 8;
                #[cfg(not(feature = "openpgp-card"))]
                let wipe_index: usize = 7;
                let max_index = wipe_index;

                match key.code {
                    KeyCode::Up if selected > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(selected - 1)));
                        true
                    }
                    KeyCode::Down if selected < max_index => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::Select(selected + 1)));
                        true
                    }
                    KeyCode::Enter => {
                        if selected <= 2 {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::StartEdit));
                        } else if selected == 4 {
                            // Change protection
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::ChangeProtection));
                        } else if selected == 5 {
                            // Export
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::StartEdit));
                        } else if selected == 6 {
                            // Import
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::StartEdit));
                        }
                        #[cfg(feature = "openpgp-card")]
                        if selected == token_index {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::TokenManagement));
                        }
                        if selected == wipe_index {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::WipeProfileStart));
                        }
                        true
                    }
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                        true
                    }
                    _ => false,
                }
            }
            SettingsMode::WipeConfirm { confirm_input } => {
                let current = confirm_input.clone();
                match key.code {
                    KeyCode::Esc => {
                        // Drop back to the Settings list — wipe is cancelled.
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Enter => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::WipeProfileConfirm));
                        true
                    }
                    code => match edit_text(code, &current) {
                        Some(next) => {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::WipeProfileInput(next)));
                            true
                        }
                        None => false,
                    },
                }
            }
        }
    }

    /// Shared key handling for the Export/Import config forms. The two forms are
    /// identical except for the submit Action, supplied via `make_submit`
    /// (called with the path and the taken passphrase buffer). `active` is the
    /// focused field (0 = path, 1 = passphrase).
    fn handle_config_form_key(
        &mut self,
        key: KeyEvent,
        active: usize,
        path: String,
        make_submit: impl FnOnce(String, String) -> SettingsAction,
    ) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.passphrase_buffer.clear();
                let _ = self
                    .action_tx
                    .send(Action::Settings(SettingsAction::CancelEdit));
                true
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                let _ = self
                    .action_tx
                    .send(Action::Settings(SettingsAction::FormTabSwitch));
                true
            }
            KeyCode::Enter if active == 1 => {
                let passphrase = std::mem::take(&mut self.passphrase_buffer);
                let _ = self
                    .action_tx
                    .send(Action::Settings(make_submit(path, passphrase)));
                true
            }
            code => {
                if active == 0 {
                    match edit_text(code, &path) {
                        Some(value) => {
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate { field: 0, value },
                            ));
                            true
                        }
                        None => false,
                    }
                } else {
                    match code {
                        KeyCode::Backspace => {
                            self.passphrase_buffer.pop();
                        }
                        KeyCode::Char(c) => {
                            self.passphrase_buffer.push(c);
                        }
                        _ => return false,
                    }
                    let _ = self
                        .action_tx
                        .send(Action::Settings(SettingsAction::PassphraseLen(
                            self.passphrase_buffer.len(),
                        )));
                    true
                }
            }
        }
    }

    fn handle_logs_key(&mut self, key: KeyEvent) -> bool {
        let total = self.props.main_page.activity_log.len();

        // Detail view mode — Esc or Enter to close
        if self.logs_detail_view {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.logs_detail_view = false;
                    return true;
                }
                KeyCode::Char('c') if total > 0 => {
                    let entries: Vec<_> = self.props.main_page.activity_log.iter().rev().collect();
                    if let Some(entry) = entries.get(self.logs_selected) {
                        copy_to_clipboard(&entry.summary, "Log entry", &self.action_tx);
                    }
                    return true;
                }
                _ => return false,
            }
        }

        match key.code {
            KeyCode::Up if self.logs_selected > 0 => {
                self.logs_selected -= 1;
                true
            }
            KeyCode::Down if self.logs_selected + 1 < total => {
                self.logs_selected += 1;
                true
            }
            KeyCode::Enter if total > 0 => {
                self.logs_detail_view = true;
                true
            }
            KeyCode::Char('c') if total > 0 => {
                // Copy selected log entry to clipboard
                let entries: Vec<_> = self.props.main_page.activity_log.iter().rev().collect();
                if let Some(entry) = entries.get(self.logs_selected) {
                    copy_to_clipboard(&entry.summary, "Log entry", &self.action_tx);
                }
                true
            }
            KeyCode::Char('a') if total > 0 => {
                // Copy all log entries to clipboard
                let all_text: String = self
                    .props
                    .main_page
                    .activity_log
                    .iter()
                    .rev()
                    .map(|e| e.summary.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&all_text, "All log entries", &self.action_tx);
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('1') => {
                // Copy persona DID to clipboard
                let did = self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .persona_did
                    .clone();
                copy_to_clipboard(&did, "Persona DID", &self.action_tx);
                true
            }
            KeyCode::Char('2') => {
                // Copy mediator DID to clipboard
                let did = self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .mediator_did
                    .clone();
                copy_to_clipboard(&did, "Mediator DID", &self.action_tx);
                true
            }
            KeyCode::Char('3') => {
                if let Some(info) = &self.props.main_page.content_panel.settings.did_git_sign {
                    copy_to_clipboard(
                        &info.did_key_id,
                        "Signing principal (DID#kid)",
                        &self.action_tx,
                    );
                }
                true
            }
            KeyCode::Char('4') => {
                if let Some(info) = &self.props.main_page.content_panel.settings.did_git_sign {
                    copy_to_clipboard(
                        &info.ssh_public_key,
                        "SSH signing public key",
                        &self.action_tx,
                    );
                }
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }
}

/// Apply one text-editing keystroke to `current`, returning the new value when
/// the key edits the buffer, or `None` otherwise. Append-only semantics
/// (printable char appends at the end; Backspace removes the last char) — these
/// inline editors have no cursor, matching the prior behavior exactly.
fn edit_text(code: KeyCode, current: &str) -> Option<String> {
    match code {
        KeyCode::Char(c) => {
            let mut s = current.to_string();
            s.push(c);
            Some(s)
        }
        KeyCode::Backspace => {
            let mut s = current.to_string();
            s.pop();
            Some(s)
        }
        _ => None,
    }
}

/// Stable identifier for the currently-displayed content view, derived from
/// the active menu and its per-panel mode. When this changes across frames
/// (e.g. list → detail, or switching menus), the content panel scroll offset
/// is reset to 0 so the new view starts at the top.
fn view_id(page: &MainPageState) -> String {
    use crate::state_handler::main_page::content::{
        CredentialsMode, RelationshipsMode, SettingsMode,
    };
    let menu = &page.menu_panel.selected_menu;
    let mode: &str = match menu {
        MainMenu::Inbox => {
            if page.content_panel.inbox.active_task.is_some() {
                "detail"
            } else {
                "list"
            }
        }
        MainMenu::Credentials => match &page.content_panel.credentials.mode {
            CredentialsMode::List => "list",
            CredentialsMode::Detail { .. } => "detail",
            CredentialsMode::NewRequest { .. } => "new",
        },
        MainMenu::Relationships => match &page.content_panel.relationships.mode {
            RelationshipsMode::List => "list",
            RelationshipsMode::Detail { .. } => "detail",
            RelationshipsMode::NewRequest { .. } => "new",
            RelationshipsMode::EditAlias { .. } => "edit",
        },
        MainMenu::Settings => match &page.content_panel.settings.mode {
            SettingsMode::View => "view",
            SettingsMode::EditFriendlyName { .. } => "edit-name",
            SettingsMode::EditMediatorDid { .. } => "edit-mediator",
            SettingsMode::EditOrgDid { .. } => "edit-org",
            SettingsMode::ExportConfig { .. } => "export",
            SettingsMode::ImportConfig { .. } => "import",
            SettingsMode::ChangeProtection { .. } => "protect",
            #[cfg(feature = "openpgp-card")]
            SettingsMode::TokenManagement { .. } => "token",
            SettingsMode::WipeConfirm { .. } => "wipe",
        },
        _ => "",
    };
    format!("{menu:?}:{mode}")
}

/// Copy text to the system clipboard, log the result to the activity log,
/// and update the status panel message to give the user visual feedback.
fn copy_to_clipboard(
    text: &str,
    label: &str,
    action_tx: &tokio::sync::mpsc::UnboundedSender<Action>,
) {
    match crate::clipboard::copy_to_clipboard(text) {
        Ok(method) => {
            tracing::info!(label, method = method.label(), "copied to clipboard");
            let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(format!(
                "✓ {label} copied via {}",
                method.label()
            ))));
        }
        Err(e) => {
            tracing::warn!(label, error = %e, "failed to copy to clipboard");
            let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(format!(
                "✗ Copy failed: {e}"
            ))));
        }
    }
}

// ****************************************************************************
// Render the page
// ****************************************************************************
impl ComponentRender<()> for MainPage {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let [main_top, main_middle, main_log, main_bottom] =
            Layout::vertical([Length(2), Min(0), Length(8), Length(1)]).areas(frame.area());

        let top =
            Layout::horizontal([Percentage(35), Percentage(30), Percentage(35)]).split(main_top);
        let middle = Layout::horizontal([Percentage(20), Min(0)]).split(main_middle);

        frame.render_widget(
            Paragraph::new(" OpenVTC Dashboard")
                .fg(COLOR_SUCCESS)
                .alignment(Alignment::Left),
            top[0],
        );

        // Connection status indicator
        let connection_line = match &self.props.connection.status {
            MediatorStatus::Connected => Line::from(Span::styled(
                "Connected",
                ratatui::style::Style::default().fg(COLOR_SUCCESS),
            )),
            MediatorStatus::Connecting => Line::from(Span::styled(
                "Connecting...",
                ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
            )),
            MediatorStatus::Failed(reason) => {
                let display = if reason.len() > 20 {
                    format!("Failed: {}...", &reason[..17])
                } else {
                    format!("Failed: {}", reason)
                };
                Line::from(Span::styled(
                    display,
                    ratatui::style::Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ))
            }
            MediatorStatus::Initializing(step) => Line::from(vec![
                Span::styled(
                    "Initializing: ",
                    ratatui::style::Style::default().fg(COLOR_ORANGE),
                ),
                Span::styled(
                    step.to_string(),
                    ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
                ),
            ]),
            MediatorStatus::Unknown => Line::from(Span::styled(
                "Mediator: --",
                ratatui::style::Style::default().fg(COLOR_ORANGE),
            )),
            MediatorStatus::NoActiveCommunity => Line::from(Span::styled(
                "No active community",
                ratatui::style::Style::default().fg(COLOR_ORANGE),
            )),
        };
        frame.render_widget(
            Paragraph::new(connection_line).alignment(Alignment::Center),
            top[1],
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(self.props.main_page.config.name.to_string()).fg(COLOR_SUCCESS),
                Line::from(
                    truncate_did_centered(&self.props.main_page.config.did, 30).into_owned(),
                )
                .fg(COLOR_TEXT_DEFAULT),
            ])
            .alignment(Alignment::Right),
            top[2],
        );

        // Middle block
        // Left = menu
        // right = actual content

        // Main Menu
        let inbox_task_count = self.props.main_page.content_panel.inbox.tasks.len();
        self.props
            .main_page
            .menu_panel
            .render(frame, middle[0], inbox_task_count);
        let max_scroll = self.props.main_page.content_panel.render(
            frame,
            middle[1],
            &self.props.main_page.menu_panel,
            &self.props.connection,
            &self.props.main_page.activity_log,
            self.logs_selected,
            self.logs_detail_view,
            self.content_scroll,
        );
        self.content_scroll_max.set(max_scroll);

        // Activity log panel
        let log_block = Block::bordered()
            .merge_borders(MergeStrategy::Fuzzy)
            .fg(COLOR_BORDER)
            .title(" Activity Log ");
        let log_inner = log_block.inner(main_log);
        frame.render_widget(log_block, main_log);

        let log = &self.props.main_page.activity_log;
        let visible_lines = log_inner.height as usize;
        let skip = if log.len() > visible_lines {
            log.len() - visible_lines
        } else {
            0
        };
        let log_lines: Vec<Line> = log
            .iter()
            .skip(skip)
            .map(|entry| Line::from(entry.summary.clone()).dark_gray())
            .collect();
        frame.render_widget(Paragraph::new(log_lines), log_inner);

        // Bottom key hints (single line)
        frame.render_widget(
            Paragraph::new(" <TAB> switch panels  <PgUp/PgDn/Home/End> scroll  <F10> quit")
                .dark_gray()
                .alignment(Alignment::Left),
            main_bottom,
        );
    }
}
