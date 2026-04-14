use crate::{
    state_handler::{
        actions::{Action, CredentialAction, InboxAction, RelationshipAction, SettingsAction},
        main_page::{
            MainPageState, MainPanel,
            content::{ActiveTaskView, TaskKind},
            menu::MainMenu,
        },
        state::{ConnectionState, MediatorStatus, State},
    },
    ui::{
        component::{Component, ComponentRender},
        shorten_did,
    },
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use openvtc::colors::{
    COLOR_BORDER, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
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
}

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
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        MainPage {
            props: Props::from(state),
            // propagate the update to the child components
            ..self
        }
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
            KeyCode::Up => {
                if self.props.main_page.menu_panel.selected {
                    let _ = self.action_tx.send(Action::MainMenuSelected(
                        self.props.main_page.menu_panel.selected_menu.prev(),
                    ));
                }
            }
            KeyCode::Down => {
                if self.props.main_page.menu_panel.selected {
                    let _ = self.action_tx.send(Action::MainMenuSelected(
                        self.props.main_page.menu_panel.selected_menu.next(),
                    ));
                }
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
        let menu = self.props.main_page.menu_panel.selected_menu.clone();

        match menu {
            MainMenu::Inbox => self.handle_inbox_key(key),
            MainMenu::Relationships => self.handle_relationships_key(key),
            MainMenu::Credentials => self.handle_credentials_key(key),
            MainMenu::Settings => self.handle_settings_key(key),
            MainMenu::Logs => self.handle_logs_key(key),
            MainMenu::Help => self.handle_help_key(key),
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
                | ActiveTaskView::VRCIssued { task_id, .. } => task_id.clone(),
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
                KeyCode::Char('a') => {
                    if is_rel_inbound {
                        let _ = self
                            .action_tx
                            .send(Action::Inbox(InboxAction::AcceptRelationship { task_id }));
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
                // Build the detail view from the selected task
                let task = &inbox.tasks[selected];
                let view = match &task.kind {
                    TaskKind::RelationshipRequestInbound {
                        from_did,
                        their_did,
                        reason,
                    } => Some(ActiveTaskView::RelationshipRequestInbound {
                        task_id: task.id.clone(),
                        from_did: from_did.clone(),
                        their_did: their_did.clone(),
                        reason: reason.clone(),
                    }),
                    TaskKind::VRCRequestInbound { reason } => {
                        Some(ActiveTaskView::VRCRequestInbound {
                            task_id: task.id.clone(),
                            from_did: task.remote_did.clone(),
                            reason: reason.clone(),
                        })
                    }
                    TaskKind::VRCIssued => Some(ActiveTaskView::VRCIssued {
                        task_id: task.id.clone(),
                        issuer: task.remote_did.clone(),
                    }),
                    _ => None,
                };
                // For tasks with detail views, send the open-detail action
                if view.is_some() {
                    let _ = self
                        .action_tx
                        .send(Action::Inbox(InboxAction::OpenDetail(selected)));
                }
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
                    KeyCode::Backspace if active_field < 3 => {
                        let mut current = match active_field {
                            0 => did_input.clone(),
                            1 => alias_input.clone(),
                            _ => reason_input.clone(),
                        };
                        current.pop();
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::InputUpdate {
                                field: active_field,
                                value: current,
                            },
                        ));
                        true
                    }
                    KeyCode::Char(c) if active_field < 3 => {
                        let mut current = match active_field {
                            0 => did_input.clone(),
                            1 => alias_input.clone(),
                            _ => reason_input.clone(),
                        };
                        current.push(c);
                        let _ = self.action_tx.send(Action::Relationship(
                            RelationshipAction::InputUpdate {
                                field: active_field,
                                value: current,
                            },
                        ));
                        true
                    }
                    _ => false,
                }
            }
            RelationshipsMode::Detail { index } => {
                let index = *index;
                match key.code {
                    KeyCode::Esc => {
                        let _ = self
                            .action_tx
                            .send(Action::Relationship(RelationshipAction::Back));
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
                    _ => false,
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
                    KeyCode::Backspace => {
                        let mut r = reason_input.clone();
                        r.pop();
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::ReasonUpdate(r)));
                        true
                    }
                    KeyCode::Char(c) => {
                        let mut r = reason_input.clone();
                        r.push(c);
                        let _ = self
                            .action_tx
                            .send(Action::Credential(CredentialAction::ReasonUpdate(r)));
                        true
                    }
                    _ => false,
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
                        };
                        if let Some(vrc) = active_list.get(detail_index) {
                            let _ =
                                self.action_tx
                                    .send(Action::Credential(CredentialAction::Remove {
                                        vrc_id: vrc.vrc_id.clone(),
                                    }));
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
                    KeyCode::Backspace => {
                        let mut v = current;
                        v.pop();
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::FieldUpdate(v)));
                        true
                    }
                    KeyCode::Char(c) => {
                        let mut v = current;
                        v.push(c);
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::FieldUpdate(v)));
                        true
                    }
                    _ => false,
                }
            }
            SettingsMode::ExportConfig {
                path_input,
                active_field,
                ..
            } => {
                let active = *active_field;
                match key.code {
                    KeyCode::Esc => {
                        self.passphrase_buffer.clear();
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Tab => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::FormTabSwitch));
                        true
                    }
                    KeyCode::Enter if active == 1 => {
                        let passphrase = std::mem::take(&mut self.passphrase_buffer);
                        let _ =
                            self.action_tx
                                .send(Action::Settings(SettingsAction::ExportConfig {
                                    path: path_input.clone(),
                                    passphrase,
                                }));
                        true
                    }
                    KeyCode::Backspace => {
                        if active == 0 {
                            let mut current = path_input.clone();
                            current.pop();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate {
                                    field: 0,
                                    value: current,
                                },
                            ));
                        } else {
                            self.passphrase_buffer.pop();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::PassphraseLen(self.passphrase_buffer.len()),
                            ));
                        }
                        true
                    }
                    KeyCode::Char(c) => {
                        if active == 0 {
                            let mut current = path_input.clone();
                            current.push(c);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate {
                                    field: 0,
                                    value: current,
                                },
                            ));
                        } else {
                            self.passphrase_buffer.push(c);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::PassphraseLen(self.passphrase_buffer.len()),
                            ));
                        }
                        true
                    }
                    _ => false,
                }
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
                    KeyCode::Backspace if active >= 1 => {
                        if active == 1 {
                            self.passphrase_buffer.pop();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionPassphraseLen(
                                    self.passphrase_buffer.len(),
                                ),
                            ));
                        } else {
                            self.confirm_buffer.pop();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionConfirmLen(self.confirm_buffer.len()),
                            ));
                        }
                        true
                    }
                    KeyCode::Char(c) if active >= 1 => {
                        if active == 1 {
                            self.passphrase_buffer.push(c);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionPassphraseLen(
                                    self.passphrase_buffer.len(),
                                ),
                            ));
                        } else {
                            self.confirm_buffer.push(c);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionConfirmLen(self.confirm_buffer.len()),
                            ));
                        }
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
                match key.code {
                    KeyCode::Esc => {
                        self.passphrase_buffer.clear();
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::CancelEdit));
                        true
                    }
                    KeyCode::Tab => {
                        let _ = self
                            .action_tx
                            .send(Action::Settings(SettingsAction::FormTabSwitch));
                        true
                    }
                    KeyCode::Enter if active == 1 => {
                        let passphrase = std::mem::take(&mut self.passphrase_buffer);
                        let _ =
                            self.action_tx
                                .send(Action::Settings(SettingsAction::ImportConfig {
                                    path: path_input.clone(),
                                    passphrase,
                                }));
                        true
                    }
                    KeyCode::Backspace => {
                        if active == 0 {
                            let mut current = path_input.clone();
                            current.pop();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate {
                                    field: 0,
                                    value: current,
                                },
                            ));
                        } else {
                            self.passphrase_buffer.pop();
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::PassphraseLen(self.passphrase_buffer.len()),
                            ));
                        }
                        true
                    }
                    KeyCode::Char(c) => {
                        if active == 0 {
                            let mut current = path_input.clone();
                            current.push(c);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::FormFieldUpdate {
                                    field: 0,
                                    value: current,
                                },
                            ));
                        } else {
                            self.passphrase_buffer.push(c);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::PassphraseLen(self.passphrase_buffer.len()),
                            ));
                        }
                        true
                    }
                    _ => false,
                }
            }
            SettingsMode::View => {
                let selected = settings.selected_index;
                // 0=name, 1=mediator, 2=org, 3=persona(ro), 4=protection, 5=export, 6=import, 7=token
                #[cfg(feature = "openpgp-card")]
                let max_index = 7;
                #[cfg(not(feature = "openpgp-card"))]
                let max_index = 6;

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
                        if selected == 7 {
                            let _ = self
                                .action_tx
                                .send(Action::Settings(SettingsAction::TokenManagement));
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
    }
    fn handle_logs_key(&mut self, key: KeyEvent) -> bool {
        let total = self.props.main_page.activity_log.len();

        match key.code {
            KeyCode::Up if self.logs_selected > 0 => {
                self.logs_selected -= 1;
                true
            }
            KeyCode::Down if self.logs_selected + 1 < total => {
                self.logs_selected += 1;
                true
            }
            KeyCode::Char('c') if total > 0 => {
                // Copy selected log entry to clipboard
                let entries: Vec<&String> =
                    self.props.main_page.activity_log.iter().rev().collect();
                if let Some(entry) = entries.get(self.logs_selected) {
                    copy_to_clipboard(entry, "Log entry", &self.action_tx);
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
                    .cloned()
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

/// Copy text to the system clipboard, log the result to the activity log,
/// and update the status panel message to give the user visual feedback.
fn copy_to_clipboard(
    text: &str,
    label: &str,
    action_tx: &tokio::sync::mpsc::UnboundedSender<Action>,
) {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.set_text(text) {
            Ok(()) => {
                tracing::info!(label, "copied to clipboard");
                // Update the settings status_message so it shows on the Help panel
                let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(format!(
                    "✓ {} copied to clipboard",
                    label
                ))));
            }
            Err(e) => {
                tracing::warn!(label, error = %e, "failed to copy to clipboard");
                let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(format!(
                    "✗ Copy failed: {e}"
                ))));
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "clipboard not available");
            let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(
                "✗ Clipboard not available".to_string(),
            )));
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
            MediatorStatus::Connected { latency_ms } => Line::from(vec![
                Span::styled(
                    "Connected ",
                    ratatui::style::Style::default().fg(COLOR_SUCCESS),
                ),
                Span::styled(
                    format!("({}ms)", latency_ms),
                    ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
                ),
            ]),
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
        };
        frame.render_widget(
            Paragraph::new(connection_line).alignment(Alignment::Center),
            top[1],
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(self.props.main_page.config.name.to_string()).fg(COLOR_SUCCESS),
                Line::from(shorten_did(&self.props.main_page.config.did, 30))
                    .fg(COLOR_TEXT_DEFAULT),
            ])
            .alignment(Alignment::Right),
            top[2],
        );

        // Middle block
        // Left = menu
        // right = actual content

        // Main Menu
        self.props.main_page.menu_panel.render(frame, middle[0]);
        self.props.main_page.content_panel.render(
            frame,
            middle[1],
            &self.props.main_page.menu_panel,
            &self.props.connection,
            &self.props.main_page.activity_log,
            self.logs_selected,
        );

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
            .map(|entry| Line::from(entry.clone()).dark_gray())
            .collect();
        frame.render_widget(Paragraph::new(log_lines), log_inner);

        // Bottom key hints (single line)
        frame.render_widget(
            Paragraph::new(" <TAB> switch panels  <F10> quit")
                .dark_gray()
                .alignment(Alignment::Left),
            main_bottom,
        );
    }
}
