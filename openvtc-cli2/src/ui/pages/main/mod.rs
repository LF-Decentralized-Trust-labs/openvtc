use crate::{
    state_handler::{
        actions::Action,
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
    widgets::{Block, Borders, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

pub mod components;

/// MainPage handles the UI and the state of the primary openvtc interface
pub struct MainPage {
    /// Action sender
    pub action_tx: UnboundedSender<Action>,

    /// State Mapped MainPage Props
    props: Props,
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

            return match key.code {
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::InboxBack);
                    true
                }
                KeyCode::Char('a') => {
                    if is_rel_inbound {
                        let _ = self
                            .action_tx
                            .send(Action::InboxAcceptRelationship { task_id });
                    } else if is_vrc_issued {
                        let _ = self.action_tx.send(Action::InboxAcceptVrc { task_id });
                    }
                    true
                }
                KeyCode::Char('r') => {
                    if is_rel_inbound {
                        let _ = self.action_tx.send(Action::InboxRejectRelationship {
                            task_id,
                            reason: None,
                        });
                    }
                    true
                }
                KeyCode::Char('d') => {
                    let _ = self.action_tx.send(Action::InboxDismissTask { task_id });
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
                let _ = self.action_tx.send(Action::InboxSelectTask(selected - 1));
                true
            }
            KeyCode::Down if selected + 1 < task_count => {
                let _ = self.action_tx.send(Action::InboxSelectTask(selected + 1));
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
                // For tasks with detail views, we use the high bit as a flag
                // to tell the state handler to open the detail view
                if view.is_some() {
                    let _ = self
                        .action_tx
                        .send(Action::InboxSelectTask(selected | 0x8000_0000));
                }
                true
            }
            KeyCode::Char('d') if selected < task_count => {
                let task_id = inbox.tasks[selected].id.clone();
                let _ = self.action_tx.send(Action::InboxDismissTask { task_id });
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

// ****************************************************************************
// Render the page
// ****************************************************************************
impl ComponentRender<()> for MainPage {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let [main_top, main_middle, main_bottom] =
            Layout::vertical([Length(2), Min(0), Length(3)]).areas(frame.area());

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
        );

        let bottom_block = Block::new()
            .borders(Borders::TOP)
            .merge_borders(MergeStrategy::Fuzzy)
            .fg(COLOR_BORDER);
        frame.render_widget(
            Paragraph::new("<TAB>/<LEFT>/<RIGHT> to change panels, <F10> to quit")
                .dark_gray()
                .alignment(Alignment::Left)
                .block(bottom_block),
            main_bottom,
        );
    }
}
