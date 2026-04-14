use crate::state_handler::{
    main_page::{
        content::{ActiveTaskView, ContentPanelState, TaskKind},
        menu::{MainMenu, MenuPanelState},
    },
    state::{ConnectionState, MediatorStatus},
};
use openvtc::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Style, Stylize},
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph},
};

// ****************************************************************************
// Render the Content panel
// ****************************************************************************
impl ContentPanelState {
    /// Render the content panel based on current state
    pub fn render(
        &self,
        frame: &mut Frame,
        rect: Rect,
        menu: &MenuPanelState,
        connection: &ConnectionState,
    ) {
        let content_block = if self.selected {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .border_type(BorderType::Double)
                .fg(COLOR_SUCCESS)
                .title("Content")
        } else {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .fg(COLOR_BORDER)
                .title("Content")
        };

        let lines = match menu.selected_menu {
            MainMenu::Inbox => self.render_inbox(connection),
            MainMenu::Relationships => self.render_relationships(),
            MainMenu::Credentials => self.render_credentials(),
            MainMenu::Settings => self.render_settings(),
            MainMenu::Help => {
                vec![
                    Line::from(""),
                    Line::from("Press Up/Down to navigate").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press Enter to select / open").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press Tab, Left, or Right to switch panels").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press Esc to go back").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press F10 to quit from anywhere").fg(COLOR_TEXT_DEFAULT),
                ]
            }
            MainMenu::Quit => {
                vec![
                    Line::from(""),
                    Line::from("Press <Enter> to quit the application")
                        .fg(COLOR_WARNING_ACCESSIBLE_RED),
                ]
            }
        };

        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Left)
                .block(content_block),
            rect,
        );
    }

    // ========================================================================
    // Inbox rendering
    // ========================================================================
    fn render_inbox(&self, connection: &ConnectionState) -> Vec<Line<'static>> {
        // If viewing a specific task detail
        if let Some(active_task) = &self.inbox.active_task {
            return render_task_detail(active_task);
        }

        let mut lines = vec![Line::from("")];

        // Connection status (compact)
        let status_line = match &connection.status {
            MediatorStatus::Connected { latency_ms } => {
                Line::from(format!("Connected ({}ms)", latency_ms)).fg(COLOR_SUCCESS)
            }
            MediatorStatus::Connecting => Line::from("Connecting...").fg(COLOR_TEXT_DEFAULT),
            MediatorStatus::Failed(reason) => {
                let display = if reason.len() > 40 {
                    format!("Failed: {}...", &reason[..37])
                } else {
                    format!("Failed: {}", reason)
                };
                Line::from(display).fg(COLOR_WARNING_ACCESSIBLE_RED)
            }
            MediatorStatus::Initializing(step) => {
                Line::from(format!("Initializing: {}", step)).fg(COLOR_ORANGE)
            }
            MediatorStatus::Unknown => Line::from("Not connected").fg(COLOR_ORANGE),
        };
        lines.push(status_line);

        if let Some(msg) = &self.inbox.status_message {
            lines.push(Line::from(""));
            lines.push(Line::from(msg.clone()).fg(COLOR_SUCCESS));
        }

        lines.push(Line::from(""));

        if self.inbox.tasks.is_empty() {
            lines.push(Line::from("No pending tasks").fg(COLOR_DARK_GRAY));
            lines.push(Line::from(""));
            lines.push(
                Line::from("Inbound messages will appear here automatically.").fg(COLOR_DARK_GRAY),
            );
        } else {
            lines.push(
                Line::from(format!(" {} task(s)", self.inbox.tasks.len())).fg(COLOR_TEXT_DEFAULT),
            );
            lines.push(Line::from(""));

            for (i, task) in self.inbox.tasks.iter().enumerate() {
                let is_selected = i == self.inbox.selected_index;
                let prefix = if is_selected { "▸ " } else { "  " };
                let style = if is_selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                };

                let kind_indicator = match &task.kind {
                    TaskKind::RelationshipRequestInbound { .. } => "⬇ REL ",
                    TaskKind::RelationshipRequestOutbound => "⬆ REL ",
                    TaskKind::VRCRequestInbound { .. } => "⬇ VRC ",
                    TaskKind::VRCRequestOutbound => "⬆ VRC ",
                    TaskKind::VRCIssued => "📄 VRC ",
                    TaskKind::TrustPing => "🏓 PING",
                    TaskKind::Informational(_) => "ℹ INFO",
                };

                lines.push(Line::from(vec![
                    Span::styled(prefix, style),
                    Span::styled(kind_indicator, style),
                    Span::styled("  ", Style::default()),
                    Span::styled(task.type_display.clone(), style),
                ]));

                if !task.remote_did.is_empty() {
                    let did_style = if is_selected {
                        Style::new().fg(COLOR_SOFT_PURPLE)
                    } else {
                        Style::new().fg(COLOR_DARK_GRAY)
                    };
                    lines.push(Line::from(vec![
                        Span::styled("    ", Style::default()),
                        Span::styled(task.remote_did.clone(), did_style),
                        Span::styled("  ", Style::default()),
                        Span::styled(task.created.clone(), did_style),
                    ]));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from("↑/↓ navigate  Enter: view  d: dismiss").fg(COLOR_DARK_GRAY));
        }

        lines
    }

    // ========================================================================
    // Relationships rendering (placeholder for Phase 3)
    // ========================================================================
    fn render_relationships(&self) -> Vec<Line<'static>> {
        let mut lines = vec![Line::from("")];

        if self.relationships.relationships.is_empty() {
            lines.push(Line::from("No relationships yet").fg(COLOR_DARK_GRAY));
            lines.push(Line::from(""));
            lines.push(
                Line::from("Use 'n' to create a new relationship request.").fg(COLOR_DARK_GRAY),
            );
        } else {
            lines.push(
                Line::from(format!(
                    " {} relationship(s)",
                    self.relationships.relationships.len()
                ))
                .fg(COLOR_TEXT_DEFAULT),
            );
            lines.push(Line::from(""));

            for (i, rel) in self.relationships.relationships.iter().enumerate() {
                let is_selected = i == self.relationships.selected_index;
                let prefix = if is_selected { "▸ " } else { "  " };
                let style = if is_selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                };

                let display_name = rel.alias.as_deref().unwrap_or(&rel.remote_p_did);

                lines.push(Line::from(vec![
                    Span::styled(prefix, style),
                    Span::styled(display_name.to_string(), style),
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("[{}]", rel.state),
                        if rel.state == "Established" {
                            Style::new().fg(COLOR_SUCCESS)
                        } else {
                            Style::new().fg(COLOR_ORANGE)
                        },
                    ),
                ]));
            }

            lines.push(Line::from(""));
            lines.push(
                Line::from("↑/↓ navigate  Enter: details  n: new request").fg(COLOR_DARK_GRAY),
            );
        }

        lines
    }

    // ========================================================================
    // Credentials rendering (placeholder for Phase 4)
    // ========================================================================
    fn render_credentials(&self) -> Vec<Line<'static>> {
        let mut lines = vec![Line::from("")];

        let active_list = match self.credentials.selected_tab {
            crate::state_handler::main_page::content::CredentialTab::Received => {
                &self.credentials.received
            }
            crate::state_handler::main_page::content::CredentialTab::Issued => {
                &self.credentials.issued
            }
        };

        // Tab bar
        let (recv_style, issued_style) = match self.credentials.selected_tab {
            crate::state_handler::main_page::content::CredentialTab::Received => (
                Style::new().fg(COLOR_SUCCESS).bold(),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            crate::state_handler::main_page::content::CredentialTab::Issued => (
                Style::new().fg(COLOR_DARK_GRAY),
                Style::new().fg(COLOR_SUCCESS).bold(),
            ),
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!(" Received ({}) ", self.credentials.received.len()),
                recv_style,
            ),
            Span::styled(" | ", Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(
                format!(" Issued ({}) ", self.credentials.issued.len()),
                issued_style,
            ),
        ]));
        lines.push(Line::from(""));

        if active_list.is_empty() {
            lines.push(Line::from("No credentials").fg(COLOR_DARK_GRAY));
        } else {
            for (i, vrc) in active_list.iter().enumerate() {
                let is_selected = i == self.credentials.selected_index;
                let prefix = if is_selected { "▸ " } else { "  " };
                let style = if is_selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                };

                let display_name = vrc.alias.as_deref().unwrap_or(&vrc.remote_p_did);

                lines.push(Line::from(vec![
                    Span::styled(prefix, style),
                    Span::styled(display_name.to_string(), style),
                    Span::styled("  ", Style::default()),
                    Span::styled(vrc.valid_from.clone(), Style::new().fg(COLOR_DARK_GRAY)),
                ]));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from("Tab: switch tab  ↑/↓ navigate  n: request VRC").fg(COLOR_DARK_GRAY));

        lines
    }

    // ========================================================================
    // Settings rendering (placeholder for Phase 5)
    // ========================================================================
    fn render_settings(&self) -> Vec<Line<'static>> {
        let settings = [
            ("Friendly Name", &self.settings.friendly_name, true),
            ("Mediator DID", &self.settings.mediator_did, true),
            ("Org DID", &self.settings.org_did, true),
            ("Persona DID", &self.settings.persona_did, false),
        ];

        let mut lines = vec![Line::from("")];

        for (i, (label, value, editable)) in settings.iter().enumerate() {
            let is_selected = i == self.settings.selected_index;
            let prefix = if is_selected { "▸ " } else { "  " };
            let style = if is_selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };

            let edit_hint = if *editable && is_selected {
                " [Enter to edit]"
            } else if !editable {
                " (read-only)"
            } else {
                ""
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(format!("{}: ", label), style),
                Span::styled(
                    if value.len() > 50 {
                        format!("{}...", &value[..47])
                    } else {
                        value.to_string()
                    },
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
                Span::styled(edit_hint, Style::new().fg(COLOR_DARK_GRAY)),
            ]));
        }

        lines.push(Line::from(""));

        // Export/Import options
        let export_selected = self.settings.selected_index == 4;
        lines.push(Line::from(vec![
            Span::styled(
                if export_selected { "▸ " } else { "  " },
                if export_selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                },
            ),
            Span::styled(
                "Export Config",
                if export_selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                },
            ),
        ]));

        lines.push(Line::from(""));
        lines.push(Line::from("↑/↓ navigate  Enter: edit").fg(COLOR_DARK_GRAY));

        lines
    }
}

/// Render detail view for a selected inbox task.
fn render_task_detail(task: &ActiveTaskView) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    match task {
        ActiveTaskView::RelationshipRequestInbound {
            task_id,
            from_did,
            their_did,
            reason,
        } => {
            lines.push(
                Line::from("Inbound Relationship Request")
                    .fg(COLOR_SUCCESS)
                    .bold(),
            );
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("From:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(from_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("DID:   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(their_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            if let Some(reason) = reason {
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(reason.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            lines.push(Line::from(vec![
                Span::styled("Task:  ", Style::new().fg(COLOR_DARK_GRAY)),
                Span::styled(task_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("a: accept  r: reject  Esc: back").fg(COLOR_DARK_GRAY));
        }
        ActiveTaskView::VRCRequestInbound {
            task_id,
            from_did,
            reason,
        } => {
            lines.push(Line::from("Inbound VRC Request").fg(COLOR_SUCCESS).bold());
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("From:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(from_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            if let Some(reason) = reason {
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(reason.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            lines.push(Line::from(vec![
                Span::styled("Task:  ", Style::new().fg(COLOR_DARK_GRAY)),
                Span::styled(task_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("d: dismiss  Esc: back").fg(COLOR_DARK_GRAY));
        }
        ActiveTaskView::VRCIssued { task_id, issuer } => {
            lines.push(Line::from("VRC Received").fg(COLOR_SUCCESS).bold());
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Issuer: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(issuer.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Task:   ", Style::new().fg(COLOR_DARK_GRAY)),
                Span::styled(task_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("a: accept (store)  d: dismiss  Esc: back").fg(COLOR_DARK_GRAY));
        }
    }

    lines
}
