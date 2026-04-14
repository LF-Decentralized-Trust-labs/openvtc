use crate::state_handler::{
    main_page::{
        content::ContentPanelState,
        menu::{MainMenu, MenuPanelState},
    },
    state::{ConnectionState, MediatorStatus},
};
use openvtc::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Style, Stylize},
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph},
};

use super::{
    credentials_panel::CredentialsPanel,
    inbox_panel::InboxPanel,
    panel::Panel,
    relationships_panel::RelationshipsPanel,
    settings_panel::SettingsPanel,
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

        let panel: Option<Box<dyn Panel>> = match menu.selected_menu {
            MainMenu::Inbox => Some(Box::new(InboxPanel)),
            MainMenu::Relationships => Some(Box::new(RelationshipsPanel)),
            MainMenu::Credentials => Some(Box::new(CredentialsPanel)),
            MainMenu::Settings => Some(Box::new(SettingsPanel)),
            _ => None,
        };

        let lines = if let Some(p) = panel {
            p.render(self, connection)
        } else {
            match menu.selected_menu {
                MainMenu::Help => render_status_help(
                    &self.settings,
                    &self.inbox,
                    &self.relationships,
                    &self.credentials,
                    connection,
                ),
                MainMenu::Quit => {
                    vec![
                        Line::from(""),
                        Line::from("Press <Enter> to quit the application")
                            .fg(COLOR_WARNING_ACCESSIBLE_RED),
                    ]
                }
                // Covered by the Panel trait above; included for exhaustiveness.
                _ => vec![],
            }
        };

        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Left)
                .block(content_block),
            rect,
        );
    }
}

/// Render the combined status + help panel.
fn render_status_help(
    settings: &crate::state_handler::main_page::content::SettingsState,
    inbox: &crate::state_handler::main_page::content::InboxState,
    relationships: &crate::state_handler::main_page::content::RelationshipsState,
    credentials: &crate::state_handler::main_page::content::CredentialsState,
    connection: &ConnectionState,
) -> Vec<Line<'static>> {
    let label_style = Style::new().fg(COLOR_TEXT_DEFAULT);
    let value_style = Style::new().fg(COLOR_SOFT_PURPLE);

    let mut lines = vec![
        Line::from(""),
        Line::from(" Status").fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];

    // Persona DID (full)
    lines.push(Line::from(vec![
        Span::styled("  Persona DID:  ", label_style),
        Span::styled(settings.persona_did.clone(), value_style),
    ]));

    // Mediator DID (full)
    lines.push(Line::from(vec![
        Span::styled("  Mediator DID: ", label_style),
        Span::styled(settings.mediator_did.clone(), value_style),
    ]));

    // Protection type
    lines.push(Line::from(vec![
        Span::styled("  Protection:   ", label_style),
        Span::styled(settings.protection_type.clone(), value_style),
    ]));

    lines.push(Line::from(""));

    // Counts
    let rel_count = relationships.relationships.len();
    let task_count = inbox.tasks.len();
    let vrc_received = credentials.received.len();
    let vrc_issued = credentials.issued.len();

    lines.push(Line::from(vec![
        Span::styled("  Relationships: ", label_style),
        Span::styled(rel_count.to_string(), value_style),
        Span::styled("    Tasks: ", label_style),
        Span::styled(task_count.to_string(), value_style),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  VRCs received: ", label_style),
        Span::styled(vrc_received.to_string(), value_style),
        Span::styled("    VRCs issued: ", label_style),
        Span::styled(vrc_issued.to_string(), value_style),
    ]));

    lines.push(Line::from(""));

    // Connection status with latency
    let conn_line = match &connection.status {
        MediatorStatus::Connected { latency_ms } => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled("Connected", Style::new().fg(COLOR_SUCCESS)),
            Span::styled(
                format!(" ({}ms)", latency_ms),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
        ]),
        MediatorStatus::Connecting => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled("Connecting...", label_style),
        ]),
        MediatorStatus::Failed(reason) => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled(
                format!("Failed: {}", reason),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
            ),
        ]),
        MediatorStatus::Initializing(step) => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled(format!("Initializing: {}", step), label_style),
        ]),
        MediatorStatus::Unknown => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled("Not connected", Style::new().fg(COLOR_DARK_GRAY)),
        ]),
    };
    lines.push(conn_line);

    // Keyboard shortcuts section
    lines.push(Line::from(""));
    lines.push(Line::from(" Keyboard Shortcuts").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));
    lines.push(Line::from("  Up/Down        Navigate").fg(COLOR_TEXT_DEFAULT));
    lines.push(Line::from("  Enter          Select / open").fg(COLOR_TEXT_DEFAULT));
    lines.push(Line::from("  Tab / L / R    Switch panels").fg(COLOR_TEXT_DEFAULT));
    lines.push(Line::from("  Esc            Go back").fg(COLOR_TEXT_DEFAULT));
    lines.push(Line::from("  F10            Quit").fg(COLOR_TEXT_DEFAULT));

    lines
}
