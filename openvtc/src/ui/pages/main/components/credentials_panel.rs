use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{
        ContentPanelState, CredentialTab, CredentialsMode, CredentialsState, RelationshipsState,
    },
    state::ConnectionState,
};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Credentials content panel.
pub struct CredentialsPanel;

impl Panel for CredentialsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.credentials, &state.relationships)
    }
}

/// Render the credentials panel content.
pub fn render(
    credentials: &CredentialsState,
    relationships: &RelationshipsState,
) -> Vec<Line<'static>> {
    match &credentials.mode {
        CredentialsMode::Detail { index } => render_detail(credentials, *index),
        CredentialsMode::NewRequest {
            relationship_index,
            reason_input,
        } => render_new_request(relationships, *relationship_index, reason_input),
        CredentialsMode::List => render_list(credentials),
    }
}

fn render_list(state: &CredentialsState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        super::status::push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }

    let active_list = match state.selected_tab {
        CredentialTab::Received => &state.received,
        CredentialTab::Issued => &state.issued,
    };

    // Tab bar
    let (recv_style, issued_style) = match state.selected_tab {
        CredentialTab::Received => (
            Style::new().fg(COLOR_SUCCESS).bold(),
            Style::new().fg(COLOR_DARK_GRAY),
        ),
        CredentialTab::Issued => (
            Style::new().fg(COLOR_DARK_GRAY),
            Style::new().fg(COLOR_SUCCESS).bold(),
        ),
    };

    lines.push(Line::from(vec![
        Span::styled(format!(" Received ({}) ", state.received.len()), recv_style),
        Span::styled(" | ", Style::new().fg(COLOR_DARK_GRAY)),
        Span::styled(format!(" Issued ({}) ", state.issued.len()), issued_style),
    ]));
    lines.push(Line::from(""));

    if active_list.is_empty() {
        lines.push(Line::from("No credentials").fg(COLOR_DARK_GRAY));
    } else {
        for (i, vrc) in active_list.iter().enumerate() {
            let is_selected = i == state.selected_index;
            let prefix = if is_selected { "▸ " } else { "  " };
            let style = if is_selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };

            let display_name = vrc
                .alias
                .as_deref()
                .unwrap_or(&vrc.remote_p_did)
                .to_string();

            let date_display = if let Some(until) = &vrc.valid_until {
                format!("{} → {}", vrc.valid_from, until)
            } else {
                vrc.valid_from.clone()
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(display_name, style),
                Span::styled("  ", Style::default()),
                Span::styled(date_display, Style::new().fg(COLOR_DARK_GRAY)),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(
        Line::from("Tab: switch tab  ↑/↓ navigate  Enter: details  n: request VRC")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}

fn render_detail(state: &CredentialsState, index: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let active_list = match state.selected_tab {
        CredentialTab::Received => &state.received,
        CredentialTab::Issued => &state.issued,
    };

    let Some(vrc) = active_list.get(index) else {
        lines.push(Line::from("Credential not found").fg(COLOR_WARNING_ACCESSIBLE_RED));
        return lines;
    };

    lines.push(Line::from("Credential Details").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));

    if let Some(alias) = &vrc.alias {
        lines.push(Line::from(vec![
            Span::styled("Contact:    ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(alias.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("Remote DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(vrc.remote_p_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Issuer:     ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(vrc.issuer.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Subject:    ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(vrc.subject.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Valid from: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(vrc.valid_from.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
    ]));
    if let Some(until) = &vrc.valid_until {
        lines.push(Line::from(vec![
            Span::styled("Valid until: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(until.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("VRC ID:     ", Style::new().fg(COLOR_DARK_GRAY)),
        Span::styled(vrc.vrc_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
    ]));

    // Raw credential JSON
    lines.push(Line::from(""));
    lines.push(Line::from(" Raw Credential").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));
    for json_line in vrc.raw_json.lines() {
        lines.push(Line::from(format!("  {}", json_line)).fg(COLOR_DARK_GRAY));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("d: remove  c: copy JSON  Esc: back").fg(COLOR_DARK_GRAY));

    lines
}

fn render_new_request(
    relationships: &RelationshipsState,
    relationship_index: usize,
    reason_input: &str,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from("Request VRC — Select Relationship")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    let established: Vec<_> = relationships
        .relationships
        .iter()
        .filter(|r| r.state == "Established")
        .collect();

    if established.is_empty() {
        lines.push(
            Line::from("No established relationships available.").fg(COLOR_WARNING_ACCESSIBLE_RED),
        );
        lines.push(Line::from(""));
        lines.push(Line::from("Esc: back").fg(COLOR_DARK_GRAY));
        return lines;
    }

    for (i, rel) in established.iter().enumerate() {
        let is_selected = i == relationship_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        let display_name = rel
            .alias
            .as_deref()
            .unwrap_or(&rel.remote_p_did)
            .to_string();

        lines.push(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(display_name, style),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Reason: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(reason_input.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
        Span::styled("▎", Style::new().fg(COLOR_SUCCESS)),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from("↑/↓ select  Enter: send request  Esc: cancel").fg(COLOR_DARK_GRAY));

    lines
}
