use crate::state_handler::main_page::content::{RelationshipsMode, RelationshipsState};
use openvtc::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Render the relationships panel content.
pub fn render(state: &RelationshipsState) -> Vec<Line<'static>> {
    match &state.mode {
        RelationshipsMode::Detail { index } => render_detail(state, *index),
        RelationshipsMode::NewRequest {
            did_input,
            alias_input,
            reason_input,
            active_field,
        } => render_form(did_input, alias_input, reason_input, *active_field),
        RelationshipsMode::List => render_list(state),
    }
}

fn render_list(state: &RelationshipsState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        lines.push(Line::from(msg.clone()).fg(COLOR_SUCCESS));
        lines.push(Line::from(""));
    }

    if state.relationships.is_empty() {
        lines.push(Line::from("No relationships yet").fg(COLOR_DARK_GRAY));
        lines.push(Line::from(""));
        lines.push(
            Line::from("Press 'n' to create a new relationship request.").fg(COLOR_DARK_GRAY),
        );
    } else {
        lines.push(
            Line::from(format!(" {} relationship(s)", state.relationships.len()))
                .fg(COLOR_TEXT_DEFAULT),
        );
        lines.push(Line::from(""));

        for (i, rel) in state.relationships.iter().enumerate() {
            let is_selected = i == state.selected_index;
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
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("[{}]", rel.state),
                    if rel.state == "Established" {
                        Style::new().fg(COLOR_SUCCESS)
                    } else {
                        Style::new().fg(COLOR_ORANGE)
                    },
                ),
                Span::styled("  ", Style::default()),
                Span::styled(rel.created.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("↑/↓ navigate  Enter: details  n: new request").fg(COLOR_DARK_GRAY));
    }

    lines
}

fn render_detail(state: &RelationshipsState, index: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let Some(rel) = state.relationships.get(index) else {
        lines.push(Line::from("Relationship not found").fg(COLOR_WARNING_ACCESSIBLE_RED));
        return lines;
    };

    lines.push(Line::from("Relationship Details").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));

    if let Some(alias) = &rel.alias {
        lines.push(Line::from(vec![
            Span::styled("Alias:        ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(alias.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("Remote P-DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(rel.remote_p_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Remote R-DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(rel.remote_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Our DID:      ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(rel.our_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("State:        ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(
            rel.state.clone(),
            if rel.state == "Established" {
                Style::new().fg(COLOR_SUCCESS)
            } else {
                Style::new().fg(COLOR_ORANGE)
            },
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Created:      ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(rel.created.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("VRCs sent:    ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(
            rel.vrc_sent_count.to_string(),
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("VRCs received: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(
            rel.vrc_received_count.to_string(),
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from("p: ping  d: remove  Esc: back").fg(COLOR_DARK_GRAY));

    lines
}

/// Render the new-relationship-request form.
fn render_form(
    did_input: &str,
    alias_input: &str,
    reason_input: &str,
    active_field: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from("New Relationship Request")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    let fields = [
        ("DID:    ", did_input),
        ("Alias:  ", alias_input),
        ("Reason: ", reason_input),
    ];

    for (i, (label, value)) in fields.iter().enumerate() {
        let is_active = i == active_field;
        let cursor = if is_active { "▎" } else { "" };
        let field_style = if is_active {
            Style::new().fg(COLOR_SUCCESS)
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        let value_style = if is_active {
            Style::new().fg(COLOR_SOFT_PURPLE)
        } else {
            Style::new().fg(COLOR_DARK_GRAY)
        };

        lines.push(Line::from(vec![
            Span::styled(if is_active { "▸ " } else { "  " }, field_style),
            Span::styled(label.to_string(), field_style),
            Span::styled(value.to_string(), value_style),
            Span::styled(cursor, Style::new().fg(COLOR_SUCCESS)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(
        Line::from("Tab: next field  Enter (on Reason): submit  Esc: cancel").fg(COLOR_DARK_GRAY),
    );

    lines
}
