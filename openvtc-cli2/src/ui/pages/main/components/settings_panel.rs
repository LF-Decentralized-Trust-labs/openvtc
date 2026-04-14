use crate::state_handler::main_page::content::{SettingsMode, SettingsState};
use openvtc::colors::{COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Render the settings panel content.
pub fn render(state: &SettingsState) -> Vec<Line<'static>> {
    match &state.mode {
        SettingsMode::EditFriendlyName { input } => render_edit("Friendly Name", input),
        SettingsMode::EditMediatorDid { input } => render_edit("Mediator DID", input),
        SettingsMode::EditOrgDid { input } => render_edit("Org DID", input),
        SettingsMode::ExportConfig {
            path_input,
            passphrase_input,
            active_field,
        } => render_export_form(path_input, passphrase_input, *active_field),
        SettingsMode::View => render_view(state),
    }
}

fn render_view(state: &SettingsState) -> Vec<Line<'static>> {
    let settings = [
        ("Friendly Name", &state.friendly_name, true),
        ("Mediator DID", &state.mediator_did, true),
        ("Org DID", &state.org_did, true),
        ("Persona DID", &state.persona_did, false),
    ];

    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        lines.push(Line::from(msg.clone()).fg(COLOR_SUCCESS));
        lines.push(Line::from(""));
    }

    for (i, (label, value, editable)) in settings.iter().enumerate() {
        let is_selected = i == state.selected_index;
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

    let export_selected = state.selected_index == 4;
    let export_style = if export_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if export_selected { "▸ " } else { "  " }, export_style),
        Span::styled("Export Config", export_style),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from("↑/↓ navigate  Enter: edit/open").fg(COLOR_DARK_GRAY));

    lines
}

/// Render inline edit for a settings field.
fn render_edit(label: &str, input: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(""),
        Line::from(format!("Editing: {}", label))
            .fg(COLOR_SUCCESS)
            .bold(),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(input.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
            Span::styled("▎", Style::new().fg(COLOR_SUCCESS)),
        ]),
        Line::from(""),
        Line::from("Enter: save  Esc: cancel").fg(COLOR_DARK_GRAY),
    ]
}

/// Render the export config form with path and passphrase fields.
fn render_export_form(
    path_input: &str,
    passphrase_input: &str,
    active_field: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(""),
        Line::from("Export Config").fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];

    let fields = [
        ("File path:  ", path_input),
        ("Passphrase: ", passphrase_input),
    ];

    for (i, (label, value)) in fields.iter().enumerate() {
        let is_active = i == active_field;
        let cursor = if is_active { "▎" } else { "" };
        let field_style = if is_active {
            Style::new().fg(COLOR_SUCCESS)
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        // Mask passphrase
        let display_value = if i == 1 {
            "*".repeat(value.len())
        } else {
            value.to_string()
        };

        lines.push(Line::from(vec![
            Span::styled(if is_active { "▸ " } else { "  " }, field_style),
            Span::styled(label.to_string(), field_style),
            Span::styled(display_value, Style::new().fg(COLOR_SOFT_PURPLE)),
            Span::styled(cursor, Style::new().fg(COLOR_SUCCESS)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(
        Line::from("Tab: switch field  Enter (on passphrase): export  Esc: cancel")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}
