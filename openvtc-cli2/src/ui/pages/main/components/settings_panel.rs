use crate::state_handler::main_page::content::{SettingsMode, SettingsState};
use openvtc::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
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
        SettingsMode::ChangeProtection {
            selected_option,
            passphrase_input,
            confirm_input,
            active_field,
        } => render_change_protection(
            *selected_option,
            passphrase_input,
            confirm_input,
            *active_field,
        ),
        #[cfg(feature = "openpgp-card")]
        SettingsMode::TokenManagement { selected_index } => {
            render_token_management(state, *selected_index)
        }
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

    // Protection type display (index 4)
    let prot_selected = state.selected_index == 4;
    let prot_style = if prot_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if prot_selected { "▸ " } else { "  " }, prot_style),
        Span::styled("Protection: ", prot_style),
        Span::styled(state.protection_type.clone(), Style::new().fg(COLOR_ORANGE)),
        Span::styled(
            if prot_selected {
                " [Enter to change]"
            } else {
                ""
            },
            Style::new().fg(COLOR_DARK_GRAY),
        ),
    ]));

    // Export option (index 5)
    let export_selected = state.selected_index == 5;
    let export_style = if export_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if export_selected { "▸ " } else { "  " }, export_style),
        Span::styled("Export Config", export_style),
    ]));

    // Token management option (index 6, only with openpgp-card)
    #[cfg(feature = "openpgp-card")]
    {
        let token_selected = state.selected_index == 6;
        let token_style = if token_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if token_selected { "▸ " } else { "  " }, token_style),
            Span::styled("Hardware Token Management", token_style),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("↑/↓ navigate  Enter: edit/open").fg(COLOR_DARK_GRAY));

    lines
}

#[cfg(feature = "openpgp-card")]
fn render_token_management(state: &SettingsState, selected_index: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from("Hardware Token Management")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    // Token status
    let detected = state.token.detected_count;
    if detected > 0 {
        lines.push(Line::from(format!("  Tokens detected: {}", detected)).fg(COLOR_SUCCESS));
    } else {
        lines.push(Line::from("  No tokens detected").fg(COLOR_ORANGE));
    }
    lines.push(Line::from(""));

    // Action items
    let actions = ["Detect Tokens", "Factory Reset"];

    for (i, label) in actions.iter().enumerate() {
        let is_selected = i == selected_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![Span::styled(
            format!("{}{}", prefix, label),
            style,
        )]));
    }

    // Messages from token operations
    if !state.token.messages.is_empty() {
        lines.push(Line::from(""));
        for msg in &state.token.messages {
            lines.push(Line::from(format!("  {}", msg)).fg(COLOR_TEXT_DEFAULT));
        }
    }

    if state.token.reset_completed {
        lines.push(Line::from(""));
        lines.push(Line::from("  Factory reset completed.").fg(COLOR_SUCCESS));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("↑/↓ navigate  Enter: execute  Esc: back").fg(COLOR_DARK_GRAY));

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

fn render_change_protection(
    selected_option: usize,
    passphrase_input: &str,
    confirm_input: &str,
    active_field: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from("Change Config Protection")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    if active_field == 0 {
        // Option selection mode
        let options = ["Set Passphrase", "Remove Passphrase (keyring only)"];
        for (i, label) in options.iter().enumerate() {
            let is_selected = i == selected_option;
            let style = if is_selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            lines.push(Line::from(vec![Span::styled(
                format!("{}{}", if is_selected { "▸ " } else { "  " }, label),
                style,
            )]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("↑/↓ select  Enter: choose  Esc: cancel").fg(COLOR_DARK_GRAY));
    } else {
        // Passphrase input mode
        lines.push(Line::from(vec![
            Span::styled(
                if active_field == 1 { "▸ " } else { "  " },
                Style::new().fg(if active_field == 1 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled(
                "Passphrase: ",
                Style::new().fg(if active_field == 1 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled(
                "*".repeat(passphrase_input.len()),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Span::styled(
                if active_field == 1 { "▎" } else { "" },
                Style::new().fg(COLOR_SUCCESS),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled(
                if active_field == 2 { "▸ " } else { "  " },
                Style::new().fg(if active_field == 2 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled(
                "Confirm:    ",
                Style::new().fg(if active_field == 2 {
                    COLOR_SUCCESS
                } else {
                    COLOR_TEXT_DEFAULT
                }),
            ),
            Span::styled(
                "*".repeat(confirm_input.len()),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Span::styled(
                if active_field == 2 { "▎" } else { "" },
                Style::new().fg(COLOR_SUCCESS),
            ),
        ]));

        if !passphrase_input.is_empty()
            && !confirm_input.is_empty()
            && passphrase_input != confirm_input
        {
            lines.push(Line::from(""));
            lines.push(Line::from("  Passphrases do not match").fg(COLOR_ORANGE));
        }

        lines.push(Line::from(""));
        lines.push(
            Line::from("Tab: next field  Enter (on confirm): save  Esc: cancel")
                .fg(COLOR_DARK_GRAY),
        );
    }

    lines
}
