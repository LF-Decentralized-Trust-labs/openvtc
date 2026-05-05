use super::panel::Panel;
use super::status::push_status;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{ContentPanelState, SettingsMode, SettingsState},
    state::ConnectionState,
};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Settings content panel.
pub struct SettingsPanel;

impl Panel for SettingsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.settings)
    }
}

/// Render the settings panel content.
pub fn render(state: &SettingsState) -> Vec<Line<'static>> {
    match &state.mode {
        SettingsMode::EditFriendlyName { input } => render_edit("Friendly Name", input),
        SettingsMode::EditMediatorDid { input } => render_edit("Mediator DID", input),
        SettingsMode::EditOrgDid { input } => render_edit("Org DID", input),
        SettingsMode::ExportConfig {
            path_input,
            passphrase_len,
            active_field,
        } => render_export_form("Export Config", path_input, *passphrase_len, *active_field),
        SettingsMode::ImportConfig {
            path_input,
            passphrase_len,
            active_field,
        } => render_export_form("Import Config", path_input, *passphrase_len, *active_field),
        SettingsMode::ChangeProtection {
            selected_option,
            passphrase_len,
            confirm_len,
            active_field,
        } => render_change_protection(
            *selected_option,
            *passphrase_len,
            *confirm_len,
            *active_field,
        ),
        #[cfg(feature = "openpgp-card")]
        SettingsMode::TokenManagement { selected_index } => {
            render_token_management(state, *selected_index)
        }
        SettingsMode::WipeConfirm { confirm_input } => render_wipe_confirm(confirm_input),
        SettingsMode::View => render_view(state),
    }
}

const WIPE_CONFIRM_TOKEN: &str = "WIPE";

fn render_wipe_confirm(confirm_input: &str) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(" Wipe profile")
            .fg(COLOR_WARNING_ACCESSIBLE_RED)
            .bold(),
    );
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  This will permanently remove this profile from this host:",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "    • openvtc config file",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::styled(
        "    • openvtc keyring entry (secured config)",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::styled(
        "    • did-git-sign config + keyring entries (if installed)",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::styled(
        "    • git config keys did-git-sign owns",
        Style::new().fg(COLOR_TEXT_DEFAULT),
    ));
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  Your VTA-side context, persona DID, and keys are NOT affected.",
        Style::new().fg(COLOR_DARK_GRAY),
    ));
    lines.push(Line::styled(
        "  If you want to clean those up too, run `pnm contexts delete` first.",
        Style::new().fg(COLOR_DARK_GRAY),
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Type ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(
            WIPE_CONFIRM_TOKEN,
            Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
        ),
        Span::styled(
            " to confirm and press Enter:",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  > ", Style::new().fg(COLOR_SOFT_PURPLE).bold()),
        Span::styled(
            confirm_input.to_string(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from("  Esc: cancel  |  Enter: confirm").fg(COLOR_DARK_GRAY));
    lines
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
        push_status(&mut lines, msg, "");
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

    // Import option (index 6)
    let import_selected = state.selected_index == 6;
    let import_style = if import_selected {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if import_selected { "▸ " } else { "  " }, import_style),
        Span::styled("Import Config", import_style),
    ]));

    // Token management option (index 7, only with openpgp-card)
    #[cfg(feature = "openpgp-card")]
    {
        let token_selected = state.selected_index == 7;
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

    // Wipe profile (index 7 without openpgp-card, 8 with).
    #[cfg(feature = "openpgp-card")]
    let wipe_index: usize = 8;
    #[cfg(not(feature = "openpgp-card"))]
    let wipe_index: usize = 7;
    let wipe_selected = state.selected_index == wipe_index;
    let wipe_style = if wipe_selected {
        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if wipe_selected { "▸ " } else { "  " }, wipe_style),
        Span::styled("Wipe profile", wipe_style),
    ]));

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

/// Render a config form (export or import) with path and passphrase fields.
fn render_export_form(
    title: &str,
    path_input: &str,
    passphrase_len: usize,
    active_field: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(""),
        Line::from(title.to_string()).fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];

    // Path field (index 0)
    let path_active = active_field == 0;
    let path_style = if path_active {
        Style::new().fg(COLOR_SUCCESS)
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if path_active { "▸ " } else { "  " }, path_style),
        Span::styled("File path:  ", path_style),
        Span::styled(path_input.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
        Span::styled(
            if path_active { "▎" } else { "" },
            Style::new().fg(COLOR_SUCCESS),
        ),
    ]));

    // Passphrase field (index 1) — display masked length only
    let pass_active = active_field == 1;
    let pass_style = if pass_active {
        Style::new().fg(COLOR_SUCCESS)
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if pass_active { "▸ " } else { "  " }, pass_style),
        Span::styled("Passphrase: ", pass_style),
        Span::styled(
            "*".repeat(passphrase_len),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ),
        Span::styled(
            if pass_active { "▎" } else { "" },
            Style::new().fg(COLOR_SUCCESS),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(
        Line::from("Tab: switch field  Enter (on passphrase): export  Esc: cancel")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}

fn render_change_protection(
    selected_option: usize,
    passphrase_len: usize,
    confirm_len: usize,
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
        // Passphrase input mode — display masked lengths only
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
                "*".repeat(passphrase_len),
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
            Span::styled("*".repeat(confirm_len), Style::new().fg(COLOR_SOFT_PURPLE)),
            Span::styled(
                if active_field == 2 { "▎" } else { "" },
                Style::new().fg(COLOR_SUCCESS),
            ),
        ]));

        if passphrase_len > 0 && confirm_len > 0 && passphrase_len != confirm_len {
            lines.push(Line::from(""));
            lines.push(
                Line::from("  Passphrases may not match (different lengths)").fg(COLOR_ORANGE),
            );
        }

        lines.push(Line::from(""));
        lines.push(
            Line::from("Tab: next field  Enter (on confirm): save  Esc: cancel")
                .fg(COLOR_DARK_GRAY),
        );
    }

    lines
}
