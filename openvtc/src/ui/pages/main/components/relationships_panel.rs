use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{ContentPanelState, RelationshipsMode, RelationshipsState},
    state::ConnectionState,
};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Relationships content panel.
pub struct RelationshipsPanel;

impl Panel for RelationshipsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.relationships)
    }
}

/// Render the relationships panel content.
pub fn render(state: &RelationshipsState) -> Vec<Line<'static>> {
    match &state.mode {
        RelationshipsMode::EditAlias { index, alias_input } => {
            render_edit_alias(state, *index, alias_input)
        }
        RelationshipsMode::Detail {
            index,
            selected_vrc,
        } => render_detail(state, *index, *selected_vrc),
        RelationshipsMode::NewRequest {
            did_input,
            alias_input,
            reason_input,
            generate_r_did,
            active_field,
        } => render_form(
            did_input,
            alias_input,
            reason_input,
            *generate_r_did,
            *active_field,
        ),
        RelationshipsMode::List => render_list(state),
    }
}

fn render_list(state: &RelationshipsState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        super::status::push_status(&mut lines, msg, "");
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

            let mut spans = vec![
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
            ];
            // Surface relationships whose R-DID keys were lost and could not be
            // recovered at load: they can no longer send or receive and must be
            // re-established. (See `Relationship::needs_reestablishment`.)
            if rel.needs_reestablishment {
                spans.push(Span::styled("  ", Style::default()));
                spans.push(Span::styled(
                    "⚠ needs re-establishment",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ));
            }
            lines.push(Line::from(spans));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("↑/↓ navigate  Enter: details  n: new request").fg(COLOR_DARK_GRAY));
    }

    lines
}

fn render_detail(
    state: &RelationshipsState,
    index: usize,
    selected_vrc: Option<usize>,
) -> Vec<Line<'static>> {
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

    // Combined VRC count: issued first, then received
    let total_vrcs = rel.vrcs_issued.len() + rel.vrcs_received.len();
    if total_vrcs > 0 {
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!(
                " Credentials ({} issued, {} received)",
                rel.vrcs_issued.len(),
                rel.vrcs_received.len()
            ))
            .fg(COLOR_SUCCESS)
            .bold(),
        );
        lines.push(Line::from(""));

        let mut vrc_index: usize = 0;

        if !rel.vrcs_issued.is_empty() {
            lines.push(Line::from("  Issued").fg(COLOR_TEXT_DEFAULT).bold());
            for vrc in &rel.vrcs_issued {
                let is_selected = selected_vrc == Some(vrc_index);
                let validity = match &vrc.valid_until {
                    Some(until) => format!("{} -> {}", vrc.valid_from, until),
                    None => format!("{} -> no expiry", vrc.valid_from),
                };
                let bullet_style = if is_selected {
                    Style::new().fg(COLOR_ORANGE).bold()
                } else {
                    Style::new().fg(COLOR_SUCCESS)
                };
                let text_style = if is_selected {
                    Style::new().fg(COLOR_ORANGE).bold()
                } else {
                    Style::new().fg(COLOR_SOFT_PURPLE)
                };
                let prefix = if is_selected { "  ▸ " } else { "    " };
                lines.push(Line::from(vec![
                    Span::styled(prefix, bullet_style),
                    Span::styled("● ", bullet_style),
                    Span::styled(format!("To: {}  ", vrc.subject), text_style),
                    Span::styled(
                        validity,
                        if is_selected {
                            Style::new().fg(COLOR_ORANGE)
                        } else {
                            Style::new().fg(COLOR_DARK_GRAY)
                        },
                    ),
                ]));

                // Show expanded detail when selected
                if is_selected {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("      Issuer:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(vrc.issuer_full.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("      Subject: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(vrc.subject_full.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                    let validity_detail = match &vrc.valid_until {
                        Some(until) => format!("{} -> {}", vrc.valid_from, until),
                        None => format!("{} -> no expiry", vrc.valid_from),
                    };
                    lines.push(Line::from(vec![
                        Span::styled("      Valid:   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(validity_detail, Style::new().fg(COLOR_TEXT_DEFAULT)),
                    ]));
                    lines.push(Line::from(""));
                    // Pretty-print the credential lazily, only for the expanded
                    // (selected) VRC — not eagerly per credential on every sync.
                    let raw_json = vrc.raw_json.to_pretty_json();
                    for json_line in raw_json.lines() {
                        lines.push(Line::from(format!("      {}", json_line)).fg(COLOR_DARK_GRAY));
                    }
                    lines.push(Line::from(""));
                }

                vrc_index += 1;
            }
        }

        if !rel.vrcs_received.is_empty() {
            if !rel.vrcs_issued.is_empty() {
                lines.push(Line::from(""));
            }
            lines.push(Line::from("  Received").fg(COLOR_TEXT_DEFAULT).bold());
            for vrc in &rel.vrcs_received {
                let is_selected = selected_vrc == Some(vrc_index);
                let validity = match &vrc.valid_until {
                    Some(until) => format!("{} -> {}", vrc.valid_from, until),
                    None => format!("{} -> no expiry", vrc.valid_from),
                };
                let bullet_style = if is_selected {
                    Style::new().fg(COLOR_ORANGE).bold()
                } else {
                    Style::new().fg(COLOR_SUCCESS)
                };
                let text_style = if is_selected {
                    Style::new().fg(COLOR_ORANGE).bold()
                } else {
                    Style::new().fg(COLOR_SOFT_PURPLE)
                };
                let prefix = if is_selected { "  ▸ " } else { "    " };
                lines.push(Line::from(vec![
                    Span::styled(prefix, bullet_style),
                    Span::styled("● ", bullet_style),
                    Span::styled(format!("From: {}  ", vrc.issuer), text_style),
                    Span::styled(
                        validity,
                        if is_selected {
                            Style::new().fg(COLOR_ORANGE)
                        } else {
                            Style::new().fg(COLOR_DARK_GRAY)
                        },
                    ),
                ]));

                // Show expanded detail when selected
                if is_selected {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("      Issuer:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(vrc.issuer_full.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("      Subject: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(vrc.subject_full.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                    let validity_detail = match &vrc.valid_until {
                        Some(until) => format!("{} -> {}", vrc.valid_from, until),
                        None => format!("{} -> no expiry", vrc.valid_from),
                    };
                    lines.push(Line::from(vec![
                        Span::styled("      Valid:   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(validity_detail, Style::new().fg(COLOR_TEXT_DEFAULT)),
                    ]));
                    lines.push(Line::from(""));
                    // Pretty-print the credential lazily, only for the expanded
                    // (selected) VRC — not eagerly per credential on every sync.
                    let raw_json = vrc.raw_json.to_pretty_json();
                    for json_line in raw_json.lines() {
                        lines.push(Line::from(format!("      {}", json_line)).fg(COLOR_DARK_GRAY));
                    }
                    lines.push(Line::from(""));
                }

                vrc_index += 1;
            }
        }
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("  No credentials exchanged yet").fg(COLOR_DARK_GRAY));
    }

    lines.push(Line::from(""));
    // A pending removal confirmation replaces the footer hint (R25).
    if state.confirm_delete.is_some() {
        lines.push(
            Line::from("Remove this relationship?   y: confirm    n: cancel")
                .fg(COLOR_ORANGE)
                .bold(),
        );
    } else {
        lines.push(
            Line::from(
                "e: edit alias  p: ping  v: request VRC  d: remove  \u{2191}/\u{2193}: browse VRCs  Esc: back",
            )
            .fg(COLOR_DARK_GRAY),
        );
    }

    lines
}

fn render_edit_alias(
    state: &RelationshipsState,
    index: usize,
    alias_input: &str,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let Some(rel) = state.relationships.get(index) else {
        lines.push(Line::from("Relationship not found").fg(COLOR_WARNING_ACCESSIBLE_RED));
        return lines;
    };

    lines.push(Line::from("Edit Alias").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Remote P-DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled(rel.remote_p_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("▸ Alias: ", Style::new().fg(COLOR_SUCCESS)),
        Span::styled(alias_input.to_string(), Style::new().fg(COLOR_SOFT_PURPLE)),
        Span::styled("▎", Style::new().fg(COLOR_SUCCESS)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from("Enter: save  Esc: cancel").fg(COLOR_DARK_GRAY));

    lines
}

/// Render the new-relationship-request form.
fn render_form(
    did_input: &str,
    alias_input: &str,
    reason_input: &str,
    generate_r_did: bool,
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

    // R-DID toggle (field index 3)
    let is_active = active_field == 3;
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
    let toggle_value = if generate_r_did { "Yes" } else { "No" };
    lines.push(Line::from(vec![
        Span::styled(if is_active { "▸ " } else { "  " }, field_style),
        Span::styled("[Space] Generate random R-DID: ".to_string(), field_style),
        Span::styled(toggle_value.to_string(), value_style),
    ]));

    lines.push(Line::from(""));
    lines.push(
        Line::from("Tab: next field  Space: toggle R-DID  Enter (on R-DID): submit  Esc: cancel")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}
