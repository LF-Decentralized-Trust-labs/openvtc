use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::{
    main_page::content::{CommunitiesState, ContentPanelState},
    state::ConnectionState,
};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Communities overview content panel (R-C-1..R-C-8).
pub struct CommunitiesPanel;

impl Panel for CommunitiesPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.communities)
    }
}

/// Render the communities panel content.
pub fn render(state: &CommunitiesState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        super::status::push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }

    if state.items.is_empty() {
        return render_empty(lines);
    }

    // Header with actions-required count (R-C-3).
    if state.actions_required > 0 {
        lines.push(
            Line::from(format!(
                " ● {} communit{} need your attention",
                state.actions_required,
                if state.actions_required == 1 {
                    "y"
                } else {
                    "ies"
                }
            ))
            .fg(COLOR_ORANGE),
        );
    } else {
        lines.push(
            Line::from(format!(
                " {} communit{}",
                state.items.len(),
                if state.items.len() == 1 { "y" } else { "ies" }
            ))
            .fg(COLOR_TEXT_DEFAULT),
        );
    }
    lines.push(Line::from(""));

    for (i, c) in state.items.iter().enumerate() {
        let is_selected = i == state.selected_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let name_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else if c.is_inactive {
            // Inactive communities are read-only (D14) — dimmed in the list.
            Style::new().fg(COLOR_DARK_GRAY)
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        let star = if c.favourite { "★ " } else { "  " };
        let attention = if c.needs_attention { " ●" } else { "" };

        lines.push(Line::from(vec![
            Span::styled(prefix, name_style),
            Span::styled(star, Style::new().fg(COLOR_ORANGE)),
            Span::styled(c.display_name.clone(), name_style),
            Span::styled(attention, Style::new().fg(COLOR_ORANGE)),
        ]));

        // Secondary line: status · persona · member-since.
        let mut detail = format!("    {}", c.status_label);
        if !c.persona_label.is_empty() {
            detail.push_str(&format!("  ·  as {}", c.persona_label));
        }
        if !c.member_since.is_empty() {
            detail.push_str(&format!("  ·  since {}", c.member_since));
        }
        if c.archived {
            detail.push_str("  ·  archived");
        }
        let detail_style = if is_selected {
            Style::new().fg(COLOR_SOFT_PURPLE)
        } else {
            Style::new().fg(COLOR_DARK_GRAY)
        };
        lines.push(Line::from(Span::styled(detail, detail_style)));

        // Expanded troubleshooting detail for the selected community: which
        // persona this community actually uses (full DID), the VTC, the
        // sub-context, the in-flight request id, and which credentials are held.
        if is_selected {
            let label = Style::new().fg(COLOR_DARK_GRAY);
            let value = Style::new().fg(COLOR_TEXT_DEFAULT);
            let kv = |k: &str, v: String| {
                Line::from(vec![
                    Span::styled(format!("      {k:<13}"), label),
                    Span::styled(v, value),
                ])
            };
            lines.push(kv("Persona DID:", c.persona_did.clone()));
            lines.push(kv("VTC DID:", c.vtc_did.clone()));
            if !c.sub_context_id.is_empty() {
                lines.push(kv("Sub-context:", c.sub_context_id.clone()));
            }
            if !c.request_id.is_empty() {
                lines.push(kv("Request ID:", c.request_id.clone()));
            }
            lines.push(kv(
                "Credentials:",
                format!(
                    "membership {}   role {}",
                    if c.has_membership_credential {
                        "✓"
                    } else {
                        "—"
                    },
                    if c.has_role_credential { "✓" } else { "—" },
                ),
            ));
        }
    }

    lines.push(Line::from(""));
    let confirm_name = |idx: usize| {
        state
            .items
            .get(idx)
            .map(|c| c.display_name.clone())
            .unwrap_or_else(|| "this community".to_string())
    };
    if let Some(idx) = state.confirm_delete {
        lines.push(
            Line::from(format!(
                "Delete “{}”?   y: confirm    n: cancel",
                confirm_name(idx)
            ))
            .fg(COLOR_ORANGE)
            .bold(),
        );
    } else if let Some(idx) = state.confirm_leave {
        lines.push(
            Line::from(format!(
                "Leave “{}”? This sends a self-removal to the community.   y: confirm    n: cancel",
                confirm_name(idx)
            ))
            .fg(COLOR_ORANGE)
            .bold(),
        );
    } else {
        let archived_hint = if state.show_archived {
            "v: hide archived"
        } else {
            "v: show archived"
        };
        lines.push(
            Line::from(format!(
                "↑/↓ navigate   ⏎ open   f: ★   a: acknowledge   l: leave   \
                 x: archive   d: delete   j: join   {archived_hint}"
            ))
            .fg(COLOR_DARK_GRAY),
        );
    }

    lines
}

/// Empty state (R-C-5): a welcoming nudge to go find a community, not a dry
/// "no items" message.
fn render_empty(mut lines: Vec<Line<'static>>) -> Vec<Line<'static>> {
    lines.push(
        Line::from("Your account is ready. 🎉")
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from("You haven't joined any communities yet — that's where the fun begins.")
            .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(
        Line::from("Find a Verifiable Trust Community and present an identity to join it.")
            .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));
    lines.push(Line::from("Press  j  to join your first community.").fg(COLOR_ORANGE));
    lines
}
