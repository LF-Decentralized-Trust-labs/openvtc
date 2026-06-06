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
        let detail_style = if is_selected {
            Style::new().fg(COLOR_SOFT_PURPLE)
        } else {
            Style::new().fg(COLOR_DARK_GRAY)
        };
        lines.push(Line::from(Span::styled(detail, detail_style)));
    }

    lines.push(Line::from(""));
    if let Some(idx) = state.confirm_delete {
        let name = state
            .items
            .get(idx)
            .map(|c| c.display_name.as_str())
            .unwrap_or("this community");
        lines.push(
            Line::from(format!("Remove “{name}”?   y: confirm    n: cancel"))
                .fg(COLOR_ORANGE)
                .bold(),
        );
    } else {
        lines.push(
            Line::from("↑/↓ navigate   j: join a community   d: remove selected")
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
