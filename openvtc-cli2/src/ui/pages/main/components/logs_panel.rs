//! Logs panel — scrollable activity log with selection and clipboard copy.

use crate::state_handler::main_page::content::LogsState;
use openvtc::colors::{COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};
use std::collections::VecDeque;

/// Render the logs panel as a scrollable list of activity log entries.
///
/// Entries are shown newest-first with a selection highlight.
/// Hotkeys: c = copy selected, a = copy all, Esc = back.
pub fn render(logs_state: &LogsState, activity_log: &VecDeque<String>) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let total = activity_log.len();
    lines.push(
        Line::from(format!(" Activity Log ({} entries)", total))
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    if total == 0 {
        lines.push(Line::from("  No log entries yet.").fg(COLOR_DARK_GRAY));
        lines.push(Line::from(""));
        lines.push(
            Line::from("  Activity will appear here as you use the app.").fg(COLOR_DARK_GRAY),
        );
        return lines;
    }

    // Show entries newest-first with selection highlight
    let entries: Vec<&String> = activity_log.iter().rev().collect();

    for (i, entry) in entries.iter().enumerate() {
        let is_selected = i == logs_state.selected_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        // Truncate long entries for list display
        let display = if entry.len() > 80 {
            format!("{}...", &entry[..77])
        } else {
            entry.to_string()
        };

        lines.push(Line::from(vec![Span::styled(
            format!("{}{}", prefix, display),
            style,
        )]));
    }

    lines.push(Line::from(""));
    lines.push(
        Line::from("  ↑/↓ navigate  c: copy selected  a: copy all  Esc: back").fg(COLOR_DARK_GRAY),
    );

    lines
}
