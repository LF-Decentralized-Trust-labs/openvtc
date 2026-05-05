//! Logs panel — scrollable activity log with selection and clipboard copy.

use super::status::wrap_text;
use crate::colors::{COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use crate::state_handler::main_page::{ActivityLogEntry, content::LogsState};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};
use std::collections::VecDeque;

/// Render the logs panel as a scrollable list of activity log entries.
///
/// Entries are shown newest-first with a selection highlight.
/// Hotkeys: Enter = view detail, c = copy selected, a = copy all, Esc = back.
pub fn render(
    logs_state: &LogsState,
    activity_log: &VecDeque<ActivityLogEntry>,
) -> Vec<Line<'static>> {
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

    let entries: Vec<&ActivityLogEntry> = activity_log.iter().rev().collect();

    // Detail view — show full text of the selected entry
    if logs_state.detail_view {
        if let Some(entry) = entries.get(logs_state.selected_index) {
            lines.push(
                Line::from(format!(
                    " Entry {} of {}",
                    logs_state.selected_index + 1,
                    total
                ))
                .fg(COLOR_DARK_GRAY),
            );
            lines.push(Line::from(""));

            // Show detail if available, otherwise show the summary
            let display_text = entry.detail.as_deref().unwrap_or(&entry.summary);

            // Word-wrap the full entry text at ~76 chars per line
            for wrapped_line in wrap_text(display_text, 76) {
                lines.push(Line::from(vec![Span::styled(
                    format!("  {}", wrapped_line),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                )]));
            }

            lines.push(Line::from(""));
            lines.push(
                Line::from("  Enter/Esc: back to list  c: copy to clipboard").fg(COLOR_DARK_GRAY),
            );
        }
        return lines;
    }

    // List view — show entries with truncation
    for (i, entry) in entries.iter().enumerate() {
        let is_selected = i == logs_state.selected_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        // Truncate long entries for list display
        let display = if entry.summary.len() > 80 {
            format!("{}...", &entry.summary[..77])
        } else {
            entry.summary.clone()
        };

        lines.push(Line::from(vec![Span::styled(
            format!("{}{}", prefix, display),
            style,
        )]));
    }

    lines.push(Line::from(""));
    lines.push(
        Line::from("  ↑/↓ navigate  Enter: view detail  c: copy selected  a: copy all  Esc: back")
            .fg(COLOR_DARK_GRAY),
    );

    lines
}
