//! Logs panel — scrollable activity log with selection and clipboard copy.

use crate::state_handler::main_page::{ActivityLogEntry, content::LogsState};
use openvtc::colors::{COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
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

/// Simple word-wrap: break text into lines of at most `width` characters.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            result.push(current_line);
            current_line = word.to_string();
        }
    }
    if !current_line.is_empty() {
        result.push(current_line);
    }
    if result.is_empty() {
        result.push(String::new());
    }
    result
}
