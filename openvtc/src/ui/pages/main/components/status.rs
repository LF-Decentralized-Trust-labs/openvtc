//! Shared helpers for rendering status messages in main-page panels.
//!
//! The content `Paragraph` does not wrap, so long status messages (typically
//! multi-cause error chains) must be word-wrapped manually before being
//! pushed as `Line`s or they get clipped at the panel width.

use crate::colors::{COLOR_SUCCESS, COLOR_WARNING_ACCESSIBLE_RED};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

/// Approximate visible width of the content panel after borders and padding.
/// Panels don't know their own width at render time; this matches the width
/// used by the logs-panel detail view.
const STATUS_WRAP_WIDTH: usize = 76;

/// Push a status message as one or more wrapped lines (no trailing blank).
///
/// Messages that look like errors are rendered in the warning (red) color;
/// everything else uses the success (green) color, matching prior behavior.
/// Each wrapped line is prefixed with `indent` so callers can indent inside
/// a panel.
pub fn push_status(lines: &mut Vec<Line<'static>>, msg: &str, indent: &'static str) {
    let style = status_style(msg);
    let width = STATUS_WRAP_WIDTH.saturating_sub(indent.len()).max(1);
    for wrapped in wrap_text(msg, width) {
        lines.push(Line::from(vec![Span::styled(
            format!("{}{}", indent, wrapped),
            style,
        )]));
    }
}

fn status_style(msg: &str) -> Style {
    let trimmed = msg.trim_start();
    let is_error = trimmed.starts_with("Error")
        || trimmed.starts_with("Failed")
        || trimmed.starts_with("failed")
        || trimmed.contains("failed:")
        || trimmed.contains("Failed:");
    if is_error {
        Style::new()
            .fg(COLOR_WARNING_ACCESSIBLE_RED)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(COLOR_SUCCESS)
    }
}

/// Word-wrap `text` into lines no longer than `width` characters. Embedded
/// newlines are honored so pre-formatted multi-line messages keep structure.
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for paragraph in text.split('\n') {
        let mut current = String::new();
        let mut pushed_any = false;
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                current = word.to_string();
            } else if current.len() + 1 + word.len() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                result.push(std::mem::take(&mut current));
                pushed_any = true;
                current = word.to_string();
            }
        }
        if !current.is_empty() {
            result.push(current);
        } else if !pushed_any {
            // Preserve blank paragraph separators from embedded newlines.
            result.push(String::new());
        }
    }
    if result.is_empty() {
        result.push(String::new());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_text_breaks_on_word_boundaries() {
        let out = wrap_text("hello world how are you today", 11);
        assert_eq!(out, vec!["hello world", "how are you", "today"]);
    }

    #[test]
    fn wrap_text_preserves_embedded_newlines() {
        let out = wrap_text("line one\nline two", 80);
        assert_eq!(out, vec!["line one", "line two"]);
    }

    #[test]
    fn wrap_text_handles_oversize_word() {
        let long = "a".repeat(40);
        let out = wrap_text(&long, 10);
        assert_eq!(out, vec![long]);
    }

    #[test]
    fn wrap_text_empty_input_yields_one_blank() {
        assert_eq!(wrap_text("", 80), vec![String::new()]);
    }

    #[test]
    fn status_style_flags_errors() {
        assert_eq!(
            status_style("Error: something broke").fg,
            Some(COLOR_WARNING_ACCESSIBLE_RED)
        );
        assert_eq!(
            status_style("Ping failed: timeout").fg,
            Some(COLOR_WARNING_ACCESSIBLE_RED)
        );
        assert_eq!(status_style("Relationship removed").fg, Some(COLOR_SUCCESS));
    }
}
