use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{ActiveTaskView, ContentPanelState, InboxConfirm, InboxState, TaskKind},
    state::{ConnectionState, MediatorStatus},
};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Inbox content panel.
pub struct InboxPanel;

impl Panel for InboxPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.inbox, connection)
    }
}

/// Render the inbox panel content.
pub fn render(state: &InboxState, connection: &ConnectionState) -> Vec<Line<'static>> {
    // If viewing a specific task detail
    if let Some(active_task) = &state.active_task {
        let mut lines = render_task_detail(active_task);
        // A pending dismiss confirmation overrides the detail footer hint (R25).
        if let Some(confirm) = &state.confirm {
            lines.push(Line::from(""));
            lines.push(confirm_prompt_line(confirm));
        }
        return lines;
    }

    let mut lines = vec![Line::from("")];

    // Connection status (compact)
    let status_line = match &connection.status {
        MediatorStatus::Connected => Line::from("Connected").fg(COLOR_SUCCESS),
        MediatorStatus::Connecting => Line::from("Connecting...").fg(COLOR_TEXT_DEFAULT),
        MediatorStatus::Failed(reason) => {
            let display = if reason.len() > 40 {
                format!("Failed: {}...", &reason[..37])
            } else {
                format!("Failed: {}", reason)
            };
            Line::from(display).fg(COLOR_WARNING_ACCESSIBLE_RED)
        }
        MediatorStatus::Initializing(step) => {
            Line::from(format!("Initializing: {}", step)).fg(COLOR_ORANGE)
        }
        MediatorStatus::Unknown => Line::from("Not connected").fg(COLOR_ORANGE),
        MediatorStatus::NoActiveCommunity => Line::from("No active community").fg(COLOR_DARK_GRAY),
    };
    lines.push(status_line);

    if let Some(msg) = &state.status_message {
        lines.push(Line::from(""));
        super::status::push_status(&mut lines, msg, "");
    }

    lines.push(Line::from(""));

    if state.tasks.is_empty() {
        lines.push(Line::from("No pending tasks").fg(COLOR_DARK_GRAY));
        lines.push(Line::from(""));
        lines.push(
            Line::from("Inbound messages will appear here automatically.").fg(COLOR_DARK_GRAY),
        );
    } else {
        lines.push(Line::from(format!(" {} task(s)", state.tasks.len())).fg(COLOR_TEXT_DEFAULT));
        lines.push(Line::from(""));

        for (i, task) in state.tasks.iter().enumerate() {
            let is_selected = i == state.selected_index;
            let prefix = if is_selected { "▸ " } else { "  " };
            let style = if is_selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };

            let kind_indicator = match &task.kind {
                TaskKind::RelationshipRequestInbound { .. } => "⬇ REL ",
                TaskKind::RelationshipRequestOutbound { .. } => "⬆ REL ",
                TaskKind::VRCRequestInbound { .. } => "⬇ VRC ",
                TaskKind::VRCRequestOutbound => "⬆ VRC ",
                TaskKind::VRCIssued => "📄 VRC ",
                TaskKind::TrustPing => "🏓 PING",
                TaskKind::Informational(_) => "ℹ INFO",
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(kind_indicator, style),
                Span::styled("  ", Style::default()),
                Span::styled(task.type_display.clone(), style),
            ]));

            if !task.remote_did.is_empty() {
                let did_style = if is_selected {
                    Style::new().fg(COLOR_SOFT_PURPLE)
                } else {
                    Style::new().fg(COLOR_DARK_GRAY)
                };
                lines.push(Line::from(vec![
                    Span::styled("    ", Style::default()),
                    Span::styled(task.remote_did.clone(), did_style),
                    Span::styled("  ", Style::default()),
                    Span::styled(task.created.clone(), did_style),
                ]));
            }
        }

        lines.push(Line::from(""));
        // A pending dismiss/clear-all confirmation replaces the footer hint (R25).
        if let Some(confirm) = &state.confirm {
            lines.push(confirm_prompt_line(confirm));
        } else {
            lines.push(
                Line::from("↑/↓ navigate  Enter: view  d: dismiss  c: clear all")
                    .fg(COLOR_DARK_GRAY),
            );
        }
    }

    lines
}

/// Footer prompt shown while a destructive inbox action awaits `y`/`n` (R25).
fn confirm_prompt_line(confirm: &InboxConfirm) -> Line<'static> {
    let text = match confirm {
        InboxConfirm::Dismiss { .. } => "Dismiss this task?   y: confirm    n: cancel",
        InboxConfirm::ClearAll => "Clear all tasks?   y: confirm    n: cancel",
    };
    Line::from(text).fg(COLOR_ORANGE).bold()
}

/// Render detail view for a selected inbox task.
pub fn render_task_detail(task: &ActiveTaskView) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    match task {
        ActiveTaskView::RelationshipRequestInbound {
            task_id,
            from_did,
            their_did,
            reason,
            name,
        } => {
            lines.push(
                Line::from("Inbound Relationship Request")
                    .fg(COLOR_SUCCESS)
                    .bold(),
            );
            lines.push(Line::from(""));
            if let Some(name) = name {
                lines.push(Line::from(vec![
                    Span::styled("Name:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(name.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                ]));
            }
            lines.push(Line::from(vec![
                Span::styled("From:      ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(from_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            let uses_r_did = from_did != their_did;
            lines.push(Line::from(vec![
                Span::styled("Their DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(their_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                if uses_r_did {
                    Span::styled("  (R-DID)", Style::new().fg(COLOR_ORANGE))
                } else {
                    Span::styled("", Style::default())
                },
            ]));
            if uses_r_did {
                lines.push(Line::from(""));
                lines.push(
                    Line::from("  ⚠ Sender is using a relationship DID for privacy.")
                        .fg(COLOR_ORANGE),
                );
                lines.push(
                    Line::from("    Use A (Shift+A) to accept with your own R-DID.")
                        .fg(COLOR_ORANGE),
                );
            }
            if let Some(reason) = reason {
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(reason.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            lines.push(Line::from(vec![
                Span::styled("Task:  ", Style::new().fg(COLOR_DARK_GRAY)),
                Span::styled(task_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
            lines.push(Line::from(""));
            lines.push(
                Line::from("a: accept  A: accept (R-DID)  r: reject  d: dismiss  Esc: back")
                    .fg(COLOR_DARK_GRAY),
            );
        }
        ActiveTaskView::VRCRequestInbound {
            task_id,
            from_did,
            reason,
        } => {
            lines.push(Line::from("Inbound VRC Request").fg(COLOR_SUCCESS).bold());
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("From:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(from_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            if let Some(reason) = reason {
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(reason.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            lines.push(Line::from(vec![
                Span::styled("Task:  ", Style::new().fg(COLOR_DARK_GRAY)),
                Span::styled(task_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
            lines.push(Line::from(""));
            lines.push(
                Line::from("a: accept (issue VRC)  r: reject  d: dismiss  Esc: back")
                    .fg(COLOR_DARK_GRAY),
            );
        }
        ActiveTaskView::VRCIssued { task_id, issuer } => {
            lines.push(Line::from("VRC Received").fg(COLOR_SUCCESS).bold());
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Issuer: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(issuer.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Task:   ", Style::new().fg(COLOR_DARK_GRAY)),
                Span::styled(task_id.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("a: accept (store)  d: dismiss  Esc: back").fg(COLOR_DARK_GRAY));
        }
        ActiveTaskView::RelationshipRequestOutbound {
            task_id,
            to_did,
            our_did,
            state,
        } => {
            let label = Style::new().fg(COLOR_TEXT_DEFAULT);
            let value = Style::new().fg(COLOR_SOFT_PURPLE);
            let dim = Style::new().fg(COLOR_DARK_GRAY);
            lines.push(
                Line::from("Outbound Relationship Request")
                    .fg(COLOR_SUCCESS)
                    .bold(),
            );
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("To:       ", label),
                Span::styled(to_did.clone(), value),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Our DID:  ", label),
                Span::styled(our_did.clone(), value),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Status:   ", label),
                Span::styled(state.clone(), Style::new().fg(COLOR_ORANGE)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Task:     ", dim),
                Span::styled(task_id.clone(), dim),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("d: dismiss  Esc: back").fg(COLOR_DARK_GRAY));
        }
        ActiveTaskView::VRCRequestOutbound {
            task_id,
            remote_did,
        } => {
            let label = Style::new().fg(COLOR_TEXT_DEFAULT);
            let value = Style::new().fg(COLOR_SOFT_PURPLE);
            let dim = Style::new().fg(COLOR_DARK_GRAY);
            lines.push(Line::from("Outbound VRC Request").fg(COLOR_SUCCESS).bold());
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("To:    ", label),
                Span::styled(remote_did.clone(), value),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Task:  ", dim),
                Span::styled(task_id.clone(), dim),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("d: dismiss  Esc: back").fg(COLOR_DARK_GRAY));
        }
        ActiveTaskView::Info {
            task_id,
            type_display,
            remote_did,
        } => {
            let label = Style::new().fg(COLOR_TEXT_DEFAULT);
            let value = Style::new().fg(COLOR_SOFT_PURPLE);
            let dim = Style::new().fg(COLOR_DARK_GRAY);
            lines.push(Line::from(type_display.clone()).fg(COLOR_SUCCESS).bold());
            lines.push(Line::from(""));
            if !remote_did.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("DID:   ", label),
                    Span::styled(remote_did.clone(), value),
                ]));
            }
            lines.push(Line::from(vec![
                Span::styled("Task:  ", dim),
                Span::styled(task_id.clone(), dim),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("d: dismiss  Esc: back").fg(COLOR_DARK_GRAY));
        }
    }

    lines
}
