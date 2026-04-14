use super::panel::Panel;
use crate::state_handler::{
    main_page::content::{ActiveTaskView, ContentPanelState, InboxState, TaskKind},
    state::{ConnectionState, MediatorStatus},
};
use openvtc::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
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
        return render_task_detail(active_task);
    }

    let mut lines = vec![Line::from("")];

    // Connection status (compact)
    let status_line = match &connection.status {
        MediatorStatus::Connected { latency_ms } => {
            Line::from(format!("Connected ({}ms)", latency_ms)).fg(COLOR_SUCCESS)
        }
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
    };
    lines.push(status_line);

    if connection.queued_outbound > 0 {
        lines.push(
            Line::from(format!("Queued outbound: {}", connection.queued_outbound)).fg(COLOR_ORANGE),
        );
    }

    if let Some(msg) = &state.status_message {
        lines.push(Line::from(""));
        lines.push(Line::from(msg.clone()).fg(COLOR_SUCCESS));
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
                TaskKind::RelationshipRequestOutbound => "⬆ REL ",
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
        lines.push(
            Line::from("↑/↓ navigate  Enter: view  d: dismiss  c: clear all").fg(COLOR_DARK_GRAY),
        );
    }

    lines
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
        } => {
            lines.push(
                Line::from("Inbound Relationship Request")
                    .fg(COLOR_SUCCESS)
                    .bold(),
            );
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("From:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(from_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("DID:   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(their_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
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
            lines.push(Line::from("a: accept  r: reject  Esc: back").fg(COLOR_DARK_GRAY));
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
    }

    lines
}
