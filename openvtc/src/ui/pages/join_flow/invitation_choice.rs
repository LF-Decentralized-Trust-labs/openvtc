//! Join flow — invitation choice.
//!
//! Reached after the operator picks an identity that holds one or more valid
//! invitations (VICs) for the community being joined. Each invitation is listed
//! with its details (Issued / Expires); the operator presents one — auto-joining
//! on a valid, trusted invitation — or chooses the trailing "join without it" row
//! to send an open request the community approves manually. The default highlight
//! is the first invitation, so Enter preserves the auto-join behaviour.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    state_handler::{actions::Action, join::JoinState},
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Debug, Default)]
pub struct InvitationChoice;

/// Trim an RFC 3339 timestamp to its date for compact display; empty stays as a
/// dash. Falls back to the full string if it is shorter than a date.
fn short_date(ts: &str) -> String {
    if ts.is_empty() {
        "—".to_string()
    } else if ts.len() >= 10 {
        ts[..10].to_string()
    } else {
        ts.to_string()
    }
}

impl InvitationChoice {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing {
            return;
        }
        let selected = state.props.state.invitation_use_selected;
        // The "join without it" row sits one past the invitations.
        let without_row = state.props.state.invitation_options.len();
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Up => {
                let _ = state
                    .action_tx
                    .send(Action::JoinInvitationSelect(selected.saturating_sub(1)));
            }
            KeyCode::Down => {
                let _ = state
                    .action_tx
                    .send(Action::JoinInvitationSelect((selected + 1).min(without_row)));
            }
            KeyCode::Enter => {
                let _ = state.action_tx.send(Action::JoinInvitationChoose);
            }
            KeyCode::Esc => {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Use an invitation for this community? "),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));

        let mut lines = vec![
            Line::styled(
                "Choose an invitation to present, or join without one:",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // One selectable row per available invitation, with its details.
        for (i, vic) in state.invitation_options.iter().enumerate() {
            let is_sel = i == state.invitation_use_selected;
            let marker = if is_sel { "▸ " } else { "  " };
            let style = if is_sel {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            lines.push(Line::from(Span::styled(
                format!("{marker}Invitation {}", vic.id),
                style,
            )));
            lines.push(Line::styled(
                format!(
                    "    Issued {}  ·  Expires {}",
                    short_date(&vic.valid_from),
                    short_date(&vic.valid_until),
                ),
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }

        // Trailing "join without it" row.
        let without_row = state.invitation_options.len();
        let without_sel = state.invitation_use_selected >= without_row;
        let marker = if without_sel { "▸ " } else { "  " };
        let style = if without_sel {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_SOFT_PURPLE)
        };
        lines.push(Line::from(Span::styled(
            format!("{marker}Join without it — send an open request"),
            style,
        )));
        lines.push(Line::styled(
            "    The community reviews and approves the request manually.",
            Style::new().fg(COLOR_DARK_GRAY),
        ));

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[↑/↓]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" select   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" choose   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" cancel", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);

        let bottom_line = Line::from(vec![
            Span::styled("[F10]", Style::new().fg(COLOR_ORANGE).bold()),
            Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);
        frame.render_widget(
            Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

#[cfg(test)]
mod tests {
    //! Key-routing tests for the invitation-choice page. `Action` derives neither
    //! `PartialEq` nor `Debug`, so assertions pattern-match the variant.
    use super::*;
    use crate::state_handler::{
        join::{AvailableVic, JoinPage, JoinState},
        state::State,
    };
    use crate::ui::component::Component;
    use crossterm::event::KeyModifiers;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    fn vic(id: &str) -> AvailableVic {
        AvailableVic {
            id: id.to_string(),
            subject: Some("did:webvh:alice".to_string()),
            valid_from: "2026-06-01T00:00:00Z".to_string(),
            valid_until: "2026-12-01T00:00:00Z".to_string(),
            body: serde_json::json!({ "id": id }),
        }
    }

    fn flow_with(mutate: impl FnOnce(&mut JoinState)) -> (JoinFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.join.page = JoinPage::InvitationChoice;
        state.join.invitation_options = vec![vic("urn:uuid:one")];
        mutate(&mut state.join);
        (JoinFlow::new(&state, tx), rx)
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn down_moves_toward_join_without_it() {
        // One invitation (row 0) + the "without" row (row 1).
        let (mut flow, mut rx) = flow_with(|_| {});
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::JoinInvitationSelect(1)) => {}
            _ => panic!("expected JoinInvitationSelect(1)"),
        }
    }

    #[test]
    fn down_clamps_at_the_without_row() {
        let (mut flow, mut rx) = flow_with(|js| js.invitation_use_selected = 1);
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Down));
        match rx.try_recv() {
            // len == 1, so the max row index is 1 (the "without" row).
            Ok(Action::JoinInvitationSelect(1)) => {}
            _ => panic!("expected JoinInvitationSelect(1)"),
        }
    }

    #[test]
    fn enter_chooses_the_highlight() {
        let (mut flow, mut rx) = flow_with(|_| {});
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::JoinInvitationChoose) => {}
            _ => panic!("expected JoinInvitationChoose"),
        }
    }

    #[test]
    fn esc_cancels_the_flow() {
        let (mut flow, mut rx) = flow_with(|_| {});
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::JoinCancel) => {}
            _ => panic!("expected JoinCancel"),
        }
    }
}
