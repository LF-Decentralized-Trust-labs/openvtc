//! Join flow — invitation choice.
//!
//! Shown only when an invitation credential (VIC) is actually available for the
//! community being joined (a loaded VIC that matches, or one held in the vault).
//! The operator chooses whether to present it — auto-joining on a valid, trusted
//! invitation — or to join as an open request the community approves manually.
//! Mirrors the other join pages' component shape; the default highlight is "use
//! it", so pressing Enter preserves the auto-join behaviour.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
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

impl InvitationChoice {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing {
            return;
        }
        let selected = state.props.state.invitation_use_selected;
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
                    .send(Action::JoinInvitationSelect((selected + 1).min(1)));
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
                .title(" Use your invitation for this community? "),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));

        let mut lines = vec![
            Line::styled(
                "An invitation for this community is available.",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Two rows: 0 = use it (auto-join), 1 = join without it (open request).
        let rows = [
            (
                "Use it — auto-join with your invitation",
                "The community admits you automatically on a valid, trusted invitation.",
            ),
            (
                "Join without it — send an open request",
                "Submit a request the community reviews and approves manually.",
            ),
        ];
        for (i, (title, detail)) in rows.iter().enumerate() {
            let is_sel = i == state.invitation_use_selected;
            let marker = if is_sel { "▸ " } else { "  " };
            let style = if is_sel {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            lines.push(Line::from(Span::styled(format!("{marker}{title}"), style)));
            lines.push(Line::styled(
                format!("    {detail}"),
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }

        lines.push(Line::default());
        lines.push(Line::styled(
            "You can still choose which identity to present on the next step.",
            Style::new().fg(COLOR_SOFT_PURPLE),
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
            Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
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
        join::{JoinPage, JoinState},
        state::State,
    };
    use crate::ui::component::Component;
    use crossterm::event::KeyModifiers;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    fn flow_with(mutate: impl FnOnce(&mut JoinState)) -> (JoinFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.join.page = JoinPage::InvitationChoice;
        mutate(&mut state.join);
        (JoinFlow::new(&state, tx), rx)
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn down_moves_to_join_without_it() {
        let (mut flow, mut rx) = flow_with(|_| {});
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::JoinInvitationSelect(1)) => {}
            _ => panic!("expected JoinInvitationSelect(1)"),
        }
    }

    #[test]
    fn up_clamps_at_use_it() {
        let (mut flow, mut rx) = flow_with(|js| js.invitation_use_selected = 0);
        InvitationChoice::handle_key_event(&mut flow, press(KeyCode::Up));
        match rx.try_recv() {
            Ok(Action::JoinInvitationSelect(0)) => {}
            _ => panic!("expected JoinInvitationSelect(0)"),
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
