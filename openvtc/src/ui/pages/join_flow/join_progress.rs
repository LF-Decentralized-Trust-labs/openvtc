//! Join flow — step 2: live progress of the automated mint + join sequence.
//!
//! Renders the `JoinState.messages` log plus the terminal outcome. On success
//! it shows the created persona DID and the pending community, and prompts the
//! operator to restart OpenVTC to activate the new community (hot-start is a
//! deliberate follow-up). [ENTER] returns to the main page.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    state_handler::{
        actions::Action,
        join::JoinState,
        setup_sequence::{Completion, MessageType},
    },
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct JoinProgress;

impl JoinProgress {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter if !state.props.state.processing => {
                // Return to the main page once the sequence has settled.
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        let block = Block::bordered()
            .fg(COLOR_BORDER)
            .padding(Padding::proportional(1))
            .title(" Joining community ");

        let mut lines = Vec::new();

        for msg in &state.messages {
            match msg {
                MessageType::Info(info) => lines.push(Line::styled(
                    format!("INFO: {info}"),
                    Style::new().fg(COLOR_SUCCESS),
                )),
                MessageType::Error(err) => lines.push(Line::styled(
                    format!("ERROR: {err}"),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                )),
            }
        }

        match state.completed {
            Completion::NotFinished => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Working… please wait.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            Completion::CompletedOK => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Join request submitted.",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
                if let Some(rec) = &state.created_community {
                    lines.push(Line::default());
                    // Only show a friendly name when one actually resolved —
                    // otherwise it would just duplicate the DID below.
                    if let Some(name) = &rec.display_name {
                        lines.push(Line::from(vec![
                            Span::styled("  Community:     ", Style::new().fg(COLOR_SUCCESS)),
                            Span::styled(name.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                        ]));
                    }
                    lines.push(Line::from(vec![
                        Span::styled("  Community DID: ", Style::new().fg(COLOR_SUCCESS)),
                        Span::styled(rec.vtc_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                    if let Some(persona_did) = &state.created_persona_did {
                        lines.push(Line::from(vec![
                            Span::styled("  Your persona:  ", Style::new().fg(COLOR_SUCCESS)),
                            Span::styled(persona_did.clone(), Style::new().fg(COLOR_SOFT_PURPLE)),
                        ]));
                    }
                    lines.push(Line::from(vec![
                        Span::styled("  Status:        ", Style::new().fg(COLOR_SUCCESS)),
                        Span::styled("Pending", Style::new().fg(COLOR_ORANGE)),
                    ]));
                    // Whether an invitation was actually presented (auto-admit
                    // path) or this is an open request (manual approval) — the
                    // distinction that determines what happens next.
                    match &state.presented_invitation {
                        Some(vic) => {
                            lines.push(Line::from(vec![
                                Span::styled(
                                    "  Invitation:    ",
                                    Style::new().fg(COLOR_SUCCESS),
                                ),
                                Span::styled(
                                    format!("Presented  ·  {}", vic.id),
                                    Style::new().fg(COLOR_SOFT_PURPLE),
                                ),
                            ]));
                            if let Some(subject) = &vic.subject {
                                lines.push(Line::from(vec![
                                    Span::styled(
                                        "  Bound to:      ",
                                        Style::new().fg(COLOR_SUCCESS),
                                    ),
                                    Span::styled(
                                        subject.clone(),
                                        Style::new().fg(COLOR_SOFT_PURPLE),
                                    ),
                                ]));
                            }
                        }
                        None => {
                            lines.push(Line::from(vec![
                                Span::styled(
                                    "  Invitation:    ",
                                    Style::new().fg(COLOR_SUCCESS),
                                ),
                                Span::styled(
                                    "None  ·  open request (awaiting approval)",
                                    Style::new().fg(COLOR_ORANGE),
                                ),
                            ]));
                        }
                    }
                }
                lines.push(Line::default());
                lines.push(Line::styled(
                    "It's now in your Communities list, marked Pending — it will update \
                     there as the community responds.",
                    Style::new().fg(COLOR_SUCCESS),
                ));
            }
            Completion::CompletedFail => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Join failed. Nothing was activated.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ));
            }
        }

        if !matches!(state.completed, Completion::NotFinished) {
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to return", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
        }

        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            middle,
        );

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
