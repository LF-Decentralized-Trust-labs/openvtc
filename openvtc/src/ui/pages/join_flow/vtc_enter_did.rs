//! Join flow — step 1: ask for the community (VTC) DID.
//!
//! Mirrors `setup_flow::vta_enter_did`. On submit we send
//! [`Action::JoinSubmitVtc`], which kicks off the automated persona-mint +
//! sub-context + join-submit sequence. Esc cancels the whole flow.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_TEXT_DEFAULT,
};
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin, Rect,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    state_handler::{actions::Action, join::JoinState},
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Debug, Default)]
pub struct VtcEnterDid;

impl VtcEnterDid {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        // Input is locked while the background sequence runs.
        if state.props.state.processing {
            return;
        }
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                let did = state.vtc_did.value().trim().to_string();
                if !did.is_empty() {
                    let _ = state.action_tx.send(Action::JoinSubmitVtc(did));
                }
            }
            KeyCode::Esc => {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            _ => {
                state.vtc_did.handle_event(&Event::Key(key));
            }
        }
    }

    pub fn render(&self, state: &JoinState, input: &Input, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Join a community "),
            middle,
        );

        let content: [Rect; 3] =
            Layout::vertical([Length(5), Length(2), Min(0)]).areas(middle.inner(Margin::new(3, 2)));

        let [prompt_col, input_col] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "Enter the Verifiable Trust Community (VTC) DID you want to join.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::styled(
                    "OpenVTC will mint a fresh persona and submit a join request on your behalf.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled(
                    "Enter the community's DID:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
            ]),
            content[0],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            prompt_col,
        );
        render_input(input, frame, input_col);

        let mut lines = vec![
            Line::styled("Example:", Style::new().fg(COLOR_ORANGE).bold()),
            Line::styled(
                "  • did:webvh:QmRoot…:community.example.com",
                Style::new().fg(COLOR_ORANGE).italic(),
            ),
            Line::default(),
        ];
        // Surface any pre-submit error (e.g. idempotency) inline.
        for msg in &state.messages {
            if let crate::state_handler::setup_sequence::MessageType::Error(err) = msg {
                lines.push(Line::styled(
                    format!("ERROR: {err}"),
                    Style::new().fg(crate::colors::COLOR_WARNING_ACCESSIBLE_RED),
                ));
            }
        }
        // When an invitation credential was supplied at launch, show that it
        // will be presented — the community can then auto-admit without review.
        if state.has_invitation {
            lines.push(Line::styled(
                "✓ Invitation credential loaded — it will be presented to the community.",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            ));
            lines.push(Line::default());
        } else {
            lines.push(Line::styled(
                "Tip: paste an invitation credential (VIC) here to auto-join.",
                Style::new().fg(COLOR_DARK_GRAY).italic(),
            ));
            lines.push(Line::default());
        }
        lines.push(Line::from(vec![
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to cancel  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to join", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content[2]);

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

fn render_input(input: &Input, frame: &mut Frame, area: Rect) {
    let width = area.width.max(3) - 3;
    let scroll = input.visual_scroll(width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(
            input.value(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ))
        .scroll((0, scroll as u16)),
        area,
    );
    let x = input.visual_cursor().max(scroll) - scroll;
    frame.set_cursor_position((area.x + x as u16, area.y))
}
