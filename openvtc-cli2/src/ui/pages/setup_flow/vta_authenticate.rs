use crossterm::event::{KeyCode, KeyEvent};
use openvtc::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
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
    state_handler::{
        actions::Action,
        setup_sequence::{Completion, MessageType, SetupState},
    },
    ui::pages::setup_flow::{
        SetupFlow, render_setup_header,
        navigation::{SetupEvent, handle_nav_result, navigate},
    },
};

// ****************************************************************************
// VtaAuthenticate
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct VtaAuthenticate;

impl VtaAuthenticate {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                match state.props.state.vta.completed {
                    Completion::CompletedOK => {
                        let result = navigate(SetupEvent::VtaAuthCompleted, &state.props.state);
                        handle_nav_result(result, state);
                    }
                    Completion::CompletedFail => {
                        // Retry authentication
                        let _ = state.action_tx.send(Action::VtaAuthenticate);
                    }
                    Completion::NotFinished => {
                        // Still in progress, do nothing
                    }
                }
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let content = middle.inner(Margin::new(3, 2));

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 2/4: VTA Authentication "),
            middle,
        );

        let mut lines = vec![
            Line::styled(
                "Authenticating with the VTA service...",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
        ];

        // Show credential info
        if !state.vta.credential_did.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Credential DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(
                    &state.vta.credential_did,
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            ]));
        }
        if !state.vta.vta_url.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("VTA URL: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(&state.vta.vta_url, Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
        }
        if !state.vta.vta_did.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("VTA DID: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(&state.vta.vta_did, Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
        }
        lines.push(Line::default());

        // Show messages
        for msg in &state.vta.messages {
            match msg {
                MessageType::Info(info) => {
                    lines.push(Line::styled(
                        format!("  {info}"),
                        Style::new().fg(COLOR_SUCCESS),
                    ));
                }
                MessageType::Error(err) => {
                    lines.push(Line::styled(
                        format!("  ERROR: {err}"),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    ));
                }
            }
        }

        match state.vta.completed {
            Completion::CompletedOK => {
                lines.push(Line::default());
                let action_text = if !state.vta.webvh_servers.is_empty() {
                    " to continue"
                } else {
                    " to create keys"
                };
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(
                        action_text,
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                ]));
            }
            Completion::CompletedFail => {
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to retry", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            Completion::NotFinished => {
                lines.push(Line::styled(
                    "Please wait...",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
        }

        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            content,
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
