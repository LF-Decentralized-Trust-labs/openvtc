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
// WebvhServerProgress - Shows DID creation progress via WebVH server
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct WebvhServerProgress;

impl WebvhServerProgress {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                if let Completion::CompletedOK = state.props.state.webvh_server.completed {
                    let result = navigate(SetupEvent::WebvhDIDCreated, &state.props.state);
                    handle_nav_result(result, state);
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
                .title(" Step 3/4: Creating DID via WebVH Server "),
            middle,
        );

        let mut lines = vec![
            Line::styled(
                "Creating and publishing your DID via WebVH server...",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
        ];

        // Show messages
        for msg in &state.webvh_server.messages {
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

        match state.webvh_server.completed {
            Completion::CompletedOK => {
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("Your Persona DID: ", Style::new().fg(COLOR_SUCCESS).bold()),
                    Span::styled(
                        &state.webvh_server.did,
                        Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                    ),
                ]));

                lines.push(Line::default());
                lines.push(Line::styled(
                    "Your DID has been created and published to the WebVH server.",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));
                lines.push(Line::styled(
                    "No manual hosting setup is needed.",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));

                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            Completion::CompletedFail => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "DID creation failed. Please restart setup.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ));
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
