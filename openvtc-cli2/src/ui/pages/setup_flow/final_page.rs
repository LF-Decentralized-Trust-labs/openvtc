use crossterm::event::{KeyCode, KeyEvent};
use openvtc::{
    LF_PUBLIC_MEDIATOR_DID,
    colors::{
        COLOR_BORDER, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
        COLOR_WARNING_ACCESSIBLE_RED,
    },
};
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
        setup_sequence::{Completion, MessageType, SetupState},
    },
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
};

#[derive(Copy, Clone, Debug, Default)]
pub struct FinalPage {}

impl FinalPage {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                let _ = state.action_tx.send(Action::ActivateMainMenu);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let block = Block::bordered()
            .fg(COLOR_BORDER)
            .padding(Padding::proportional(1))
            .title(" Profile configuration ");

        let mut lines = Vec::new();

        for msg in state.final_page.messages.iter() {
            match msg {
                MessageType::Info(info) => {
                    lines.push(Line::styled(
                        format!("INFO: {}", info),
                        Style::new().fg(COLOR_SUCCESS),
                    ));
                }
                MessageType::Error(err) => {
                    lines.push(Line::styled(
                        format!("ERROR: {}", err),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    ));
                }
            }
        }

        // Show congratulations and next steps if setup completed successfully
        if matches!(state.final_page.completed, Completion::CompletedOK) {
            lines.push(Line::default());
            lines.push(Line::styled(
                "Congratulations! Your OpenVTC profile is ready.",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::default());

            // Display profile information
            lines.push(Line::styled(
                "Profile Summary:",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            lines.push(Line::from(vec![
                Span::styled("  Display Name: ", Style::new().fg(COLOR_SUCCESS)),
                Span::styled(&state.username, Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Persona DID: ", Style::new().fg(COLOR_SUCCESS)),
                Span::styled(&state.webvh_address.did, Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));

            let mediator_did = state
                .custom_mediator
                .as_deref()
                .unwrap_or(LF_PUBLIC_MEDIATOR_DID);
            lines.push(Line::from(vec![
                Span::styled("  Mediator DID: ", Style::new().fg(COLOR_SUCCESS)),
                Span::styled(mediator_did, Style::new().fg(COLOR_SOFT_PURPLE)),
            ]));

            lines.push(Line::default());
            lines.push(Line::styled(
                "You can now access the dashboard to:",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            lines.push(Line::styled(
                "  • Send relationship requests and connect with others.",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "  • Issue and manage verifiable relationship credentials (VRCs).",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        }

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        frame.render_widget(
            Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
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
