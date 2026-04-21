use crossterm::event::{Event, KeyCode, KeyEvent};
use openvtc::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_TEXT_DEFAULT,
};
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
    state_handler::{
        actions::Action,
        setup_sequence::{Completion, MessageType, SetupState},
    },
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
};

use openvtc::colors::COLOR_WARNING_ACCESSIBLE_RED;

// ****************************************************************************
// VtaCredentialPaste
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct VtaCredentialPaste {
    pub credential_input: Input,
    pub warning_msg: Option<String>,
}

impl VtaCredentialPaste {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                let input = state.vta_credential.credential_input.value().to_string();
                if input.trim().is_empty() {
                    state.vta_credential.warning_msg =
                        Some("Please paste a credential bundle.".to_string());
                } else {
                    state.vta_credential.warning_msg = None;
                    let _ = state.action_tx.send(Action::VtaSubmitCredential(input));
                }
            }
            KeyCode::Esc => {
                state.vta_credential.credential_input.reset();
            }
            _ => {
                state
                    .vta_credential
                    .credential_input
                    .handle_event(&Event::Key(key));
            }
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let content: [Rect; 5] =
            Layout::vertical([Length(6), Length(2), Length(2), Length(2), Min(0)])
                .areas(middle.inner(Margin::new(3, 2)));

        let [input_prompt, input_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 1/4: VTA Credential "),
            middle,
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "OpenVTC uses a Verifiable Trust Agent (VTA) service to manage your cryptographic keys.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::styled(
                    "To connect to your VTA, please follow the instructions below.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled(
                    "Paste your VTA credential bundle below:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::default(),
            ]),
            content[0],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(">", Style::new().fg(COLOR_BORDER).bold())),
            input_prompt,
        );

        render_input(&self.credential_input, frame, input_box);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to clear input  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ])),
            content[2],
        );

        // Prefer a local input warning; otherwise surface the first error
        // returned from the backend (e.g. invalid credential bundle decode).
        let backend_error = if matches!(state.vta.completed, Completion::CompletedFail) {
            state.vta.messages.iter().find_map(|m| match m {
                MessageType::Error(e) => Some(e.clone()),
                MessageType::Info(_) => None,
            })
        } else {
            None
        };
        if let Some(warning_msg) = self.warning_msg.as_ref().or(backend_error.as_ref()) {
            frame.render_widget(
                Paragraph::new(Line::styled(
                    warning_msg.clone(),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ))
                .wrap(Wrap { trim: false }),
                content[3],
            );
        }

        // If the backend returned errors, show them in full (wrapped) in the
        // bottom area instead of the PNM instructions, so the user can see why
        // their bundle was rejected rather than appearing to be sent back to
        // a blank input.
        if backend_error.is_some() {
            let mut err_lines: Vec<Line<'_>> = Vec::new();
            err_lines.push(Line::styled(
                "The credential bundle could not be used:",
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
            ));
            err_lines.push(Line::default());
            for msg in &state.vta.messages {
                let (prefix, style) = match msg {
                    MessageType::Error(_) => (
                        "ERROR: ",
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                    ),
                    MessageType::Info(_) => ("  ", Style::new().fg(COLOR_DARK_GRAY)),
                };
                let text = match msg {
                    MessageType::Error(e) => e.clone(),
                    MessageType::Info(i) => i.clone(),
                };
                err_lines.push(Line::styled(format!("{prefix}{text}"), style));
            }
            err_lines.push(Line::default());
            err_lines.push(Line::styled(
                "Paste a corrected credential bundle above and press [ENTER] to retry.",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            frame.render_widget(
                Paragraph::new(err_lines).wrap(Wrap { trim: false }),
                content[4],
            );
            let bottom_line = Line::from(vec![
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]);
            frame.render_widget(
                Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
                bottom,
            );
            return;
        }

        // PNM instructions
        let pnm_lines = vec![
            Line::styled(
                "Don't have a credential? Use the PNM CLI to create one:",
                Style::new().fg(COLOR_ORANGE).bold(),
            ),
            Line::default(),
            Line::styled(
                "1. Get a VTA admin credential from your VTA administrator.",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::default(),
            Line::styled(
                "2. Set up PNM with the admin credential:",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "   pnm setup --credential <ADMIN_CREDENTIAL>",
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Line::styled(
                "   Or run 'pnm setup' and paste the credential when prompted.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "3. Create a new context and generate a credential for OpenVTC:",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "   pnm contexts bootstrap --id <CONTEXT_ID> --name <NAME>",
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Line::styled(
                "   This outputs a one-time credential bundle.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "   Or generate a credential from an existing context:",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "   pnm auth-credential create --role admin --contexts <CONTEXT_ID>",
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Line::default(),
            Line::styled(
                "4. Copy the base64 credential bundle and paste it above.",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
        ];

        frame.render_widget(
            Paragraph::new(pnm_lines).wrap(Wrap { trim: false }),
            content[4],
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

fn render_input(input: &Input, frame: &mut Frame, area: Rect) {
    let width = area.width.max(3) - 3;
    let scroll = input.visual_scroll(width as usize);
    frame.render_widget(
        Paragraph::new(input.value())
            .fg(COLOR_SOFT_PURPLE)
            .scroll((0, scroll as u16)),
        area,
    );

    let x = input.visual_cursor().max(scroll) - scroll;
    frame.set_cursor_position((area.x + x as u16, area.y))
}
