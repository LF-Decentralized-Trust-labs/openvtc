use crossterm::event::{Event, KeyCode, KeyEvent};
use openvtc::colors::{COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_TEXT_DEFAULT};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin, Rect,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph},
};
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    state_handler::{actions::Action, setup_sequence::SetupState},
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
};

// ****************************************************************************
// DIDKeysExportInputs
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct DIDKeysExportInputs {
    /// 0 = passphrase
    /// 1 = username
    pub active_input: u8,

    pub passphrase: Input,
    pub username: Input,
}

impl DIDKeysExportInputs {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                if state.did_keys_export_inputs.active_input == 0 {
                    state.did_keys_export_inputs.active_input = 1;
                } else {
                    state.did_keys_export_inputs.active_input = 0;
                }
            }
            KeyCode::Enter => {
                let _ = state
                    .action_tx
                    .send(Action::ExportDIDKeys(state.did_keys_export_inputs.clone()));
            }
            KeyCode::Esc => {
                if state.did_keys_export_inputs.active_input == 0 {
                    state.did_keys_export_inputs.passphrase.reset();
                } else {
                    state.did_keys_export_inputs.username.reset();
                }
            }
            _ => {
                // Handle text input
                if state.did_keys_export_inputs.active_input == 0 {
                    state
                        .did_keys_export_inputs
                        .passphrase
                        .handle_event(&Event::Key(key));
                } else {
                    state
                        .did_keys_export_inputs
                        .username
                        .handle_event(&Event::Key(key));
                }
            }
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        // 0: Input 0 Header (Passphrase)
        // 1: INPUT <-- Passphrase
        // 2: Input 1 Header (Username)
        // 3: INPUT <-- Username
        // 4: Key Bindings
        let content: [Rect; 5] =
            Layout::vertical([Length(2), Length(2), Length(2), Length(2), Min(0)])
                .areas(middle.inner(Margin::new(3, 2)));

        let [input0_prompt, input0_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);
        let [input1_prompt, input1_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[3]);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 4/4: Export private DID keys settings "),
            middle,
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "Enter passphrase to protect exported keys:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::styled(
                    "Leave blank to export DID keys with no protection.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
            ]),
            content[0],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            input0_prompt,
        );

        render_input(
            &self.passphrase,
            frame,
            input0_box,
            true,
            self.active_input == 0,
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "Enter PGP user ID for exported keys:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::from(vec![
                    Span::styled("Use the format ", Style::new().fg(COLOR_DARK_GRAY)),
                    Span::styled(
                        "Name <email@example.com>: ",
                        Style::new().fg(COLOR_DARK_GRAY).bold().italic(),
                    ),
                ]),
            ]),
            content[2],
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            input1_prompt,
        );

        render_input(
            &self.username,
            frame,
            input1_box,
            false,
            self.active_input == 1,
        );

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to clear input  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ])),
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

fn render_input(input: &Input, frame: &mut Frame, area: Rect, password: bool, active: bool) {
    // keep 1 for borders and 1 for cursor
    let width = area.width.max(3) - 3;
    let scroll = input.visual_scroll(width as usize);
    let text = if password {
        let mut s = String::new();
        for _ in 0..input.value().len() {
            s.push('*');
        }
        Span::styled(s, Style::new().fg(COLOR_SOFT_PURPLE))
    } else {
        Span::styled(
            input.value().to_string(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        )
    };

    frame.render_widget(Paragraph::new(text).scroll((0, scroll as u16)), area);

    if active {
        let x = input.visual_cursor().max(scroll) - scroll;
        frame.set_cursor_position((area.x + x as u16, area.y))
    }
}
