use crossterm::event::{Event, KeyCode, KeyEvent};
use openvtc::colors::{COLOR_BORDER, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_TEXT_DEFAULT};
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
    ui::pages::setup_flow::{
        SetupFlow, render_setup_header,
        navigation::{SetupEvent, handle_nav_result, navigate},
    },
};

// ****************************************************************************
// MediatorCustom
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct MediatorCustom {
    pub mediator_did: Input,
}

impl MediatorCustom {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                let mediator_did = state.mediator_custom.mediator_did.value().to_string();
                let result = navigate(
                    SetupEvent::CustomMediatorSet { mediator_did },
                    &state.props.state,
                );
                handle_nav_result(result, state);
            }
            KeyCode::Esc => {
                state.mediator_custom.mediator_did.reset();
            }
            _ => {
                // Handle text input
                state
                    .mediator_custom
                    .mediator_did
                    .handle_event(&Event::Key(key));
            }
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        // 0: Input 0 Header (Passphrase)
        // 1: INPUT <-- Passphrase
        // 2: Key Bindings
        let content: [Rect; 3] =
            Layout::vertical([Length(2), Length(2), Min(0)]).areas(middle.inner(Margin::new(3, 2)));

        let [input0_prompt, input0_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 2/2: Set custom messaging mediator "),
            middle,
        );

        frame.render_widget(
            Paragraph::new(vec![Line::styled(
                "Enter custom mediator DID:",
                Style::new().fg(COLOR_BORDER).bold(),
            )]),
            content[0],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            input0_prompt,
        );

        render_input(&self.mediator_did, frame, input0_box);

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "ℹ️ Note: The custom mediator DID must support DIDComm v2 protocol.",
                    Style::new().fg(COLOR_ORANGE),
                ),
                Line::default(),
                Line::from(vec![
                    Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to clear input  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]),
            ]),
            content[2],
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
    // keep 1 for borders and 1 for cursor
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
