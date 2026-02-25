use crossterm::event::{KeyCode, KeyEvent};
use openvtc::colors::{COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
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
        setup_sequence::{SetupPage, SetupState},
    },
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
};

// ****************************************************************************
// MediatorAsk
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub enum MediatorAsk {
    #[default]
    Default,
    Custom,
}
impl MediatorAsk {
    /// Switches to the next panel when pressing <TAB>
    pub fn switch(&self) -> Self {
        match self {
            MediatorAsk::Default => MediatorAsk::Custom,
            MediatorAsk::Custom => MediatorAsk::Default,
        }
    }
}

impl MediatorAsk {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.mediator_ask = state.mediator_ask.switch();
            }
            KeyCode::Enter => {
                // User has chosen whether to create or import their BIP32 phrase
                state.props.state.active_page = match state.mediator_ask {
                    MediatorAsk::Default => SetupPage::UserName,
                    MediatorAsk::Custom => SetupPage::MediatorCustom,
                }
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        // Dynamically set the title based on selected option
        let title = match self {
            MediatorAsk::Default => " Step 1/1: Configure messaging mediator ",
            MediatorAsk::Custom => " Step 1/2: Configure messaging mediator ",
        };

        let block = Block::bordered()
            .fg(COLOR_BORDER)
            .padding(Padding::proportional(1))
            .title(title);

        let mut lines = vec![
            Line::styled(
                "All communication uses secure messaging based on the DIDComm protocol and requires a mediator (relay service) for reliable message delivery.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Choose the default mediator, or select a custom mediator if your community requires one.",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the active chocie
        if let MediatorAsk::Default = self {
            lines.push(Line::styled(
                "[✓] Use the Default OpenVTC Mediator (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Uses the managed OpenVTC community mediator for reliable, out-of-the-box messaging.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] Use Custom Mediator (requires a mediator DID)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        } else {
            lines.push(Line::styled(
                "[ ] Use the Default OpenVTC Mediator (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] Use Custom Mediator (requires a mediator DID)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Specify a custom mediator DID for messaging, if your community requires it.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to confirm", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

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
