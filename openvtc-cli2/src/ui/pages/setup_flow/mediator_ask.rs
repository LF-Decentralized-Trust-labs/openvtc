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
        setup_sequence::SetupState,
    },
    ui::pages::setup_flow::{
        SetupFlow, render_setup_header,
        navigation::{SetupEvent, handle_nav_result, navigate},
    },
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
                let event = match state.mediator_ask {
                    MediatorAsk::Default => SetupEvent::UseDefaultMediator,
                    MediatorAsk::Custom => SetupEvent::UseCustomMediator,
                };
                handle_nav_result(navigate(event, &state.props.state), state);
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
                "Your persona DID requires a mediator (relay service) for reliable DIDComm message delivery.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Use the default VTA mediator, or specify a custom mediator if you prefer a different one.",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the active choice
        if let MediatorAsk::Default = self {
            lines.push(Line::styled(
                "[✓] Use Default VTA Mediator (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Uses the mediator configured by your VTA service.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] Use Custom Mediator (requires a mediator DID)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        } else {
            lines.push(Line::styled(
                "[ ] Use Default VTA Mediator (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] Use Custom Mediator (requires a mediator DID)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Specify a different mediator DID to use instead of the VTA default.",
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
