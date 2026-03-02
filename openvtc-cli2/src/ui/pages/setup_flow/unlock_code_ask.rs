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
// UnlockCodeAsk
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub enum UnlockCodeAsk {
    #[default]
    UseCode,
    NoCode,
}
impl UnlockCodeAsk {
    /// Switches to the next panel when pressing <TAB>
    pub fn switch(&self) -> Self {
        match self {
            UnlockCodeAsk::UseCode => UnlockCodeAsk::NoCode,
            UnlockCodeAsk::NoCode => UnlockCodeAsk::UseCode,
        }
    }
}

impl UnlockCodeAsk {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.unlock_code_ask = state.unlock_code_ask.switch();
            }
            KeyCode::Enter => {
                let event = match state.unlock_code_ask {
                    UnlockCodeAsk::UseCode => SetupEvent::WantUnlockCode,
                    UnlockCodeAsk::NoCode => SetupEvent::SkipUnlockCode,
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

        let block = Block::bordered()
            .fg(COLOR_BORDER)
            .padding(Padding::proportional(1))
            .title(" Step 1/2: Set up unlock code ");

        let mut lines = vec![
            Line::styled(
                "An unlock code encrypts your cryptographic keys, configuration, and private data stored by OpenVTC.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::styled(
                "This prevents unauthorized access even if someone gains access to your device.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Would you like to set an unlock code?",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the active choice
        if let UnlockCodeAsk::UseCode = self {
            lines.push(Line::styled(
                "[✓] Yes, require unlock code (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Encrypts your keys, configuration, and private data for protection against unauthorized access.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] No, do not require unlock code",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        } else {
            lines.push(Line::styled(
                "[ ] Yes, require unlock code (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] No, do not require unlock code",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Anyone with access to this device will be able to open OpenVTC and use your keys and access your private data.",
                Style::new().fg(COLOR_DARK_GRAY).bold(),
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
