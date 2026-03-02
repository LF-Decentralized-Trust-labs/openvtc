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
// DIDKeysExportAsk
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub enum DIDKeysExportAsk {
    #[default]
    Skip,
    Export,
}
impl DIDKeysExportAsk {
    /// Switches to the next panel when pressing <TAB>
    pub fn switch(&self) -> Self {
        match self {
            DIDKeysExportAsk::Skip => DIDKeysExportAsk::Export,
            DIDKeysExportAsk::Export => DIDKeysExportAsk::Skip,
        }
    }
}

impl DIDKeysExportAsk {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.did_keys_export_ask = state.did_keys_export_ask.switch();
            }
            KeyCode::Enter => {
                let event = match state.did_keys_export_ask {
                    DIDKeysExportAsk::Skip => SetupEvent::SkipExport,
                    DIDKeysExportAsk::Export => SetupEvent::StartExport,
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
            .title(" Step 4/4: Export private DID keys ");

        let mut lines = vec![
            Line::styled(
                "You may want to export the private key material used by your profile so you can reuse the same keys in other applications or with other DIDs.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Would you like to export your private DID keys now?",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the active choice
        if let DIDKeysExportAsk::Skip = self {
            lines.push(Line::styled(
                "[✓] Skip for now (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    You can continue setting up your profile and export them later from within OpenVTC if needed.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] Export private DID keys",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        } else {
            lines.push(Line::styled(
                "[ ] Skip for now (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] Export private DID keys",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Private keys will be exported in a secure, text-based PGP-armoured format suitable for secure storage and transfer.",
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
