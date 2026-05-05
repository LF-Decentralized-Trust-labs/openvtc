//! Yes/no prompt: should we configure `did-git-sign` so the operator's
//! persona signing key is used for git verified commit signing?
//!
//! Yes → dispatch `Action::DidGitSignInstall` (which transitions to
//!       `DidGitSignSetup` and runs the install).
//! No  → skip directly to whatever comes after the git-signing step
//!       (`after_export()` in the navigation module).

use crate::colors::{COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use crossterm::event::{KeyCode, KeyEvent};
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
    state_handler::{actions::Action, setup_sequence::SetupState},
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

#[derive(Copy, Clone, Debug, Default)]
pub enum DidGitSignAsk {
    #[default]
    Use,
    Skip,
}

impl DidGitSignAsk {
    fn switch(&self) -> Self {
        match self {
            DidGitSignAsk::Use => DidGitSignAsk::Skip,
            DidGitSignAsk::Skip => DidGitSignAsk::Use,
        }
    }

    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.did_git_sign_ask = state.did_git_sign_ask.switch();
            }
            KeyCode::Enter => {
                let event = match state.did_git_sign_ask {
                    DidGitSignAsk::Use => SetupEvent::DidGitSignAccept,
                    DidGitSignAsk::Skip => SetupEvent::DidGitSignSkip,
                };
                handle_nav_result(navigate(event, &state.props.state), state);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let block = Block::bordered()
            .fg(COLOR_BORDER)
            .padding(Padding::proportional(1))
            .title(" Configure git commit signing ");

        let mut lines = vec![
            Line::styled(
                "Your DID persona signing key (Ed25519) can also be used to sign git commits.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::styled(
                "OpenVTC will configure `did-git-sign` so your commits sign and verify",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::styled(
                "automatically — no extra setup steps in each repository.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Use your DID signing key for git verified signing?",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        match self {
            DidGitSignAsk::Use => {
                lines.push(Line::styled(
                    "[✓] Yes, configure git signing now (recommended)",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
                lines.push(Line::styled(
                    "    Sets up global git config + allowed_signers and stores VTA",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
                lines.push(Line::styled(
                    "    credentials in your OS keyring.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
                lines.push(Line::styled(
                    "[ ] No, skip git signing setup",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));
            }
            DidGitSignAsk::Skip => {
                lines.push(Line::styled(
                    "[ ] Yes, configure git signing now (recommended)",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));
                lines.push(Line::styled(
                    "[✓] No, skip git signing setup",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
                lines.push(Line::styled(
                    "    You can run `did-git-sign init` later if you change your mind.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
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
