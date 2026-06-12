//! Yes/no prompt: should we configure `did-git-sign` so the operator's
//! persona signing key is used for git verified commit signing?
//!
//! Yes → dispatch `Action::DidGitSignInstall` (which transitions to
//!       `DidGitSignSetup` and runs the install).
//! No  → skip directly to whatever comes after the git-signing step
//!       (`after_export()` in the navigation module).

use crossterm::event::KeyEvent;
use ratatui::{Frame, style::Style, text::Line};

use crate::{
    colors::{COLOR_BORDER, COLOR_DARK_GRAY},
    state_handler::setup_sequence::SetupState,
    ui::pages::setup_flow::{
        SetupFlow,
        choice_page::{self, ChoiceOption, ChoiceSpec},
        navigation::SetupEvent,
    },
};

#[derive(Copy, Clone, Debug, Default)]
pub enum DidGitSignAsk {
    #[default]
    Use,
    Skip,
}

impl DidGitSignAsk {
    fn index(&self) -> usize {
        match self {
            DidGitSignAsk::Use => 0,
            DidGitSignAsk::Skip => 1,
        }
    }

    fn from_index(i: usize) -> Self {
        if i == 0 {
            DidGitSignAsk::Use
        } else {
            DidGitSignAsk::Skip
        }
    }

    fn spec() -> ChoiceSpec {
        ChoiceSpec {
            title: [
                " Configure git commit signing ",
                " Configure git commit signing ",
            ],
            intro: vec![
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
            ],
            options: [
                ChoiceOption {
                    label: "Yes, configure git signing now (recommended)",
                    description: vec![
                        Line::styled(
                            "    Sets up global git config + allowed_signers and stores VTA",
                            Style::new().fg(COLOR_DARK_GRAY),
                        ),
                        Line::styled(
                            "    credentials in your OS keyring.",
                            Style::new().fg(COLOR_DARK_GRAY),
                        ),
                    ],
                    event: SetupEvent::DidGitSignAccept,
                },
                ChoiceOption {
                    label: "No, skip git signing setup",
                    description: vec![Line::styled(
                        "    You can run `did-git-sign init` later if you change your mind.",
                        Style::new().fg(COLOR_DARK_GRAY),
                    )],
                    event: SetupEvent::DidGitSignSkip,
                },
            ],
        }
    }

    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        let selected = state.did_git_sign_ask.index();
        choice_page::handle_key_event(
            state,
            key,
            selected,
            |s, i| s.did_git_sign_ask = DidGitSignAsk::from_index(i),
            Self::spec(),
        );
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        choice_page::render(&Self::spec(), self.index(), state, frame);
    }
}
