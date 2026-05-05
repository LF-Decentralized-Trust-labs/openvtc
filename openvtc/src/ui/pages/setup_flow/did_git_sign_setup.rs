//! Auto-configures `did-git-sign` for the freshly-provisioned persona so
//! the operator can `git commit -S` immediately without running
//! `did-git-sign init` by hand. All inputs are already in cli2 state at
//! this point — the persona signing key + admin VC + VTA URL/DID — so the
//! install is non-interactive.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin,
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
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

#[derive(Clone, Debug, Default)]
pub struct DidGitSignSetup;

impl DidGitSignSetup {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => match state.props.state.did_git_sign.completed {
                Completion::CompletedOK | Completion::CompletedFail => {
                    // Either way, we're done with this page — install
                    // failure is non-fatal (operator can re-run
                    // `did-git-sign init` later) and we let the wizard
                    // continue.
                    let result = navigate(SetupEvent::DidGitSignDone, &state.props.state);
                    handle_nav_result(result, state);
                }
                Completion::NotFinished => {
                    // Still installing — Enter is a no-op.
                }
            },
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Configure git commit signing "),
            middle,
        );

        let mut lines = vec![
            Line::styled(
                "OpenVTC is configuring `did-git-sign` so you can sign git commits",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::styled(
                "with this persona's signing key — no extra setup steps required.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
        ];

        for msg in &state.did_git_sign.messages {
            match msg {
                MessageType::Info(info) => lines.push(Line::styled(
                    format!("  {info}"),
                    Style::new().fg(COLOR_SUCCESS),
                )),
                MessageType::Error(err) => lines.push(Line::styled(
                    format!("  ERROR: {err}"),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                )),
            }
        }

        match state.did_git_sign.completed {
            Completion::NotFinished => {
                lines.push(Line::styled(
                    "  Installing… please wait.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            Completion::CompletedOK => {
                if let Some(path) = &state.did_git_sign.config_path {
                    lines.push(Line::default());
                    lines.push(Line::from(vec![
                        Span::styled("Config: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(path, Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                }
                if let Some(pk) = &state.did_git_sign.ssh_public_key {
                    lines.push(Line::from(vec![
                        Span::styled("Pubkey: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                        Span::styled(pk, Style::new().fg(COLOR_SOFT_PURPLE)),
                    ]));
                    lines.push(Line::default());
                    lines.push(Line::styled(
                        "Add this SSH public key to your git host's signing-key settings",
                        Style::new().fg(COLOR_ORANGE),
                    ));
                    lines.push(Line::styled(
                        "to make signed commits show as 'Verified'.",
                        Style::new().fg(COLOR_ORANGE),
                    ));
                }
                if let Some(prev) = &state.did_git_sign.overridden_global_signing_key {
                    lines.push(Line::default());
                    lines.push(Line::styled(
                        format!("Note: your global user.signingKey ({prev}) was shadowed locally."),
                        Style::new().fg(COLOR_DARK_GRAY),
                    ));
                }
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            Completion::CompletedFail => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "did-git-sign install did not complete. You can re-run it later with",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
                lines.push(Line::styled(
                    "`did-git-sign init --vta-did <vta-did>`.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(
                        " to continue without git signing",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                ]));
            }
        }

        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            middle.inner(Margin::new(3, 2)),
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
