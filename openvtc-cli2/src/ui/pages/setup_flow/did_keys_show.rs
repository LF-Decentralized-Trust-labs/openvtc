use arboard::Clipboard;
use crossterm::event::{KeyCode, KeyEvent};
use openvtc::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_DARK_PURPLE, COLOR_ORANGE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
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
// DIDKeysShow
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub struct DIDKeysShow {
    /// Whether all keys have been copied to clipboard
    pub cc_copy: bool,
}

impl DIDKeysShow {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if let Some(did_keys) = &state.props.state.did_keys {
                    let mut clipboard = Clipboard::new().unwrap();
                    let signing_key = did_keys.signing.secret.get_public_keymultibase().unwrap();
                    let auth_key = did_keys
                        .authentication
                        .secret
                        .get_public_keymultibase()
                        .unwrap();
                    let decrypt_key = did_keys
                        .decryption
                        .secret
                        .get_public_keymultibase()
                        .unwrap();

                    let clipboard_text = format!(
                        "Signing Key (Ed25519): {}\n\nAuthentication Key (Ed25519): {}\n\nDecryption Key (X25519): {}",
                        signing_key, auth_key, decrypt_key
                    );

                    clipboard.set_text(clipboard_text).unwrap();
                    state.did_keys_show.cc_copy = true;
                }
            }
            KeyCode::Enter => {
                state.props.state.active_page = SetupPage::DidKeysExportAsk;
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
            .title(" Step 3/4: DID Keys ");

        let mut lines = vec![
            Line::styled(
                "These DID keys are used for cryptographic operations, including signing and encrypting data.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Your keys have been created via the VTA service.",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the keys
        if let Some(did_keys) = &state.did_keys {
            // Signing Key
            lines.push(Line::styled(
                format!(
                    "Signing key ({}) created:",
                    did_keys.signing.secret.get_key_type()
                ),
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::from(vec![
                Span::styled("🔑 ", Style::new()),
                Span::styled(
                    did_keys.signing.secret.get_public_keymultibase().unwrap(),
                    Style::new().fg(COLOR_DARK_PURPLE),
                ),
            ]));
            lines.push(Line::default());

            // Authentication Key
            lines.push(Line::styled(
                format!(
                    "Authentication key ({}) created:",
                    did_keys.authentication.secret.get_key_type()
                ),
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::from(vec![
                Span::styled("🔑 ", Style::new()),
                Span::styled(
                    did_keys
                        .authentication
                        .secret
                        .get_public_keymultibase()
                        .unwrap(),
                    Style::new().fg(COLOR_DARK_PURPLE),
                ),
            ]));
            lines.push(Line::default());

            // Decryption Key
            lines.push(Line::styled(
                format!(
                    "Decryption key ({}) created:",
                    did_keys.decryption.secret.get_key_type()
                ),
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::from(vec![
                Span::styled("🔑 ", Style::new()),
                Span::styled(
                    did_keys
                        .decryption
                        .secret
                        .get_public_keymultibase()
                        .unwrap(),
                    Style::new().fg(COLOR_DARK_PURPLE),
                ),
            ]));
            lines.push(Line::default());
        } else {
            lines.push(Line::from(vec![
                Span::styled(
                    "ERROR: ",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ),
                Span::styled(
                    "Expected to see DID keys, instead they don't exist!",
                    Style::new().fg(COLOR_ORANGE),
                ),
            ]));
        }

        lines.push(Line::default());
        lines.push(Line::styled(
            "ℹ️ Note: These keys can be exported later from your personal Verifiable Trust Agent.",
            Style::new().fg(COLOR_ORANGE),
        ));

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[C]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(
                " Copy to clipboard  |  ",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));
        if self.cc_copy {
            lines.push(Line::styled(
                "Derived keys copied!",
                Style::new().fg(COLOR_SUCCESS).slow_blink(),
            ));
        }

        frame.render_widget(
            Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
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
