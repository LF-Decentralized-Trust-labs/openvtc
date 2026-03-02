//! Handles the setup of the Persona WebVH DID
//! Allows creating a new DID or importing an existing one
use crossterm::event::{Event, KeyCode, KeyEvent};
use openvtc::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin, Rect,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    state_handler::{
        actions::Action,
        setup_sequence::{Completion, MessageType, SetupState},
    },
    ui::pages::setup_flow::{
        SetupFlow, render_setup_header,
        navigation::{SetupEvent, handle_nav_result, navigate},
    },
};

// ****************************************************************************
// WebvhAddress
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct WebvhAddress {
    pub address: Input,
    pub state: WebVHState,
    pub choice: WebVHChoice,
    pub processing: bool,
}

#[derive(Clone, Debug, Default)]
pub enum WebVHState {
    /// Unknown State - shows a choice
    #[default]
    Unknown,

    /// Create a new DID
    NewDID,

    /// Use an existing DID
    ExistingDID,
}

#[derive(Copy, Clone, Debug, Default)]
pub enum WebVHChoice {
    #[default]
    Create,
    Import,
}
impl WebVHChoice {
    /// Switches to the next panel when pressing <TAB>
    pub fn switch(&self) -> Self {
        match self {
            WebVHChoice::Create => WebVHChoice::Import,
            WebVHChoice::Import => WebVHChoice::Create,
        }
    }
}

impl WebvhAddress {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match (key.code, &state.webvh_address.state) {
            (KeyCode::F(10), _) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            (KeyCode::Tab | KeyCode::Up | KeyCode::Down, WebVHState::Unknown) => {
                state.webvh_address.choice = state.webvh_address.choice.switch();
            }
            (KeyCode::Enter, WebVHState::Unknown) => {
                // Selection mode
                match state.webvh_address.choice {
                    WebVHChoice::Create => {
                        state.webvh_address.state = WebVHState::NewDID;
                    }
                    WebVHChoice::Import => {
                        state.webvh_address.state = WebVHState::ExistingDID;
                    }
                }
            }
            (KeyCode::Enter, WebVHState::NewDID) => {
                match state.props.state.webvh_address.completed {
                    Completion::CompletedOK => {
                        let result = navigate(SetupEvent::WebVHComplete, &state.props.state);
                        handle_nav_result(result, state);
                    }
                    Completion::CompletedFail => {
                        // Reset to try again
                        state.webvh_address.address.reset();
                        state.webvh_address.processing = false;
                        let _ = state.action_tx.send(Action::ResetWebVHDID);
                    }
                    Completion::NotFinished => {
                        let _ = state.action_tx.send(Action::CreateWebVHDID(
                            state.webvh_address.address.value().to_string(),
                        ));
                        state.webvh_address.processing = true;
                    }
                }
            }
            (KeyCode::Enter, WebVHState::ExistingDID) => {
                match state.props.state.webvh_address.completed {
                    Completion::CompletedOK => {
                        let result = navigate(SetupEvent::WebVHComplete, &state.props.state);
                        handle_nav_result(result, state);
                    }
                    Completion::CompletedFail => {
                        // Reset to try again
                        state.webvh_address.address.reset();
                        state.webvh_address.processing = false;
                        let _ = state.action_tx.send(Action::ResetWebVHDID);
                    }
                    Completion::NotFinished => {
                        let _ = state.action_tx.send(Action::ResolveWebVHDID(
                            state.webvh_address.address.value().to_string(),
                        ));
                        state.webvh_address.processing = true;
                    }
                }
            }
            (KeyCode::Esc, _) => {
                state.webvh_address.address.reset();
            }
            _ => {
                // Handle text input
                state.webvh_address.address.handle_event(&Event::Key(key));
            }
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
                .title(" Step 2/2 Persona DID Setup "),
            middle,
        );

        match self.state {
            WebVHState::Unknown => {
                render_selection(self, frame, middle);
            }
            WebVHState::NewDID => {
                render_new_did(self, state, frame, middle);
            }
            WebVHState::ExistingDID => {
                render_import_did(self, state, frame, middle);
            }
        }

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

/// Renders the WebVH Selection Choice
fn render_selection(state: &WebvhAddress, frame: &mut Frame<'_>, area: Rect) {
    let mut lines = Vec::new();

    lines.push(Line::styled(
        "You can create a new WebVH DID using the keys created via your VTA service, or restore an existing DID.",
        Style::new().fg(COLOR_DARK_GRAY),
    ));
    lines.push(Line::default());
    lines.push(Line::styled(
        "How would you like to set up your DID?",
        Style::new().fg(COLOR_BORDER).bold(),
    ));
    lines.push(Line::default());

    // Render the active choice
    if let WebVHChoice::Create = state.choice {
        lines.push(Line::styled(
            "[✓] Create a new WebVH DID",
            Style::new().fg(COLOR_SUCCESS).bold(),
        ));
        lines.push(Line::styled(
            "    Generate a brand new DID for this profile. You'll provide a hosting URL where the DID document will be hosted.",
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        lines.push(Line::styled(
            "[ ] Import an existing WebVH DID",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ));
        lines.push(Line::styled(
            "    Restore a DID you previously created. You'll need to provide the WebVH DID value.",
            Style::new().fg(COLOR_DARK_GRAY),
        ));
    } else {
        lines.push(Line::styled(
            "[ ] Create a new WebVH DID",
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ));
        lines.push(Line::styled(
            "    Generate a brand new DID for this profile. You'll provide a hosting URL where the DID document will be hosted.",
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        lines.push(Line::styled(
            "[✓] Import an existing WebVH DID",
            Style::new().fg(COLOR_SUCCESS).bold(),
        ));
        lines.push(Line::styled(
            "    Restore a DID you previously created. You'll need to provide the WebVH DID value.",
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
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        area.inner(Margin::new(3, 2)),
    );
}

/// Renders input for a new DID creation
fn render_new_did(
    state: &WebvhAddress,
    backend_state: &SetupState,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    // 0: Input 0 Header
    // 1: INPUT
    // 2: Key Bindings
    let content: [Rect; 3] =
        Layout::vertical([Length(4), Length(2), Min(0)]).areas(area.inner(Margin::new(3, 2)));

    let [input0_prompt, input0_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

    frame.render_widget(
Paragraph::new(vec![
                Line::styled(
                    "Your identity within OpenVTC is represented using the Web Verifiable History (WebVH) DID method.", 
                    Style::new().fg(COLOR_DARK_GRAY)
                ),
                Line::default(),
                Line::styled(
                    "Enter the web address where your DID will be hosted:",
                    Style::new().fg(COLOR_BORDER).bold(),
                )
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

    render_input(&state.address, frame, input0_box);

    let mut lines = Vec::new();
    if state.processing {
        for msg in backend_state.webvh_address.messages.iter() {
            match msg {
                MessageType::Info(info) => {
                    lines.push(Line::styled(
                        format!("INFO: {}", info),
                        Style::new().fg(COLOR_SUCCESS),
                    ));
                }
                MessageType::Error(err) => {
                    lines.push(Line::styled(
                        format!("ERROR: {}", err),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    ));
                }
            }
        }
        if backend_state.webvh_address.messages.is_empty() {
            lines.push(Line::styled(
                "Processing... please wait.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        } else {
            lines.push(Line::default());
        }

        match backend_state.webvh_address.completed {
            Completion::NotFinished => {}
            Completion::CompletedOK => {
                lines.push(Line::from(vec![
                    Span::styled("Your Persona DID: ", Style::new().fg(COLOR_SUCCESS).bold()),
                    Span::styled(
                        &backend_state.webvh_address.did,
                        Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                    ),
                ]));

                lines.push(Line::default());
                lines.push(Line::styled(
                    "ℹ️ Upload Instructions:",
                    Style::new().fg(COLOR_ORANGE).bold(),
                ));
                lines.push(Line::default());

                // Trim base url to remove trailing slash
                let base_url = state.address.value().trim_end_matches('/');

                // Check if there's a subpath after the base domain
                let has_subfolder = base_url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .contains('/');

                let expected_url = if has_subfolder {
                    format!("{}/did.jsonl", base_url)
                } else {
                    format!("{}/.well-known/did.jsonl", base_url)
                };

                lines.push(Line::from(vec![
                    Span::styled("1. Find ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled("did.jsonl", Style::new().fg(COLOR_SOFT_PURPLE).bold()),
                    Span::styled(
                        " in your current directory.",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                ]));

                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled(
                        "2. Upload it to your hosting service so it's accessible at: ",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                    Span::styled(expected_url, Style::new().fg(COLOR_SOFT_PURPLE).bold()),
                ]));

                lines.push(Line::default());
                lines.push(Line::styled(
                    "3. Ensure the file is publicly accessible via HTTPS.",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            Completion::CompletedFail => {
                lines.push(Line::styled(
                    "WebVH DID creation failed. Press [ENTER] to try again.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ));
            }
        }
    } else {
        lines.extend_from_slice(&[
            Line::styled(
                "ℹ️ Note: For example, if hosting your DID using GitHub Pages, use a URL like: ",
                Style::new().fg(COLOR_ORANGE),
            ),
            Line::styled(
                "         • https://<username>.github.io/",
                Style::new().fg(COLOR_ORANGE).bold().italic(),
            ),
            Line::styled(
                "         • https://<username>.github.io/openvtc-did/",
                Style::new().fg(COLOR_ORANGE).bold().italic(),
            ),
            Line::default(),
            Line::from(vec![
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to clear input  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]),
            Line::default(),
            Line::styled("What is WebVH DID?", Style::new().fg(COLOR_BORDER).bold()),
            Line::styled(
                "• Decentralized identifier accessible via HTTPS",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "• Changes are tracked using Verifiable History Logs",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "• No blockchain or external services required beyond simple web hosting",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "• Full control and ownership over your DID and where you choose to host it",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
        ]);
    }
    frame.render_widget(Paragraph::new(lines), content[2]);
}

/// Renders input for importing an existing DID
fn render_import_did(
    state: &WebvhAddress,
    backend_state: &SetupState,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    // 0: Input 0 Header
    // 1: INPUT
    // 2: Key Bindings
    let content: [Rect; 3] =
        Layout::vertical([Length(2), Length(2), Min(0)]).areas(area.inner(Margin::new(3, 2)));

    let [input0_prompt, input0_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

    frame.render_widget(
        Paragraph::new(vec![Line::styled(
            "Enter your WebVH DID:",
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

    render_input(&state.address, frame, input0_box);

    let mut lines = Vec::new();
    if state.processing {
        for msg in backend_state.webvh_address.messages.iter() {
            match msg {
                MessageType::Info(info) => {
                    lines.push(Line::styled(
                        format!("INFO: {}", info),
                        Style::new().fg(COLOR_SUCCESS),
                    ));
                }
                MessageType::Error(err) => {
                    lines.push(Line::styled(
                        format!("ERROR: {}", err),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    ));
                }
            }
        }
        if backend_state.webvh_address.messages.is_empty() {
            lines.push(Line::styled(
                "Resolving... please wait.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        } else {
            lines.push(Line::default());
        }

        match backend_state.webvh_address.completed {
            Completion::NotFinished => {}
            Completion::CompletedOK => {
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            Completion::CompletedFail => {
                lines.push(Line::styled(
                    "WebVH DID Resolution failed. Press [ENTER] to try again.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ));
            }
        }
    } else {
        lines.extend_from_slice(&[
            Line::default(),
            Line::from(vec![
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to clear input  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]),
            Line::default(),
            Line::styled("What is WebVH DID?", Style::new().fg(COLOR_BORDER).bold()),
            Line::styled(
                "• Decentralized identifier accessible via HTTPS",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "• Changes are tracked using Verifiable History Logs",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "• No blockchain or external services required beyond simple web hosting",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Line::styled(
                "• Full control and ownership over your DID and where you choose to host it",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
        ]);
    }
    frame.render_widget(Paragraph::new(lines), content[2]);
}
