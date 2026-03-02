use crossterm::event::{Event, KeyCode, KeyEvent};
use openvtc::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT,
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
        setup_sequence::SetupState,
    },
    ui::pages::setup_flow::{
        SetupFlow, render_setup_header,
        navigation::{SetupEvent, handle_nav_result, navigate},
    },
};

// ****************************************************************************
// WebvhServerSelect - Two-phase selection page
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct WebvhServerSelect {
    pub phase: SelectPhase,
    pub method: SelectMethod,
    pub selected_server_index: usize,
    pub path_input: Input,
}

#[derive(Clone, Debug, Default)]
pub enum SelectPhase {
    #[default]
    ChooseMethod,
    ServerConfig,
}

#[derive(Copy, Clone, Debug, Default)]
pub enum SelectMethod {
    #[default]
    UseServer,
    CreateManually,
}

impl SelectMethod {
    pub fn switch(&self) -> Self {
        match self {
            SelectMethod::UseServer => SelectMethod::CreateManually,
            SelectMethod::CreateManually => SelectMethod::UseServer,
        }
    }
}

impl WebvhServerSelect {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            _ => match state.webvh_server_select.phase {
                SelectPhase::ChooseMethod => {
                    handle_choose_method(state, key);
                }
                SelectPhase::ServerConfig => {
                    handle_server_config(state, key);
                }
            },
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 2/4: DID Hosting "),
            middle,
        );

        match self.phase {
            SelectPhase::ChooseMethod => {
                render_choose_method(self, frame, middle);
            }
            SelectPhase::ServerConfig => {
                render_server_config(self, state, frame, middle);
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

fn handle_choose_method(state: &mut SetupFlow, key: KeyEvent) {
    match key.code {
        KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
            state.webvh_server_select.method = state.webvh_server_select.method.switch();
        }
        KeyCode::Enter => match state.webvh_server_select.method {
            SelectMethod::CreateManually => {
                let result = navigate(SetupEvent::CreateManually, &state.props.state);
                handle_nav_result(result, state);
            }
            SelectMethod::UseServer => {
                state.webvh_server_select.phase = SelectPhase::ServerConfig;
            }
        },
        _ => {}
    }
}

fn handle_server_config(state: &mut SetupFlow, key: KeyEvent) {
    let server_count = state.props.state.vta.webvh_servers.len();

    match key.code {
        KeyCode::Up => {
            if server_count > 1 && state.webvh_server_select.selected_server_index > 0 {
                state.webvh_server_select.selected_server_index -= 1;
            }
        }
        KeyCode::Down => {
            if server_count > 1
                && state.webvh_server_select.selected_server_index < server_count - 1
            {
                state.webvh_server_select.selected_server_index += 1;
            }
        }
        KeyCode::Esc => {
            // Go back to method selection
            state.webvh_server_select.phase = SelectPhase::ChooseMethod;
            state.webvh_server_select.path_input.reset();
        }
        KeyCode::Enter => {
            let servers = &state.props.state.vta.webvh_servers;
            if let Some(server) = servers.get(state.webvh_server_select.selected_server_index) {
                let server_id = server.id.clone();
                let path_value = state.webvh_server_select.path_input.value().to_string();
                let custom_path = if path_value.is_empty() {
                    None
                } else {
                    Some(path_value)
                };

                // Store server selection in webvh_server state for UI rendering
                state.props.state.webvh_server.selected_server_id = server_id.clone();
                state.props.state.webvh_server.custom_path = custom_path.clone();

                let result = navigate(
                    SetupEvent::UseWebvhServer { server_id, custom_path },
                    &state.props.state,
                );
                handle_nav_result(result, state);
            }
        }
        _ => {
            // Handle text input for path
            state
                .webvh_server_select
                .path_input
                .handle_event(&Event::Key(key));
        }
    }
}

fn render_choose_method(select: &WebvhServerSelect, frame: &mut Frame, area: Rect) {
    let content = area.inner(Margin::new(3, 2));

    let mut lines = vec![
        Line::styled(
            "Your VTA has WebVH server(s) available. You can create and host your DID automatically, or set it up manually.",
            Style::new().fg(COLOR_DARK_GRAY),
        ),
        Line::default(),
        Line::styled(
            "How would you like to host your DID?",
            Style::new().fg(COLOR_BORDER).bold(),
        ),
        Line::default(),
    ];

    match select.method {
        SelectMethod::UseServer => {
            lines.push(Line::styled(
                "[✓] Use WebVH Server (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Create and host your DID automatically via the VTA's WebVH server.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] Create Manually",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        }
        SelectMethod::CreateManually => {
            lines.push(Line::styled(
                "[ ] Use WebVH Server (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] Create Manually",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Create keys locally and host the DID document yourself (e.g., GitHub Pages).",
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
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        content,
    );
}

fn render_server_config(
    select: &WebvhServerSelect,
    state: &SetupState,
    frame: &mut Frame,
    area: Rect,
) {
    let servers = &state.vta.webvh_servers;

    let content: [Rect; 3] =
        Layout::vertical([Length(5), Length(3), Min(0)]).areas(area.inner(Margin::new(3, 2)));

    let mut lines = vec![];

    // Server selection (if multiple)
    if servers.len() > 1 {
        lines.push(Line::styled(
            "Select a WebVH server:",
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        lines.push(Line::default());

        for (i, server) in servers.iter().enumerate() {
            let label = server
                .label
                .as_deref()
                .unwrap_or(&server.id);
            if i == select.selected_server_index {
                lines.push(Line::styled(
                    format!("[✓] {}", label),
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
            } else {
                lines.push(Line::styled(
                    format!("[ ] {}", label),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ));
            }
        }
        lines.push(Line::default());
    } else if let Some(server) = servers.first() {
        let label = server
            .label
            .as_deref()
            .unwrap_or(&server.id);
        lines.push(Line::from(vec![
            Span::styled("Server: ", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(label, Style::new().fg(COLOR_SOFT_PURPLE)),
        ]));
        lines.push(Line::default());
    }

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        content[0],
    );

    // Path input
    let path_header = Line::styled(
        "Custom path (optional, leave empty for auto-generated):",
        Style::new().fg(COLOR_BORDER).bold(),
    );
    frame.render_widget(Paragraph::new(path_header), content[1]);

    let [input_prompt, input_box] =
        Layout::horizontal([Length(2), Min(0)]).areas(Rect {
            x: content[1].x,
            y: content[1].y + 1,
            width: content[1].width,
            height: 1,
        });

    frame.render_widget(
        Paragraph::new(Span::styled(
            "> ",
            Style::new().fg(COLOR_SOFT_PURPLE).bold(),
        )),
        input_prompt,
    );

    render_input(&select.path_input, frame, input_box);

    // Helpful info and key bindings
    let mut info_lines = vec![Line::default()];

    // Show how the path maps to a URL and DID
    let path_value = select.path_input.value();

    // Extract server domain from the selected server's DID (did:webvh:<scid>:domain:...)
    let server_domain = servers
        .get(select.selected_server_index)
        .map(|s| {
            // Server DID format: did:webvh:<scid>:domain.com or similar
            // Extract domain from DID by taking everything after the SCID
            let parts: Vec<&str> = s.did.splitn(4, ':').collect();
            if parts.len() >= 4 {
                parts[3].replace(':', "/")
            } else {
                s.did.clone()
            }
        })
        .unwrap_or_default();

    if path_value.is_empty() {
        info_lines.push(Line::styled(
            "If left empty, a random mnemonic phrase will be used as the path.",
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        info_lines.push(Line::default());
        info_lines.push(Line::from(vec![
            Span::styled("DID document URL: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(
                format!("https://{}/{{mnemonic}}/did.jsonl", server_domain),
                Style::new().fg(COLOR_ORANGE).italic(),
            ),
        ]));
        info_lines.push(Line::from(vec![
            Span::styled("Your DID:         ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(
                format!("did:webvh:{{scid}}:{}:{{mnemonic}}", server_domain),
                Style::new().fg(COLOR_ORANGE).italic(),
            ),
        ]));
    } else {
        info_lines.push(Line::from(vec![
            Span::styled("DID document URL: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(
                format!("https://{}/{}/did.jsonl", server_domain, path_value),
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            ),
        ]));
        info_lines.push(Line::from(vec![
            Span::styled("Your DID:         ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled(
                format!("did:webvh:{{scid}}:{}:{}", server_domain, path_value),
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            ),
        ]));
    }

    info_lines.push(Line::default());

    if servers.len() > 1 {
        info_lines.push(Line::from(vec![
            Span::styled("[UP/DOWN]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" select server  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" go back  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));
    } else {
        info_lines.push(Line::from(vec![
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" go back  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));
    }

    frame.render_widget(
        Paragraph::new(info_lines).wrap(Wrap { trim: false }),
        content[2],
    );
}

fn render_input(input: &Input, frame: &mut Frame, area: Rect) {
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
