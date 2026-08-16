//! Join flow — step 1: ask for the community (VTC) DID.
//!
//! Mirrors `setup_flow::vta_enter_did`. On submit we send
//! [`Action::JoinSubmitVtc`], which kicks off the automated persona-mint +
//! sub-context + join-submit sequence. Esc cancels the whole flow.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT,
};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
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
    state_handler::{actions::Action, join::JoinState},
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Debug, Default)]
pub struct VtcEnterDid;

impl VtcEnterDid {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        // Input is locked while the background sequence runs.
        if state.props.state.processing {
            return;
        }
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                // Submit unconditionally, empty input included: the handler
                // answers an empty field with an on-screen reason. Swallowing
                // the keypress here made Enter look broken after a VIC paste,
                // which populates the invitation but not this input (issue #29).
                let did = state.vtc_did.value().trim().to_string();
                let _ = state.action_tx.send(Action::JoinSubmitVtc(did));
            }
            KeyCode::Esc => {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            // Ctrl+V: the explicit "paste an invitation" affordance. Intercepted
            // ahead of the input handler so it loads a VIC rather than typing
            // into the DID field. Bracketed paste still works and is the path
            // that survives SSH; this is the discoverable one.
            KeyCode::Char('v') | KeyCode::Char('V')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                let _ = state.action_tx.send(Action::JoinPasteFromClipboard);
            }
            // Ctrl+L: clear a loaded invitation and join without it. Ctrl-modified
            // so it never collides with typing the VTC DID into the input field.
            KeyCode::Char('l') | KeyCode::Char('L')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && state.props.state.has_invitation =>
            {
                let _ = state.action_tx.send(Action::JoinClearVic);
            }
            _ => {
                state.vtc_did.handle_event(&Event::Key(key));
            }
        }
    }

    pub fn render(&self, state: &JoinState, input: &Input, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Join a community "),
            middle,
        );

        let inner = middle.inner(Margin::new(3, 2));

        // Everything the operator needs *before* typing goes above the input:
        // the invitation status and any error. Both used to sit below it, under
        // the examples block, where the invitation tip was the dimmest and
        // lowest thing on the page and read as decoration (issue #29).
        let width = inner.width as usize;
        let mut header = wrapped(
            "Enter the Verifiable Trust Community (VTC) DID you want to join. OpenVTC \
             will mint a fresh persona and submit a join request on your behalf.",
            width,
            Style::new().fg(COLOR_DARK_GRAY),
        );
        header.push(Line::default());
        header.extend(invitation_lines(state, width));
        // Surface any pre-submit error (e.g. idempotency, empty input) inline.
        let mut had_error = false;
        for msg in &state.messages {
            if let crate::state_handler::setup_sequence::MessageType::Error(err) = msg {
                header.extend(wrapped(
                    &format!("ERROR: {err}"),
                    width,
                    Style::new().fg(crate::colors::COLOR_WARNING_ACCESSIBLE_RED),
                ));
                had_error = true;
            }
        }
        if had_error {
            header.push(Line::default());
        }
        header.push(Line::styled(
            "Enter the community's DID or agent name:",
            Style::new().fg(COLOR_BORDER).bold(),
        ));

        // Height is the line count: every line above is already wrapped (or, for
        // a DID, truncated) to `inner`, so the block cannot rewrap under the
        // renderer and push the input off its row. Clamped so a terminal too
        // short for the whole block clips the *prose* rather than the input —
        // an unreachable input field is the one failure worth ruling out.
        let header_height = u16::try_from(header.len())
            .unwrap_or(u16::MAX)
            .min(inner.height.saturating_sub(2));
        let content: [Rect; 3] =
            Layout::vertical([Length(header_height), Length(2), Min(0)]).areas(inner);

        let [prompt_col, input_col] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

        frame.render_widget(Paragraph::new(header), content[0]);

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            prompt_col,
        );
        render_input(input, frame, input_col);

        let lines = vec![
            Line::styled("Examples:", Style::new().fg(COLOR_ORANGE).bold()),
            Line::styled(
                "  • did:webvh:QmRoot…:community.example.com",
                Style::new().fg(COLOR_ORANGE).italic(),
            ),
            Line::styled(
                "  • community.example.com/@acme",
                Style::new().fg(COLOR_ORANGE).italic(),
            ),
            Line::default(),
            Line::from(vec![
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to cancel  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to join", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]),
        ];

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content[2]);

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

/// The invitation status block shown above the DID input, always ending in a
/// blank line.
///
/// Explicit VIC state so the operator knows exactly what will be presented:
///   loaded   → it will ride in the join VP (community can auto-admit)
///   cleared  → operator dropped it; joining without one (may need review)
///   none     → never had one; offer the paste tip
///
/// The "loaded" case names the issuing community. A VIC's issuer *is* the
/// community being joined, and it is the DID prefilled into the input below —
/// showing it is what makes the prefill checkable rather than magic, and answers
/// "which community did this invitation come from" without leaving the page.
///
/// Prose is wrapped to `width` and the DID centre-truncated to it — the caller
/// sizes the header block by line count, so nothing may rewrap later.
fn invitation_lines(state: &JoinState, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if state.has_invitation {
        lines.extend(wrapped(
            "✓ Invitation credential loaded — it will be presented to the community.",
            width,
            Style::new().fg(COLOR_SUCCESS).bold(),
        ));
        if let Some(issuer) = &state.invitation_issuer {
            const LABEL: &str = "  Community: ";
            lines.push(Line::from(vec![
                Span::styled(LABEL, Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(
                    openvtc_core::display::truncate_did_centered(
                        issuer,
                        width.saturating_sub(LABEL.len()),
                    )
                    .into_owned(),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            ]));
        }
        lines.push(key_row(
            "[Ctrl+V]",
            " replace it from the clipboard   ·   [Ctrl+L] join without it",
            " replace   ·   [Ctrl+L] join without it",
            width,
        ));
    } else if state.vic_cleared {
        lines.extend(wrapped(
            "Invitation cleared — joining without a credential; the community may \
             require manual approval.",
            width,
            Style::new().fg(COLOR_ORANGE),
        ));
        lines.push(paste_row(width));
    } else {
        // The lead-in gets its own line: hanging it off a narrowed first line
        // wraps the body into a ragged column on small terminals.
        lines.push(Line::styled(
            "Have an invitation?",
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        lines.extend(wrapped(
            "Load the invitation credential (VIC) JSON — it fills in the community \
             DID for you and rides along with the join request.",
            width,
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ));
        lines.push(paste_row(width));
    }
    lines.push(Line::default());
    lines
}

/// The explicit "paste an invitation" row.
///
/// The reason issue #29 was filed at all: bracketed paste worked the whole
/// time, but nothing on screen said so, and an affordance nobody can see is not
/// an affordance. A named key is discoverable in the way "just paste" is not —
/// and it still degrades to bracketed paste over SSH, where reading the OS
/// clipboard cannot work.
fn paste_row(width: usize) -> Line<'static> {
    key_row(
        "[Ctrl+V]",
        " paste an invitation from the clipboard, or paste the JSON straight in",
        " paste an invitation",
        width,
    )
}

/// A `[Key] description` row, keys highlighted, falling back to `short` when
/// the long form would not fit `width`.
///
/// These rows are single `Line`s in a block sized by line count, so they clip
/// rather than wrap — a key row that loses its tail on a narrow terminal is
/// exactly the affordance this page is trying to make visible.
fn key_row(key: &str, long: &str, short: &str, width: usize) -> Line<'static> {
    let desc = if key.len() + long.chars().count() <= width {
        long
    } else {
        short
    };
    Line::from(vec![
        Span::styled(key.to_string(), Style::new().fg(COLOR_SOFT_PURPLE).bold()),
        Span::styled(desc.to_string(), Style::new().fg(COLOR_TEXT_DEFAULT)),
    ])
}

/// Hard-wrap `text` to `width` and style each resulting line.
///
/// The header block is sized by line count, so it renders unwrapped `Line`s —
/// which a `Paragraph` clips rather than wraps, losing the tail of anything too
/// long. Wrapping here keeps the count honest and the text whole. Reuses the
/// overlay wrapper, which already hard-splits DIDs and JSON (no spaces to break
/// on) rather than overflowing them.
fn wrapped(text: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    crate::ui::pages::main::wrap_text(text, width)
        .into_iter()
        .map(|l| Line::styled(l, style))
        .collect()
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

#[cfg(test)]
mod tests {
    //! The invitation status block is sized by line count, not by wrapping, so
    //! these render the page and read the buffer back — a line that wrapped
    //! would silently push the input off its row.
    use super::*;
    use crate::state_handler::setup_sequence::MessageType;
    use ratatui::{Terminal, backend::TestBackend};

    const ISSUER: &str = "did:webvh:QmRootQmRootQmRoot:community.example.com";

    /// Render at `width`×24 and return the drawn rows, trailing spaces trimmed.
    fn rows(state: &JoinState, input: &str, width: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).expect("test terminal");
        let input = Input::new(input.to_string());
        terminal
            .draw(|frame| VtcEnterDid.render(state, &input, frame))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(|c| c.symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn row_of(rows: &[String], needle: &str) -> usize {
        rows.iter()
            .position(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("{needle:?} not drawn in:\n{}", rows.join("\n")))
    }

    /// The explicit paste key is named on screen in every invitation state.
    /// Bracketed paste worked all along; nothing said so, which is why the
    /// issue was filed as "I cannot find anywhere to import a VIC".
    #[test]
    fn the_paste_key_is_named_in_every_state() {
        let states = [
            ("none", JoinState::default()),
            (
                "cleared",
                JoinState {
                    vic_cleared: true,
                    ..JoinState::default()
                },
            ),
            (
                "loaded",
                JoinState {
                    has_invitation: true,
                    invitation_issuer: Some(ISSUER.to_string()),
                    ..JoinState::default()
                },
            ),
        ];
        for (name, state) in states {
            for width in [60, 100] {
                let drawn = rows(&state, "", width).join("\n");
                assert!(
                    drawn.contains("[Ctrl+V]"),
                    "{name} at width {width} should name the paste key:\n{drawn}"
                );
            }
        }
    }

    /// Ctrl+V loads a VIC instead of typing a `v` into the DID field.
    #[test]
    fn ctrl_v_asks_for_the_clipboard_rather_than_typing() {
        use crate::ui::component::Component;
        use crate::{state_handler::state::State, ui::pages::join_flow::JoinFlow};
        use tokio::sync::mpsc::unbounded_channel;

        let (tx, mut rx) = unbounded_channel();
        let mut flow = JoinFlow::new(&State::default(), tx);
        VtcEnterDid::handle_key_event(
            &mut flow,
            KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL),
        );
        assert!(
            matches!(rx.try_recv(), Ok(Action::JoinPasteFromClipboard)),
            "expected JoinPasteFromClipboard"
        );
        assert_eq!(flow.vtc_did.value(), "", "the key must not reach the input");
    }

    /// A plain `v` is still just a character — the guard is on the modifier.
    #[test]
    fn a_bare_v_still_types() {
        use crate::ui::component::Component;
        use crate::{state_handler::state::State, ui::pages::join_flow::JoinFlow};
        use tokio::sync::mpsc::unbounded_channel;

        let (tx, mut rx) = unbounded_channel();
        let mut flow = JoinFlow::new(&State::default(), tx);
        VtcEnterDid::handle_key_event(
            &mut flow,
            KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE),
        );
        assert!(
            rx.try_recv().is_err(),
            "no action for an ordinary keystroke"
        );
        assert_eq!(flow.vtc_did.value(), "v");
    }

    /// The paste affordance is the thing an operator holding a VIC needs to
    /// see; it belongs above the input, not below the examples (issue #29).
    #[test]
    fn the_paste_affordance_is_drawn_above_the_input() {
        let drawn = rows(&JoinState::default(), "", 100);
        assert!(
            row_of(&drawn, "Have an invitation?") < row_of(&drawn, "Enter the community's DID"),
            "the invitation prompt should precede the input prompt:\n{}",
            drawn.join("\n")
        );
        // And still ahead of the examples that used to bury it.
        assert!(row_of(&drawn, "Have an invitation?") < row_of(&drawn, "Examples:"));
    }

    /// A loaded invitation names the community it is for — that DID is what
    /// gets prefilled into the input, so it has to be visible to be checkable.
    #[test]
    fn a_loaded_invitation_names_its_community() {
        let state = JoinState {
            has_invitation: true,
            invitation_issuer: Some(ISSUER.to_string()),
            ..JoinState::default()
        };
        let drawn = rows(&state, ISSUER, 100);
        let row = &drawn[row_of(&drawn, "Community:")];
        assert!(row.contains("community.example.com"), "got {row:?}");
    }

    /// On a terminal too small for the whole status block the prose clips, but
    /// the input the operator has to type into stays on screen.
    #[test]
    fn a_cramped_terminal_still_shows_the_input() {
        let mut terminal = Terminal::new(TestBackend::new(40, 14)).expect("test terminal");
        let state = JoinState {
            has_invitation: true,
            invitation_issuer: Some(ISSUER.to_string()),
            ..JoinState::default()
        };
        let input = Input::new("did:webvh:typed".to_string());
        terminal
            .draw(|frame| VtcEnterDid.render(&state, &input, frame))
            .expect("render");
        let drawn: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(drawn.contains("> did:webvh:typed"), "got:\n{drawn}");
    }

    /// The input row must stay put whatever the status block says, at a width
    /// narrow enough that an unwrapped long DID would have spilled.
    #[test]
    fn the_input_keeps_its_row_across_states_and_widths() {
        let mut with_error = JoinState {
            has_invitation: true,
            invitation_issuer: Some(ISSUER.to_string()),
            ..JoinState::default()
        };
        with_error
            .messages
            .push(MessageType::Error("something went wrong".to_string()));
        let states = [
            JoinState::default(),
            JoinState {
                vic_cleared: true,
                ..JoinState::default()
            },
            JoinState {
                has_invitation: true,
                invitation_issuer: Some(ISSUER.to_string()),
                ..JoinState::default()
            },
            with_error,
        ];
        for width in [60, 100, 160] {
            for (i, state) in states.iter().enumerate() {
                let drawn = rows(state, "did:webvh:typed", width);
                let prompt = row_of(&drawn, "Enter the community's DID");
                let input = row_of(&drawn, "> did:webvh:typed");
                assert_eq!(
                    input,
                    prompt + 1,
                    "state {i} at width {width}: input should sit directly under its \
                     prompt:\n{}",
                    drawn.join("\n")
                );
            }
        }
    }
}
