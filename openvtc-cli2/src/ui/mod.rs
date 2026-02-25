use crate::{
    Interrupted,
    state_handler::{actions::Action, state::State},
    ui::{
        component::{Component, ComponentRender},
        pages::AppRouter,
    },
};
use anyhow::{Context, Result};
use crossterm::{
    event::{DisableMouseCapture, Event, EventStream},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::CrosstermBackend};
use std::io::{self, Stdout};
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver},
};
use tokio_stream::StreamExt;

pub mod component;
pub mod pages;

pub fn shorten_did(did: &str, max_len: usize) -> String {
    let char_count = did.chars().count();

    if char_count <= max_len {
        return did.to_string();
    }

    let ellipsis = "...";
    let keep = (max_len - ellipsis.len()) / 2;

    let start: String = did.chars().take(keep).collect();
    let end: String = did.chars().skip(char_count - keep).collect();

    format!("{}...{}", start, end)
}

pub struct UiManager {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl UiManager {
    pub fn new() -> (Self, UnboundedReceiver<Action>) {
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        (Self { action_tx }, action_rx)
    }

    pub async fn main_loop(
        self,
        mut state_rx: UnboundedReceiver<State>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> Result<Interrupted> {
        let mut terminal = setup_terminal()?;

        let mut crossterm_events = EventStream::new();
        // let mut ticker = tokio::time::interval(Duration::from_millis(250));

        // consume the first state to initialize the ui app
        let mut app_router = {
            match state_rx.recv().await {
                Some(state) => AppRouter::new(&state, self.action_tx.clone()),
                _ => {
                    let _ = restore_terminal(&mut terminal);
                    return Err(anyhow::anyhow!(
                        "could not get the initial application state"
                    ));
                }
            }
        };

        let result: anyhow::Result<Interrupted> = loop {
            if let Err(err) = terminal
                .draw(|frame| app_router.render(frame, ()))
                .context("could not render to the terminal")
            {
                break Err(err);
            }

            tokio::select! {
                // Tick to terminate the select every N milliseconds
                // _ = ticker.tick() => (),
                // Catch and handle crossterm events
               maybe_event = crossterm_events.next() => match maybe_event {
                    Some(Ok(Event::Key(key)))  => {
                        app_router.handle_key_event(key);
                    },
                    None => break Ok(Interrupted::UserInt),
                    _ => (),
                },
                // Handle state updates
                Some(state) = state_rx.recv() => {
                    app_router = app_router.move_with_state(&state);
                },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break Ok(interrupted);
                }
            }
        };

        restore_terminal(&mut terminal)?;

        result
    }
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    let mut stdout = io::stdout();

    enable_raw_mode()?;

    execute!(stdout, EnterAlternateScreen, DisableMouseCapture)?;

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    terminal.clear()?;

    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;

    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;

    Ok(terminal.show_cursor()?)
}
