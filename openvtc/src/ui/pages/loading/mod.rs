//! The startup loading screen (`ActivePage::Loading`).
//!
//! Shown while the app loads its config and establishes the mediator
//! connection, replacing the previous behaviour of rendering the full (but not
//! yet interactive) main page during startup. It surfaces the current startup
//! phase, a tail of the activity log, a rotating tip, and — on failure — the
//! full error plus a recovery suggestion.
//!
//! A small [`Component`] mirroring the shape of the other pages: a `Props`
//! struct mapped `From<&State>` carries everything the screen renders, so the
//! component itself stays free of business logic.

use crate::{
    colors::{
        COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
        COLOR_WARNING_ACCESSIBLE_RED,
    },
    state_handler::{
        actions::Action,
        state::{LoadingStep, MediatorStatus, State},
    },
    ui::component::{Component, ComponentRender},
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Flex, Layout,
    },
    style::Style,
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};
use tokio::sync::mpsc::UnboundedSender;

/// Rotating friendly/fun tips about verifiable trust shown during startup.
/// Indexed by `tip_index % TIPS.len()`.
const TIPS: &[&str] = &[
    "Tip: A DID is an identifier you control — no central registrar required.",
    "Did you know? Verifiable credentials are cryptographically tamper-evident.",
    "Tip: Your keys never leave your device — trust is proven, not surrendered.",
    "Did you know? did:webvh anchors your DID to a verifiable history log.",
    "Tip: DIDComm messages are end-to-end encrypted between peers.",
    "Tip: A relationship is mutual — both parties prove who they are.",
];

/// Multi-line banner shown at the top of the loading screen.
const BANNER: &[&str] = &[
    "  ___                __     _______ ___ ",
    " / _ \\ _ __  ___ _ _ \\ \\   / |_   _/ __|",
    "| (_) | '_ \\/ -_) ' \\ \\ \\ / /  | || (__ ",
    " \\___/| .__/\\___|_||_| \\_V_/   |_| \\___|",
    "      |_|                               ",
];

/// State-mapped props for the loading screen.
#[derive(Clone, Debug)]
pub struct Props {
    /// Current mediator/connection status, driving the phase + error display.
    pub status: MediatorStatus,
    /// Timed startup steps, in order (the last may still be in progress).
    pub steps: Vec<LoadingStep>,
    /// Rotating-tip index (advanced as startup steps stream).
    pub tip_index: usize,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            status: state.connection.status.clone(),
            steps: state.loading_steps.clone(),
            tip_index: state.tip_index,
        }
    }
}

/// The startup loading screen.
pub struct LoadingScreen {
    /// Action sender (used only to request exit on F10).
    pub action_tx: UnboundedSender<Action>,
    /// State-mapped props.
    pub props: Props,
}

impl Component for LoadingScreen {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        LoadingScreen {
            action_tx,
            props: Props::from(state),
        }
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        LoadingScreen {
            props: Props::from(state),
            ..self
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        // The loading screen is non-interactive: only quit is honoured.
        if let KeyCode::F(10) = key.code {
            let _ = self.action_tx.send(Action::Exit);
        }
    }
}

impl LoadingScreen {
    /// The human-readable phase line derived from the connection status.
    /// `Failed` is handled separately (rendered as a prominent error block).
    fn phase_line(status: &MediatorStatus) -> Line<'static> {
        let (text, color) = match status {
            MediatorStatus::Unknown => ("Starting…".to_string(), COLOR_DARK_GRAY),
            MediatorStatus::Initializing(step) => (step.clone(), COLOR_SOFT_PURPLE),
            MediatorStatus::Connecting => {
                ("Connecting to the mediator…".to_string(), COLOR_SOFT_PURPLE)
            }
            MediatorStatus::Connected => ("Connected".to_string(), COLOR_SUCCESS),
            MediatorStatus::NoActiveCommunity => ("Ready".to_string(), COLOR_SUCCESS),
            MediatorStatus::Failed(_) => {
                ("Startup failed".to_string(), COLOR_WARNING_ACCESSIBLE_RED)
            }
        };
        Line::styled(text, Style::new().fg(color).bold())
    }
}

impl ComponentRender<()> for LoadingScreen {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let area = frame.area();

        // Centre a fixed-width content column; cap height to what we render.
        let content_width = 64u16.min(area.width.saturating_sub(2));
        let [col] = Layout::horizontal([Length(content_width)])
            .flex(Flex::Center)
            .areas(area);

        let [banner_area, body_area, footer_area] =
            Layout::vertical([Length(BANNER.len() as u16 + 1), Min(0), Length(1)]).areas(col);

        // Banner.
        let banner: Vec<Line> = BANNER
            .iter()
            .map(|l| Line::styled(*l, Style::new().fg(COLOR_SOFT_PURPLE).bold()))
            .collect();
        frame.render_widget(Paragraph::new(banner).centered(), banner_area);

        let mut lines: Vec<Line> = Vec::new();

        // Phase line.
        lines.push(Self::phase_line(&self.props.status));
        lines.push(Line::default());

        // On failure, show the full error + a recovery suggestion. The error is
        // intentionally NOT truncated here — this screen is where the full
        // message lives (the main status bar truncates elsewhere).
        if let MediatorStatus::Failed(reason) = &self.props.status {
            lines.push(Line::styled(
                reason.clone(),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
            ));
            lines.push(Line::default());
            lines.push(Line::styled(
                "Check your network and that your VTA/mediator are reachable, \
                 then restart OpenVTC. Press F10 to quit.",
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
            ));
            lines.push(Line::default());
        }

        // Timed startup steps — each shows its start time and, once finished,
        // how long it took, so a slow step is obvious at a glance.
        if !self.props.steps.is_empty() {
            lines.push(Line::styled(
                "Startup",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            for step in &self.props.steps {
                let (marker, detail, marker_color) = match step.duration_ms {
                    Some(ms) => ("✓", format!("  ({ms} ms)"), COLOR_SUCCESS),
                    None => ("▸", "  …".to_string(), COLOR_SOFT_PURPLE),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("  {marker} "), Style::new().fg(marker_color)),
                    Span::styled(
                        format!("[{}] ", step.started),
                        Style::new().fg(COLOR_DARK_GRAY),
                    ),
                    Span::styled(step.label.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(detail, Style::new().fg(COLOR_DARK_GRAY)),
                ]));
            }
            lines.push(Line::default());
        }

        // Rotating tip.
        if !TIPS.is_empty() {
            let tip = TIPS[self.props.tip_index % TIPS.len()];
            lines.push(Line::styled(
                tip,
                Style::new().fg(COLOR_SOFT_PURPLE).italic(),
            ));
        }

        let body = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::new().padding(Padding::new(1, 1, 1, 0)));
        frame.render_widget(body, body_area);

        // Footer.
        let footer = Line::from(vec![
            Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);
        frame.render_widget(Paragraph::new(footer).centered(), footer_area);
    }
}
