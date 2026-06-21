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
        state::{LoadingTask, MediatorStatus, State, StepStatus},
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
    /// Hierarchical, timed startup tasks (the last may still be in progress).
    pub tasks: Vec<LoadingTask>,
    /// Rotating-tip index (advanced as startup steps stream); also drives the
    /// running-step spinner frame.
    pub tip_index: usize,
    /// True once phase 1 finished — show the "Press Enter to continue" prompt.
    pub complete: bool,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            status: state.connection.status.clone(),
            tasks: state.loading.clone(),
            tip_index: state.tip_index,
            complete: state.loading_complete,
        }
    }
}

/// Human-friendly duration: milliseconds (2 dp) under a second, seconds (2 dp)
/// at or above — e.g. `3.42ms`, `842.10ms`, `5.83s`.
fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 {
        format!("{secs:.2}s")
    } else {
        format!("{:.2}ms", d.as_micros() as f64 / 1000.0)
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
        match key.code {
            KeyCode::F(10) => {
                let _ = self.action_tx.send(Action::Exit);
            }
            // Once phase 1 has finished, Enter dismisses the loading screen and
            // reveals the main page (phase-2 connections already run in the bg).
            KeyCode::Enter if self.props.complete => {
                let _ = self.action_tx.send(Action::DismissLoading);
            }
            _ => {}
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

    /// Per-status leading icon + colour. A `Running` step gets a simple
    /// frame-based spinner driven by `tick` (the tip index, bumped each step).
    fn status_icon(status: StepStatus, tick: usize) -> (String, ratatui::style::Color) {
        const SPINNER: &[char] = &['▸', '▹', '▸', '▹'];
        match status {
            StepStatus::Queued => ("◦".to_string(), COLOR_DARK_GRAY),
            StepStatus::Running => (SPINNER[tick % SPINNER.len()].to_string(), COLOR_SOFT_PURPLE),
            StepStatus::Done => ("✓".to_string(), COLOR_SUCCESS),
            StepStatus::Failed => ("✗".to_string(), COLOR_WARNING_ACCESSIBLE_RED),
        }
    }

    /// Column the timing annotation starts at, so times line up neatly.
    const TIME_COL: usize = 34;

    /// A right-aligned `(time)` annotation, padded so it lands in [`TIME_COL`].
    /// `prefix_len` is the visible width already consumed on the line.
    fn time_span(
        duration: Option<std::time::Duration>,
        prefix_len: usize,
    ) -> Option<Span<'static>> {
        let d = duration?;
        let text = format!("({})", format_duration(d));
        let pad = Self::TIME_COL.saturating_sub(prefix_len).max(1);
        Some(Span::styled(
            format!("{}{text}", " ".repeat(pad)),
            Style::new().fg(COLOR_DARK_GRAY),
        ))
    }

    /// Render a major task line: bold, leading status icon, combined time once
    /// the major is Done.
    fn major_line(task: &LoadingTask, tick: usize) -> Line<'static> {
        let (icon, icon_color) = Self::status_icon(task.status, tick);
        let label_color = match task.status {
            StepStatus::Failed => COLOR_WARNING_ACCESSIBLE_RED,
            StepStatus::Queued => COLOR_DARK_GRAY,
            _ => COLOR_TEXT_DEFAULT,
        };
        let clock = task.started.as_deref().unwrap_or("--:--:--");
        let time_prefix = format!("[{clock}] ");
        let mut spans = vec![
            Span::styled(format!("  {icon} "), Style::new().fg(icon_color)),
            Span::styled(time_prefix.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(task.label.clone(), Style::new().fg(label_color).bold()),
        ];
        // prefix = "  " + icon(1) + " " + "[HH:MM:SS] " + label
        let prefix_len = 4 + time_prefix.chars().count() + task.label.chars().count();
        if let Some(t) = Self::time_span(task.duration, prefix_len) {
            spans.push(t);
        }
        Line::from(spans)
    }

    /// Render a sub-step line: indented under its major, dimmer, prefixed with
    /// its start time and annotated with its own per-step time once Done.
    fn sub_line(step: &crate::state_handler::state::LoadingStep, tick: usize) -> Line<'static> {
        let (icon, icon_color) = Self::status_icon(step.status, tick);
        let label_color = match step.status {
            StepStatus::Failed => COLOR_WARNING_ACCESSIBLE_RED,
            StepStatus::Running => COLOR_TEXT_DEFAULT,
            _ => COLOR_DARK_GRAY,
        };
        let clock = step.started.as_deref().unwrap_or("--:--:--");
        let time_prefix = format!("[{clock}] ");
        let mut spans = vec![
            Span::styled(format!("      {icon} "), Style::new().fg(icon_color)),
            Span::styled(time_prefix.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(step.label.clone(), Style::new().fg(label_color)),
        ];
        // prefix = 6 spaces + icon(1) + " " + "[HH:MM:SS] " + label
        let prefix_len = 8 + time_prefix.chars().count() + step.label.chars().count();
        if let Some(t) = Self::time_span(step.duration, prefix_len) {
            spans.push(t);
        }
        Line::from(spans)
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

        // +2: one line for the version under the logo, one as a spacer.
        let [banner_area, body_area, footer_area] =
            Layout::vertical([Length(BANNER.len() as u16 + 2), Min(0), Length(1)]).areas(col);

        // Banner, with the build version under the logo.
        let mut banner: Vec<Line> = BANNER
            .iter()
            .map(|l| Line::styled(*l, Style::new().fg(COLOR_SOFT_PURPLE).bold()))
            .collect();
        banner.push(Line::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::new().fg(COLOR_DARK_GRAY),
        ));
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

        // Hierarchical startup tasks — majors in bold with their combined time,
        // sub-steps indented and dimmer with their own time, so a slow task (and
        // which sub-step caused it) is obvious at a glance.
        if !self.props.tasks.is_empty() {
            lines.push(Line::styled(
                "Startup",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            for task in &self.props.tasks {
                lines.push(Self::major_line(task, self.props.tip_index));
                for step in &task.children {
                    lines.push(Self::sub_line(step, self.props.tip_index));
                }
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

        // Once phase 1 is done, prompt to continue (phase-2 connections are
        // already running in the background).
        if self.props.complete {
            lines.push(Line::default());
            lines.push(Line::styled(
                "Press [ENTER] to continue — connecting in the background",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
        }

        let body = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::new().padding(Padding::new(1, 1, 1, 0)));
        frame.render_widget(body, body_area);

        // Footer.
        let footer = if self.props.complete {
            Line::from(vec![
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" continue   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ])
        } else {
            Line::from(vec![
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ])
        };
        frame.render_widget(Paragraph::new(footer).centered(), footer_area);
    }
}
