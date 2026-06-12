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

// ****************************************************************************
// MediatorAsk
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub enum MediatorAsk {
    #[default]
    Default,
    Custom,
}

impl MediatorAsk {
    fn index(&self) -> usize {
        match self {
            MediatorAsk::Default => 0,
            MediatorAsk::Custom => 1,
        }
    }

    fn from_index(i: usize) -> Self {
        if i == 0 {
            MediatorAsk::Default
        } else {
            MediatorAsk::Custom
        }
    }

    fn spec() -> ChoiceSpec {
        ChoiceSpec {
            // Title depends on the selected option: the custom path adds a step.
            title: [
                " Step 1/1: Configure messaging mediator ",
                " Step 1/2: Configure messaging mediator ",
            ],
            intro: vec![
                Line::styled(
                    "Your persona DID requires a mediator (relay service) for reliable DIDComm message delivery.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled(
                    "Use the default VTA mediator, or specify a custom mediator if you prefer a different one.",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::default(),
            ],
            options: [
                ChoiceOption {
                    label: "Use Default VTA Mediator (recommended)",
                    description: vec![Line::styled(
                        "    Uses the mediator configured by your VTA service.",
                        Style::new().fg(COLOR_DARK_GRAY),
                    )],
                    event: SetupEvent::UseDefaultMediator,
                },
                ChoiceOption {
                    label: "Use Custom Mediator (requires a mediator DID)",
                    description: vec![Line::styled(
                        "    Specify a different mediator DID to use instead of the VTA default.",
                        Style::new().fg(COLOR_DARK_GRAY),
                    )],
                    event: SetupEvent::UseCustomMediator,
                },
            ],
        }
    }

    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        let selected = state.mediator_ask.index();
        choice_page::handle_key_event(
            state,
            key,
            selected,
            |s, i| s.mediator_ask = MediatorAsk::from_index(i),
            Self::spec(),
        );
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        choice_page::render(&Self::spec(), self.index(), state, frame);
    }
}
