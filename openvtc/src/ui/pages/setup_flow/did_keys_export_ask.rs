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
// DIDKeysExportAsk
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub enum DIDKeysExportAsk {
    #[default]
    Skip,
    Export,
}

impl DIDKeysExportAsk {
    fn index(&self) -> usize {
        match self {
            DIDKeysExportAsk::Skip => 0,
            DIDKeysExportAsk::Export => 1,
        }
    }

    fn from_index(i: usize) -> Self {
        if i == 0 {
            DIDKeysExportAsk::Skip
        } else {
            DIDKeysExportAsk::Export
        }
    }

    fn spec() -> ChoiceSpec {
        ChoiceSpec {
            title: [
                " Step 4/4: Export private DID keys ",
                " Step 4/4: Export private DID keys ",
            ],
            intro: vec![
                Line::styled(
                    "You may want to export the private key material used by your profile so you can reuse the same keys in other applications or with other DIDs.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled(
                    "Would you like to export your private DID keys now?",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::default(),
            ],
            options: [
                ChoiceOption {
                    label: "Skip for now (recommended)",
                    description: vec![Line::styled(
                        "    You can continue setting up your profile and export them later from within OpenVTC if needed.",
                        Style::new().fg(COLOR_DARK_GRAY),
                    )],
                    event: SetupEvent::SkipExport,
                },
                ChoiceOption {
                    label: "Export private DID keys",
                    description: vec![Line::styled(
                        "    Private keys will be exported in a secure, text-based PGP-armoured format suitable for secure storage and transfer.",
                        Style::new().fg(COLOR_DARK_GRAY),
                    )],
                    event: SetupEvent::StartExport,
                },
            ],
        }
    }

    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        let selected = state.did_keys_export_ask.index();
        choice_page::handle_key_event(
            state,
            key,
            selected,
            |s, i| s.did_keys_export_ask = DIDKeysExportAsk::from_index(i),
            Self::spec(),
        );
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        choice_page::render(&Self::spec(), self.index(), state, frame);
    }
}
