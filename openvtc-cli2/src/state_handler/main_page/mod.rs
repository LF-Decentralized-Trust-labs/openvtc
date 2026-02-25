use std::sync::Arc;

use openvtc::config::Config;

use crate::state_handler::main_page::{content::ContentPanelState, menu::MenuPanelState};

pub mod content;
pub mod menu;

/// Holds all state related info for the main page
#[derive(Clone, Debug, Default)]
pub struct MainPageState {
    /// State related to the menu panel
    pub menu_panel: MenuPanelState,

    /// State related to the content panel
    pub content_panel: ContentPanelState,

    pub config: MainMenuConfigState,
}

/// Contains config information that is shown in the main menu
#[derive(Clone, Debug, Default)]
pub struct MainMenuConfigState {
    pub name: String,
    pub did: Arc<String>,
}

impl From<&Box<Config>> for MainMenuConfigState {
    fn from(config: &Box<Config>) -> Self {
        MainMenuConfigState {
            name: config.public.friendly_name.clone(),
            did: config.public.persona_did.clone(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub enum MainPanel {
    #[default]
    MainMenu,
    ContentPanel,
}

impl MainPanel {
    /// Switches to the next panel when pressing <TAB>
    pub fn switch(&self) -> Self {
        match self {
            MainPanel::MainMenu => MainPanel::ContentPanel,
            MainPanel::ContentPanel => MainPanel::MainMenu,
        }
    }
}
