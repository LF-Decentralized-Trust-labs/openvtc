use std::fmt::Display;

use strum_macros::EnumIter;

/// Holds all state related info for the main page
#[derive(Clone, Debug)]
pub struct MenuPanelState {
    /// Selected?
    pub selected: bool,

    /// What is the selected menu item?
    pub selected_menu: MainMenu,
}

impl Default for MenuPanelState {
    fn default() -> Self {
        MenuPanelState {
            selected: true,
            selected_menu: MainMenu::default(),
        }
    }
}

#[derive(Default, Debug, Clone, EnumIter, PartialEq, Eq)]
pub enum MainMenu {
    /// Communities overview — the account hub and post-bootstrap landing (R-C).
    #[default]
    Communities,
    Inbox,
    Relationships,
    Credentials,
    Settings,
    Vta,
    /// Action item (not a panel): opens the create-persona overlay on Enter,
    /// mirroring how `Quit` triggers an action rather than switching panels.
    CreatePersona,
    Logs,
    Help,
    Quit,
}

impl Display for MainMenu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainMenu::Communities => write!(f, "Communities"),
            MainMenu::Inbox => write!(f, "Inbox"),
            MainMenu::Relationships => write!(f, "My Relationships"),
            MainMenu::Credentials => write!(f, "My Credentials"),
            MainMenu::Settings => write!(f, "Settings"),
            MainMenu::Vta => write!(f, "VTA Service"),
            MainMenu::CreatePersona => write!(f, "Create Persona DID"),
            MainMenu::Logs => write!(f, "Logs"),
            MainMenu::Help => write!(f, "Help / Status"),
            MainMenu::Quit => write!(f, "Quit"),
        }
    }
}

impl MainMenu {
    /// Returns the previous MainMenu item
    pub fn prev(&self) -> MainMenu {
        match self {
            MainMenu::Communities => MainMenu::Quit,
            MainMenu::Inbox => MainMenu::Communities,
            MainMenu::Relationships => MainMenu::Inbox,
            MainMenu::Credentials => MainMenu::Relationships,
            MainMenu::Settings => MainMenu::Credentials,
            MainMenu::Vta => MainMenu::Settings,
            MainMenu::CreatePersona => MainMenu::Vta,
            MainMenu::Logs => MainMenu::CreatePersona,
            MainMenu::Help => MainMenu::Logs,
            MainMenu::Quit => MainMenu::Help,
        }
    }

    /// Returns the next MainMenu item
    pub fn next(&self) -> MainMenu {
        match self {
            MainMenu::Communities => MainMenu::Inbox,
            MainMenu::Inbox => MainMenu::Relationships,
            MainMenu::Relationships => MainMenu::Credentials,
            MainMenu::Credentials => MainMenu::Settings,
            MainMenu::Settings => MainMenu::Vta,
            MainMenu::Vta => MainMenu::CreatePersona,
            MainMenu::CreatePersona => MainMenu::Logs,
            MainMenu::Logs => MainMenu::Help,
            MainMenu::Help => MainMenu::Quit,
            MainMenu::Quit => MainMenu::Communities,
        }
    }
}
