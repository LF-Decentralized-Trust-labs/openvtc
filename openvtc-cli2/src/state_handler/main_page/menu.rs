use std::fmt::Display;

use strum::EnumIter;

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
    #[default]
    Inbox,
    Relationships,
    Credentials,
    Settings,
    Help,
    Quit,
}

impl Display for MainMenu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainMenu::Inbox => write!(f, "Inbox"),
            MainMenu::Relationships => write!(f, "My Relationships"),
            MainMenu::Credentials => write!(f, "My Credentials"),
            MainMenu::Settings => write!(f, "Settings"),
            MainMenu::Help => write!(f, "Help"),
            MainMenu::Quit => write!(f, "Quit"),
        }
    }
}

impl MainMenu {
    /// Returns the previous MainMenu item
    pub fn prev(&self) -> MainMenu {
        match self {
            MainMenu::Inbox => MainMenu::Quit,
            MainMenu::Relationships => MainMenu::Inbox,
            MainMenu::Credentials => MainMenu::Relationships,
            MainMenu::Settings => MainMenu::Credentials,
            MainMenu::Help => MainMenu::Settings,
            MainMenu::Quit => MainMenu::Help,
        }
    }

    /// Returns the next MainMenu item
    pub fn next(&self) -> MainMenu {
        match self {
            MainMenu::Inbox => MainMenu::Relationships,
            MainMenu::Relationships => MainMenu::Credentials,
            MainMenu::Credentials => MainMenu::Settings,
            MainMenu::Settings => MainMenu::Help,
            MainMenu::Help => MainMenu::Quit,
            MainMenu::Quit => MainMenu::Inbox,
        }
    }
}
