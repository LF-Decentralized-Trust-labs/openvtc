use crate::state_handler::{
    main_page::{
        content::ContentPanelState,
        menu::{MainMenu, MenuPanelState},
    },
    state::ConnectionState,
};
use openvtc::colors::{
    COLOR_BORDER, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Stylize,
    symbols::merge::MergeStrategy,
    text::Line,
    widgets::{Block, BorderType, Paragraph},
};

use super::{credentials_panel, inbox_panel, relationships_panel, settings_panel};

// ****************************************************************************
// Render the Content panel
// ****************************************************************************
impl ContentPanelState {
    /// Render the content panel based on current state
    pub fn render(
        &self,
        frame: &mut Frame,
        rect: Rect,
        menu: &MenuPanelState,
        connection: &ConnectionState,
    ) {
        let content_block = if self.selected {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .border_type(BorderType::Double)
                .fg(COLOR_SUCCESS)
                .title("Content")
        } else {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .fg(COLOR_BORDER)
                .title("Content")
        };

        let lines = match menu.selected_menu {
            MainMenu::Inbox => inbox_panel::render(&self.inbox, connection),
            MainMenu::Relationships => relationships_panel::render(&self.relationships),
            MainMenu::Credentials => {
                credentials_panel::render(&self.credentials, &self.relationships)
            }
            MainMenu::Settings => settings_panel::render(&self.settings),
            MainMenu::Help => {
                vec![
                    Line::from(""),
                    Line::from("Press Up/Down to navigate").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press Enter to select / open").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press Tab, Left, or Right to switch panels").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press Esc to go back").fg(COLOR_TEXT_DEFAULT),
                    Line::from("Press F10 to quit from anywhere").fg(COLOR_TEXT_DEFAULT),
                ]
            }
            MainMenu::Quit => {
                vec![
                    Line::from(""),
                    Line::from("Press <Enter> to quit the application")
                        .fg(COLOR_WARNING_ACCESSIBLE_RED),
                ]
            }
        };

        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Left)
                .block(content_block),
            rect,
        );
    }
}
