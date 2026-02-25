use crate::state_handler::main_page::menu::{MainMenu, MenuPanelState};
use openvtc::colors::{COLOR_BORDER, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Stylize,
    symbols::merge::MergeStrategy,
    text::Line,
    widgets::{Block, BorderType, Paragraph},
};
use strum::IntoEnumIterator;

// ****************************************************************************
// Render the Main Menu panel
// ****************************************************************************
impl MenuPanelState {
    /// Render the main menu based on current state
    pub fn render(&self, frame: &mut Frame, rect: Rect) {
        // The surrounding block for the menu

        let menu_block = if self.selected {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .border_type(BorderType::Double)
                .fg(COLOR_SUCCESS)
                .title("Menu")
        } else {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .fg(COLOR_BORDER)
                .title("Menu")
        };

        let mut lines = Vec::new();
        for item in MainMenu::iter() {
            if item == self.selected_menu {
                // make it colorful
                lines.push(
                    Line::from(["• ".to_string(), item.to_string()].concat()).fg(COLOR_SUCCESS),
                );
            } else {
                lines.push(
                    Line::from(["• ".to_string(), item.to_string()].concat())
                        .fg(COLOR_TEXT_DEFAULT),
                );
            }
        }

        frame.render_widget(
            Paragraph::new(lines)
                .dark_gray()
                .alignment(Alignment::Left)
                .block(menu_block),
            rect,
        );
    }
}
