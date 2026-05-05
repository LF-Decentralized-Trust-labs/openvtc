use crate::colors::{
    COLOR_BORDER, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::main_page::menu::{MainMenu, MenuPanelState};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Stylize,
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph},
};
use strum::IntoEnumIterator;

// ****************************************************************************
// Render the Main Menu panel
// ****************************************************************************
impl MenuPanelState {
    /// Render the main menu based on current state
    pub fn render(&self, frame: &mut Frame, rect: Rect, inbox_task_count: usize) {
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
            let is_selected = item == self.selected_menu;
            let base_color = if is_selected {
                COLOR_SUCCESS
            } else {
                COLOR_TEXT_DEFAULT
            };

            if item == MainMenu::Inbox && inbox_task_count > 0 {
                lines.push(Line::from(vec![
                    Span::styled("* Inbox ", base_color),
                    Span::styled(
                        format!("({})", inbox_task_count),
                        COLOR_WARNING_ACCESSIBLE_RED,
                    ),
                ]));
            } else {
                lines
                    .push(Line::from(["* ".to_string(), item.to_string()].concat()).fg(base_color));
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
