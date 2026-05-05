//! Panel trait for self-contained main menu content panels.

use crate::state_handler::{main_page::content::ContentPanelState, state::ConnectionState};
use ratatui::text::Line;

/// Trait for a main-menu content panel.
///
/// Each panel handles its own key events and renders its own content.
/// Panels are stateless renderers that derive display from [`ContentPanelState`].
pub trait Panel {
    /// Render the panel content as a list of styled lines.
    fn render(&self, state: &ContentPanelState, connection: &ConnectionState)
    -> Vec<Line<'static>>;
}
