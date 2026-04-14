use super::panel::Panel;
use crate::state_handler::{
    main_page::content::{ContentPanelState, VtaState},
    state::ConnectionState,
};
use openvtc::colors::{COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// VTA service information panel.
pub struct VtaPanel;

impl Panel for VtaPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.vta)
    }
}

/// Render the VTA service information panel.
pub fn render(state: &VtaState) -> Vec<Line<'static>> {
    let label_style = Style::new().fg(COLOR_TEXT_DEFAULT);
    let value_style = Style::new().fg(COLOR_SOFT_PURPLE);

    let mut lines = vec![
        Line::from(""),
        Line::from(" VTA Service").fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];

    if !state.is_vta_managed {
        lines.push(Line::from("  Not using VTA (BIP32 key backend)").fg(COLOR_DARK_GRAY));
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!("  Total keys managed: {}", state.key_count)).fg(COLOR_TEXT_DEFAULT),
        );
        return lines;
    }

    // VTA URL
    lines.push(Line::from(vec![
        Span::styled("  VTA URL:         ", label_style),
        Span::styled(state.vta_url.clone(), value_style),
    ]));

    // VTA DID
    lines.push(Line::from(vec![
        Span::styled("  VTA DID:         ", label_style),
        Span::styled(state.vta_did.clone(), value_style),
    ]));

    // Credential DID
    lines.push(Line::from(vec![
        Span::styled("  Credential DID:  ", label_style),
        Span::styled(state.credential_did.clone(), value_style),
    ]));

    lines.push(Line::from(""));

    // Key count
    lines.push(Line::from(vec![
        Span::styled("  Total keys managed: ", label_style),
        Span::styled(state.key_count.to_string(), value_style),
    ]));

    lines
}
