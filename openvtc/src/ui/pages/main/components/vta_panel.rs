use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::{
    main_page::content::{ContentPanelState, VicLifecycle, VtaFocus, VtaState},
    state::ConnectionState,
};
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
        Line::from(" Context").fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];

    // Profile
    lines.push(Line::from(vec![
        Span::styled("  Profile:       ", label_style),
        Span::styled(state.profile.clone(), value_style),
    ]));

    // VTA Context name
    if let Some(ctx) = &state.context_name {
        lines.push(Line::from(vec![
            Span::styled("  VTA Context:   ", label_style),
            Span::styled(ctx.clone(), value_style),
        ]));
    }

    // Persona + Mediator DIDs are community-scoped: they only exist once a
    // community is joined (a persona is minted). Pre-community (State A) show a
    // readiness line instead of blank fields, so the panel confirms the account
    // is set up and ready to join.
    if state.persona_did.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  Status:        ", label_style),
            Span::styled(
                "Ready — join a community to create your persona",
                Style::new().fg(COLOR_SUCCESS),
            ),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("  Persona DID:   ", label_style),
            Span::styled(state.persona_did.clone(), value_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Mediator DID:  ", label_style),
            Span::styled(state.mediator_did.clone(), value_style),
        ]));
    }

    if !state.is_vta_managed {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  Key Backend:   ", label_style),
            Span::styled("BIP32 (local)", value_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Keys managed:  ", label_style),
            Span::styled(state.key_count.to_string(), value_style),
        ]));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(" VTA Service").fg(COLOR_SUCCESS).bold());
        lines.push(Line::from(""));

        lines.push(Line::from(vec![
            Span::styled("  VTA URL:       ", label_style),
            Span::styled(state.vta_url.clone(), value_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  VTA DID:       ", label_style),
            Span::styled(state.vta_did.clone(), value_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Credential:    ", label_style),
            Span::styled(state.credential_did.clone(), value_style),
        ]));

        lines.push(Line::from(""));
        lines.push(Line::from(" Keys").fg(COLOR_SUCCESS).bold());
        lines.push(Line::from(""));

        lines.push(Line::from(vec![
            Span::styled("  Total:         ", label_style),
            Span::styled(state.key_count.to_string(), value_style),
            Span::styled("  (", Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(
                format!("{} persona", state.persona_key_count),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Span::styled(", ", Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(
                format!("{} relationship", state.relationship_key_count),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Span::styled(")", Style::new().fg(COLOR_DARK_GRAY)),
        ]));
    }

    // Active DIDs
    if !state.active_dids.is_empty() {
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!(" Active DIDs ({})", state.active_dids.len()))
                .fg(COLOR_SUCCESS)
                .bold(),
        );
        lines.push(Line::from(""));

        for did_entry in state.active_dids.iter() {
            lines.push(Line::from(vec![
                Span::styled("  ● ", Style::new().fg(COLOR_SUCCESS)),
                Span::styled(
                    format!("{:<16}", did_entry.label),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
                Span::styled(did_entry.did.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            ]));
        }
    }

    // Context identities — every persona DID in this context, with its binding.
    // Orphans (no community) are flagged so they can be spotted and removed.
    if !state.context_dids.is_empty() {
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!(
                " Context Identities ({})",
                state.context_dids.len()
            ))
            .fg(COLOR_SUCCESS)
            .bold(),
        );
        lines.push(Line::from(""));

        for (i, d) in state.context_dids.iter().enumerate() {
            let is_selected = i == state.did_selected_index;
            let orphan = d.bound_communities == 0;
            let prefix = if is_selected { "▸ " } else { "  " };
            let marker = if orphan { "○ " } else { "● " };
            let marker_style = if orphan {
                Style::new().fg(COLOR_ORANGE)
            } else {
                Style::new().fg(COLOR_SUCCESS)
            };
            let did_style = if is_selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            lines.push(Line::from(vec![
                Span::styled(prefix, marker_style),
                Span::styled(marker, marker_style),
                Span::styled(d.did.clone(), did_style),
            ]));

            let name = if d.label.is_empty() {
                "persona".to_string()
            } else {
                d.label.clone()
            };
            let active = if d.is_active { "  ·  active" } else { "" };
            let binding = if orphan {
                "orphan — no community".to_string()
            } else {
                format!(
                    "{} communit{}",
                    d.bound_communities,
                    if d.bound_communities == 1 { "y" } else { "ies" }
                )
            };
            let binding_style = if orphan {
                Style::new().fg(COLOR_ORANGE)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("      {name}{active}  ·  "),
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Span::styled(binding, binding_style),
            ]));
        }

        // Confirmation prompt (a delete is armed) or the navigation/remove hint.
        lines.push(Line::from(""));
        if let Some(idx) = state.confirm_delete_did {
            let target = state
                .context_dids
                .get(idx)
                .map(|d| d.did.as_str())
                .unwrap_or("this identity");
            lines.push(
                Line::from(format!("Remove {target}?   y: confirm    n: cancel"))
                    .fg(COLOR_ORANGE)
                    .bold(),
            );
        } else {
            lines.push(
                Line::from("↑/↓ select   n: new persona   d: remove selected orphan")
                    .fg(COLOR_DARK_GRAY),
            );
        }
    } else {
        // No personas yet: still surface how to mint one.
        lines.push(Line::from(""));
        lines.push(
            Line::from("No persona DIDs yet.   n: create a new persona DID").fg(COLOR_DARK_GRAY),
        );
    }

    render_vics(state, &mut lines);

    lines
}

/// Render the "Invitation Credentials" (VIC) manager section: the held VICs with
/// their lifecycle state, the confirm gates, and the focus-aware key hints.
fn render_vics(state: &VtaState, lines: &mut Vec<Line<'static>>) {
    let focused = state.focus == VtaFocus::Vics;
    let header_style = if focused {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_DARK_GRAY).bold()
    };

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            format!(" Invitation Credentials ({})", state.vics.len()),
            header_style,
        ),
        Span::styled(
            if focused { "   ◀ focus" } else { "   [Tab] focus" },
            Style::new().fg(COLOR_DARK_GRAY),
        ),
    ]));
    lines.push(Line::from(""));

    if state.vics.is_empty() {
        lines.push(
            Line::from("No invitation credentials.   a: import a VIC   ·   i: show inactive")
                .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    for (i, v) in state.vics.iter().enumerate() {
        let selected = focused && i == state.vic_selected_index;
        let prefix = if selected { "▸ " } else { "  " };
        let (marker, marker_style) = match v.lifecycle {
            VicLifecycle::Active => ("● ", Style::new().fg(COLOR_SUCCESS)),
            VicLifecycle::Archived => ("○ ", Style::new().fg(COLOR_ORANGE)),
            VicLifecycle::Deleted => ("✗ ", Style::new().fg(COLOR_DARK_GRAY)),
        };
        let id_style = if selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, marker_style),
            Span::styled(marker, marker_style),
            Span::styled(v.id.clone(), id_style),
        ]));

        let issuer = if v.issuer.is_empty() {
            "issuer unknown".to_string()
        } else {
            v.issuer.clone()
        };
        let mut detail = format!("      {issuer}  ·  {}", v.status);
        if v.lifecycle != VicLifecycle::Active {
            detail.push_str(&format!("  ·  {}", v.lifecycle.tag()));
        }
        if !v.valid_until.is_empty() {
            detail.push_str(&format!("  ·  until {}", v.valid_until));
        }
        let detail_style = if v.lifecycle == VicLifecycle::Active {
            Style::new().fg(COLOR_DARK_GRAY)
        } else {
            Style::new().fg(COLOR_ORANGE)
        };
        lines.push(Line::from(Span::styled(detail, detail_style)));
    }

    lines.push(Line::from(""));
    if let Some(idx) = state.confirm_purge_vic {
        let target = state.vics.get(idx).map(|v| v.id.as_str()).unwrap_or("this VIC");
        lines.push(
            Line::from(format!("Purge {target} permanently?   y: confirm    n: cancel"))
                .fg(COLOR_ORANGE)
                .bold(),
        );
    } else if let Some(idx) = state.confirm_delete_vic {
        let target = state.vics.get(idx).map(|v| v.id.as_str()).unwrap_or("this VIC");
        lines.push(
            Line::from(format!("Delete {target}?   y: confirm    n: cancel"))
                .fg(COLOR_ORANGE)
                .bold(),
        );
    } else if focused {
        let sel = state.vics.get(state.vic_selected_index);
        let restore_verb = match sel.map(|v| v.lifecycle) {
            Some(VicLifecycle::Archived) => "u: unarchive",
            Some(VicLifecycle::Deleted) => "u: restore",
            _ => "r: archive",
        };
        lines.push(
            Line::from(format!(
                "↑/↓ select   a: import   {restore_verb}   d: delete   p: purge   i: inactive"
            ))
            .fg(COLOR_DARK_GRAY),
        );
    }
}
