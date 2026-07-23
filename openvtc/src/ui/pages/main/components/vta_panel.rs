use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::{
    main_page::content::{ContentPanelState, VicLifecycle, VtaFocus, VtaState},
    state::ConnectionState,
};
use openvtc_core::display::{display_identifier, truncate_did_centered};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Width the DID lists render an identifier at. The panel has never truncated
/// these, so this only bounds an agent name shown in a DID's place.
const ID_WIDTH: usize = 256;

/// Width the delete-confirm prompt renders the target DID at. The prompt carries
/// a name *and* the DID plus the y/n hint, so the DID is centre-truncated here
/// (both ends stay visible) to keep the line on one row.
const CONFIRM_DID_WIDTH: usize = 48;

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
        if let Some(agent_name) = &state.persona_agent_name {
            lines.push(Line::from(vec![
                Span::styled("  Agent name:    ", label_style),
                Span::styled(agent_name.clone(), value_style),
            ]));
        }
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
            // `label` is the DID's *role* ("Persona", "R-DID (…)"), not a name
            // for it — the verified agent name (when known) replaces the DID
            // beside it.
            lines.push(Line::from(vec![
                Span::styled("  ● ", Style::new().fg(COLOR_SUCCESS)),
                Span::styled(
                    format!("{:<16}", did_entry.label),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
                Span::styled(
                    display_identifier(did_entry.agent_name.as_deref(), &did_entry.did, ID_WIDTH)
                        .into_owned(),
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
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
                Span::styled(
                    display_identifier(d.agent_name.as_deref(), &d.did, ID_WIDTH).into_owned(),
                    did_style,
                ),
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
            // Keep *both* the name and the DID. The row the operator selected
            // shows the name, so a DID-only prompt names something they never
            // saw; but a destructive confirm must stay unambiguous, so the DID
            // is not dropped either — it is centre-truncated to keep the line
            // readable while both ends stay checkable.
            let target = match state.context_dids.get(idx) {
                Some(d) => {
                    let did = truncate_did_centered(&d.did, CONFIRM_DID_WIDTH);
                    match d.agent_name.as_deref() {
                        Some(name) => format!("{name} ({did})"),
                        None => did.into_owned(),
                    }
                }
                None => "this identity".to_string(),
            };
            lines.push(
                Line::from(format!("Remove {target}?   y: confirm    n: cancel"))
                    .fg(COLOR_ORANGE)
                    .bold(),
            );
        } else {
            lines.push(
                Line::from(
                    "↑/↓ select   n: new persona   g: agent names   d: remove selected orphan",
                )
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
            if focused {
                "   ◀ focus"
            } else {
                "   [Tab] focus"
            },
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

        // The issuer is a community VTC DID, which the agent-name sweep already
        // targets — so a verified name is usually available and shown in its
        // place. No name (or a cached negative) keeps the DID.
        let issuer = if v.issuer.is_empty() {
            "issuer unknown".to_string()
        } else {
            display_identifier(v.issuer_agent_name.as_deref(), &v.issuer, ID_WIDTH).into_owned()
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
        let target = state
            .vics
            .get(idx)
            .map(|v| v.id.as_str())
            .unwrap_or("this VIC");
        lines.push(
            Line::from(format!(
                "Purge {target} permanently?   y: confirm    n: cancel"
            ))
            .fg(COLOR_ORANGE)
            .bold(),
        );
    } else if let Some(idx) = state.confirm_delete_vic {
        let target = state
            .vics
            .get(idx)
            .map(|v| v.id.as_str())
            .unwrap_or("this VIC");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{ManagedDid, VicSummary};

    const PERSONA_DID: &str = "did:webvh:QmScidAliceAAAAAAAAAAAAAAAAAAAA:example.com:alice";
    const VTC_DID: &str = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";

    /// Flatten the rendered lines to plain text, one entry per line.
    fn text(lines: &[Line<'static>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    fn managed_did(agent_name: Option<&str>) -> ManagedDid {
        ManagedDid {
            did: PERSONA_DID.to_string(),
            agent_name: agent_name.map(str::to_owned),
            label: "Work me".to_string(),
            bound_communities: 0,
            is_active: false,
        }
    }

    fn vic(issuer_agent_name: Option<&str>) -> VicSummary {
        VicSummary {
            id: "urn:vic:1".to_string(),
            issuer: VTC_DID.to_string(),
            issuer_agent_name: issuer_agent_name.map(str::to_owned),
            status: "valid".to_string(),
            lifecycle: VicLifecycle::Active,
            valid_until: String::new(),
        }
    }

    fn state_with(dids: Vec<ManagedDid>, vics: Vec<VicSummary>) -> VtaState {
        VtaState {
            context_dids: dids.into(),
            vics: vics.into(),
            ..VtaState::default()
        }
    }

    // --- VIC issuer ---------------------------------------------------------

    #[test]
    fn vic_row_shows_the_issuers_verified_agent_name() {
        let out = text(&render(&state_with(
            vec![],
            vec![vic(Some("example.com/@acme"))],
        )));
        assert!(
            out.iter().any(|l| l.contains("example.com/@acme")),
            "issuer name is shown: {out:?}"
        );
        assert!(
            !out.iter().any(|l| l.contains(VTC_DID)),
            "the DID is replaced by the name: {out:?}"
        );
    }

    /// A cached negative lookup arrives as `None`, so the row keeps the DID.
    #[test]
    fn vic_row_without_a_name_keeps_the_issuer_did() {
        let out = text(&render(&state_with(vec![], vec![vic(None)])));
        assert!(
            out.iter().any(|l| l.contains(VTC_DID)),
            "issuer DID is shown: {out:?}"
        );
    }

    // --- delete-confirm prompt (KEEP-BOTH) ----------------------------------

    /// The destructive confirm names what the operator selected *and* keeps the
    /// DID, so it is both recognisable and unambiguous.
    #[test]
    fn delete_confirm_keeps_both_the_name_and_the_did() {
        let mut state = state_with(vec![managed_did(Some("example.com/@alice"))], vec![]);
        state.confirm_delete_did = Some(0);
        let out = text(&render(&state));

        let prompt = out
            .iter()
            .find(|l| l.starts_with("Remove "))
            .expect("confirm prompt rendered");
        assert!(prompt.contains("example.com/@alice"), "{prompt}");
        // The DID is centre-truncated, so both ends must still be checkable.
        assert!(prompt.contains("did:webvh:QmScidAlice"), "{prompt}");
        assert!(prompt.contains("example.com:alice"), "{prompt}");
        assert!(prompt.contains("y: confirm"), "{prompt}");
    }

    /// With no verified name (uncached or a cached negative) the prompt falls
    /// back to the DID alone — never to an empty or name-less "this identity".
    #[test]
    fn delete_confirm_without_a_name_shows_the_did() {
        let mut state = state_with(vec![managed_did(None)], vec![]);
        state.confirm_delete_did = Some(0);
        let out = text(&render(&state));

        let prompt = out
            .iter()
            .find(|l| l.starts_with("Remove "))
            .expect("confirm prompt rendered");
        assert!(prompt.contains("did:webvh:QmScidAlice"), "{prompt}");
        assert!(prompt.contains("example.com:alice"), "{prompt}");
        assert!(
            !prompt.contains('('),
            "no empty name parenthetical: {prompt}"
        );
    }
}
