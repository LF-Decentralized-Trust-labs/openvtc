use super::panel::Panel;
use super::status::push_status;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::{
    main_page::content::{ContentPanelState, VicLifecycle, VtaFocus, VtaState, VtaTransport},
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
        render(&state.vta, state.selected)
    }
}

/// Render the VTA service information panel.
///
/// `panel_focused` is whether the *content panel* holds keyboard focus (as
/// opposed to the menu on the left). Both lists here draw a focus affordance,
/// and without this they drew it from `state.focus` alone — so a panel the
/// keyboard could not reach still announced "◀ focus" and advertised its verbs.
/// Every one of those keys is dropped in that state (content keys are only
/// routed when the content panel is selected), which is exactly the "the key
/// does nothing" report.
pub fn render(state: &VtaState, panel_focused: bool) -> Vec<Line<'static>> {
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
        // One row per identity, not two. The name is the value and the DID is
        // dimmed detail beneath it — the same shape the identity lists below
        // already use, instead of an "Agent name" row and a "Persona DID" row
        // naming the same party twice. With no verified name the DID *is* the
        // value and there is no second line.
        push_identity(
            &mut lines,
            "  Persona:       ",
            state.persona_agent_name.as_deref(),
            &state.persona_did,
        );
        // The mediator is a *transport* fact, not an identity one, so on a
        // VTA-managed account it lives under `Transport:` below rather than
        // being named here as well. A local-key account has no VTA Service
        // section to host it, so it stays here.
        if !state.is_vta_managed {
            push_identity(
                &mut lines,
                "  Mediator:      ",
                state.mediator_agent_name.as_deref(),
                &state.mediator_did,
            );
        }
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

        push_identity(
            &mut lines,
            "  VTA:           ",
            state.vta_agent_name.as_deref(),
            &state.vta_did,
        );
        render_transports(state, &mut lines);
        lines.push(Line::from(vec![
            // "Credential" said nothing about what the credential is *for*. It
            // is the DID this client authenticates to the VTA as; a `did:key`
            // can never carry an agent name, so it stays a (truncated) DID.
            Span::styled("  Authenticated: ", label_style),
            Span::styled(
                truncate_did_centered(&state.credential_did, CONFIRM_DID_WIDTH).into_owned(),
                value_style,
            ),
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

    // Active DIDs — the persona plus one relationship pseudonym (R-DID) per
    // relationship. Suppressed when it holds nothing but the persona: that row
    // duplicates the one already marked `active` in Context Identities below,
    // and a section that restates the row under it is noise, not structure.
    let active_dids_worth_showing = state
        .active_dids
        .iter()
        .any(|d| d.label.starts_with("R-DID"));
    if active_dids_worth_showing {
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
        // Same focus affordance the VIC section carries. Without it this list
        // showed a `▸` selection cursor and a key-hint row with no indication
        // that it was the focused list — the two lists looked equally live.
        let focused = panel_focused && state.focus == VtaFocus::Dids;
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                format!(" Context Identities ({})", state.context_dids.len()),
                if focused {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_DARK_GRAY).bold()
                },
            ),
            Span::styled(
                focus_hint(focused, panel_focused),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
        ]));
        lines.push(Line::from(""));

        for (i, d) in state.context_dids.iter().enumerate() {
            // Only the focused list shows a selection cursor, so `↑/↓` never
            // appears to be driving two lists at once (matches the VIC rows).
            let is_selected = focused && i == state.did_selected_index;
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

        // Confirmation prompt (a delete is armed) or, when focused, the
        // navigation/remove hint. The spacer goes with them — an unfocused list
        // ends at its last row rather than trailing a blank.
        if state.confirm_delete_did.is_some() || focused {
            lines.push(Line::from(""));
        }
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
        } else if focused {
            // Same verb order as the VIC hints: navigation, then create, then
            // the rest, each `key: verb` with the same separator.
            lines.push(
                Line::from("↑/↓ select   n: new persona   g: agent names   d: remove orphan")
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

    render_vics(state, panel_focused, &mut lines);

    lines
}

/// The focus affordance for one of the two manageable lists.
///
/// Three states, not two: the list has the keyboard, the *other* list has it
/// (Tab switches between them), or the content panel is not focused at all — in
/// which case Tab does not reach these lists and the operator needs the panel
/// first. Collapsing the last two into "[Tab] focus" pointed at the wrong key.
fn focus_hint(focused: bool, panel_focused: bool) -> &'static str {
    match (focused, panel_focused) {
        (true, _) => "   ◀ focus",
        (false, true) => "   [Tab] focus",
        (false, false) => "   [→] focus the panel",
    }
}

/// Push a labelled identity as one row: the verified agent name as the value,
/// with the DID as a dimmed second line. With no verified name the DID is the
/// value and only one line is pushed — a party is never named twice.
fn push_identity(
    lines: &mut Vec<Line<'static>>,
    label: &'static str,
    agent_name: Option<&str>,
    did: &str,
) {
    let label_style = Style::new().fg(COLOR_TEXT_DEFAULT);
    let value_style = Style::new().fg(COLOR_SOFT_PURPLE);
    match agent_name {
        Some(name) => {
            lines.push(Line::from(vec![
                Span::styled(label, label_style),
                Span::styled(name.to_string(), value_style),
            ]));
            lines.push(Line::from(Span::styled(
                format!("{:width$}{did}", "", width = label.len()),
                Style::new().fg(COLOR_DARK_GRAY),
            )));
        }
        None => lines.push(Line::from(vec![
            Span::styled(label, label_style),
            Span::styled(did.to_string(), value_style),
        ])),
    }
}

/// Render the transport block: which transport this process is on, what the VTA
/// advertises, and the endpoint behind each.
///
/// This replaced a bare `VTA URL:` row. The URL alone was misleading — it stays
/// populated on the DIDComm path (where it is only the REST fallback), so it
/// read as "we talk to the VTA over HTTPS" even when every call went over
/// DIDComm. A probe that has not landed says "checking…", and a probe that
/// *failed* says so explicitly, so an unreachable VTA is never rendered as one
/// that advertises nothing (VTI R6.4).
fn render_transports(state: &VtaState, lines: &mut Vec<Line<'static>>) {
    let label_style = Style::new().fg(COLOR_TEXT_DEFAULT);
    let dim = Style::new().fg(COLOR_DARK_GRAY);
    let t = &state.transports;

    let mut spans = vec![
        Span::styled("  Transport:     ", label_style),
        Span::styled(t.in_use.label().to_string(), Style::new().fg(COLOR_SUCCESS)),
        Span::styled("  (in use)", dim),
    ];
    match &t.advertised {
        None => spans.push(Span::styled("   ·   checking what else is offered…", dim)),
        Some(a) if a.error.is_some() => {
            spans.push(Span::styled("   ·   other transports unknown", {
                Style::new().fg(COLOR_ORANGE)
            }));
        }
        Some(a) => {
            // Only mention the transports we are *not* on; the one in use is
            // already the headline. This used to be a single `Option<&str>`
            // computed as REST-or-nothing, so a VTA advertising `#tsp` and no
            // `#vta-rest` fell through to "only transport offered" — false
            // about a VTA that offers two.
            let mut others = Vec::new();

            let switchable = match t.in_use {
                VtaTransport::DidComm => a.rest_url.is_some().then_some("REST"),
                VtaTransport::Rest => a.mediator_did.is_some().then_some("DIDComm"),
            };
            if let Some(name) = switchable {
                others.push(Span::styled(format!("   ·   {name} also available"), dim));
            }

            // TSP is reported separately from the transports we could switch to,
            // because it is not one: it carries the **trust-task surface only**,
            // as a leg of the DIDComm session rather than an alternative to it.
            // Key management, DID minting and context listing stay on DIDComm
            // unconditionally — the VTA has no TSP dispatcher behind them. So
            // "also available" would be wrong in the other direction now: TSP is
            // in use for part of the traffic, not available to switch to.
            if a.tsp_mediator_did.is_some() {
                others.push(Span::styled("   ·   TSP for trust tasks", dim));
            }

            if others.is_empty() {
                spans.push(Span::styled("   ·   only transport offered", dim));
            } else {
                spans.extend(others);
            }
        }
    }
    lines.push(Line::from(spans));

    // Endpoint detail, indented under the transport it belongs to.
    if !state.mediator_did.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("    via mediator  ", dim),
            Span::styled(
                display_identifier(
                    state.mediator_agent_name.as_deref(),
                    &state.mediator_did,
                    ID_WIDTH,
                )
                .into_owned(),
                dim,
            ),
        ]));
    }
    if !t.rest_url.is_empty() {
        // `t.rest_url` is *stored config*, not something the document
        // advertises, so a bare "REST endpoint" line could sit directly under a
        // transport line reporting that the VTA offers no REST — two true facts
        // reading as a contradiction. Label it when we positively know the
        // document carries no `#vta-rest`; stay silent when the probe has not
        // landed or failed, where "not advertised" is not something we know.
        let known_absent = t
            .advertised
            .as_ref()
            .is_some_and(|a| a.error.is_none() && a.rest_url.is_none());
        let mut spans = vec![
            Span::styled("    REST endpoint ", dim),
            Span::styled(t.rest_url.clone(), dim),
        ];
        if known_absent {
            spans.push(Span::styled("  (configured; not advertised)", dim));
        }
        lines.push(Line::from(spans));
    }
    if let Some(err) = t.advertised.as_ref().and_then(|a| a.error.as_deref()) {
        push_status(
            lines,
            &format!("Could not read the VTA's advertised transports: {err}"),
            "    ",
        );
    }
}

/// Render the "Invitation Credentials" (VIC) manager section: the held VICs with
/// their lifecycle state, the confirm gates, and the focus-aware key hints.
fn render_vics(state: &VtaState, panel_focused: bool, lines: &mut Vec<Line<'static>>) {
    let focused = panel_focused && state.focus == VtaFocus::Vics;
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
            focus_hint(focused, panel_focused),
            Style::new().fg(COLOR_DARK_GRAY),
        ),
        // The vault query runs off the loop now, so the list can be visibly
        // mid-load. Saying so is the difference between "you hold no VICs" and
        // "we haven't heard back yet" — the panel used to render both as the
        // empty state, and the load was only ever noticed as a frozen Tab.
        Span::styled(
            if state.vic_loading {
                "   loading…"
            } else {
                ""
            },
            Style::new().fg(COLOR_DARK_GRAY),
        ),
    ]));
    lines.push(Line::from(""));

    if state.vics.is_empty() {
        lines.push(
            Line::from(if state.vic_loading {
                "Reading the credential vault…"
            } else {
                "No invitation credentials.   a: import a VIC   ·   i: show inactive"
            })
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
    use crate::state_handler::main_page::content::{
        ActiveDid, AdvertisedTransports, ManagedDid, VicSummary, VtaTransports,
    };

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

    // --- transports ---------------------------------------------------------

    const VTA_DID: &str = "did:webvh:QmScidVtaCCCCCCCCCCCCCCCCCCCCCC:example.com:vta";
    const MEDIATOR_DID: &str = "did:webvh:QmScidMediatorDDDDDDDDDDDDDDDD:example.com:mediator";
    /// Distinct from [`MEDIATOR_DID`] on purpose: `#tsp` is read from its own
    /// service entry, so the tests must not pass by conflating the two.
    const TSP_MEDIATOR_DID: &str = "did:webvh:QmScidTspMediatorTTTTTTTTTTTT:example.com:tsp";

    /// A VTA-managed account on the DIDComm transport with a REST fallback URL.
    fn vta_managed(advertised: Option<AdvertisedTransports>) -> VtaState {
        VtaState {
            is_vta_managed: true,
            persona_did: PERSONA_DID.to_string(),
            mediator_did: MEDIATOR_DID.to_string(),
            vta_did: VTA_DID.to_string(),
            credential_did: "did:key:z6MkTestCredentialKeyAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            transports: VtaTransports {
                in_use: VtaTransport::DidComm,
                rest_url: "https://vta.example".to_string(),
                advertised,
            },
            ..VtaState::default()
        }
    }

    fn joined(lines: &[Line<'static>]) -> String {
        text(lines).join("\n")
    }

    /// The headline fact is the transport in use, not the URL. A populated
    /// `vta_url` on the DIDComm path is the REST *fallback* and must not read as
    /// "we talk to the VTA over HTTPS".
    #[test]
    fn transport_row_names_the_transport_in_use() {
        let out = joined(&render(&vta_managed(None), true));
        assert!(out.contains("Transport:"), "{out}");
        assert!(out.contains("DIDComm"), "{out}");
        assert!(out.contains("(in use)"), "{out}");
        assert!(!out.contains("VTA URL"), "the bare URL row is gone: {out}");
    }

    /// Until the probe lands the panel says so, rather than claiming the VTA
    /// offers only the transport we happen to be on.
    #[test]
    fn transport_row_says_checking_before_the_probe_lands() {
        let out = joined(&render(&vta_managed(None), true));
        assert!(out.contains("checking"), "{out}");
    }

    #[test]
    fn transport_row_reports_the_other_advertised_transport() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: None,
                mediator_did: Some(MEDIATOR_DID.to_string()),
                rest_url: Some("https://vta.example".to_string()),
                error: None,
            })),
            true,
        ));
        assert!(out.contains("REST also available"), "{out}");
    }

    /// A VTA that advertises only the transport in use says exactly that.
    #[test]
    fn transport_row_reports_a_single_advertised_transport() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: None,
                mediator_did: Some(MEDIATOR_DID.to_string()),
                rest_url: None,
                error: None,
            })),
            true,
        ));
        assert!(out.contains("only transport offered"), "{out}");
    }

    /// The defect in #185: a VTA advertising `#tsp` alongside `#vta-didcomm`,
    /// and no `#vta-rest`, rendered as "only transport offered". Two transports
    /// were offered.
    #[test]
    fn a_tsp_advertising_vta_is_not_reported_as_single_transport() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: Some(TSP_MEDIATOR_DID.to_string()),
                mediator_did: Some(MEDIATOR_DID.to_string()),
                rest_url: None,
                error: None,
            })),
            true,
        ));
        assert!(
            !out.contains("only transport offered"),
            "TSP is offered, so this claim is false: {out}"
        );
        assert!(out.contains("TSP for trust tasks"), "{out}");
    }

    /// TSP is neither "available to switch to" nor absent: it carries the
    /// trust-task surface as a leg of the DIDComm session, while everything else
    /// stays on DIDComm. The panel has to express that third thing (VTI R6.4).
    #[test]
    fn tsp_reads_as_carrying_the_trust_task_surface() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: Some(TSP_MEDIATOR_DID.to_string()),
                mediator_did: Some(MEDIATOR_DID.to_string()),
                rest_url: None,
                error: None,
            })),
            true,
        ));
        assert!(out.contains("TSP for trust tasks"), "{out}");
        assert!(
            !out.contains("TSP also available"),
            "TSP is not an alternative transport to switch to: {out}"
        );
        assert!(
            !out.contains("not yet supported"),
            "TSP now carries the trust-task surface: {out}"
        );
    }

    /// A VTA offering all three lists both transports we are not on, and keeps
    /// the selectable one distinct from the one we cannot speak.
    #[test]
    fn a_triple_transport_vta_reports_both_others() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: Some(TSP_MEDIATOR_DID.to_string()),
                mediator_did: Some(MEDIATOR_DID.to_string()),
                rest_url: Some("https://vta.example".to_string()),
                error: None,
            })),
            true,
        ));
        assert!(out.contains("REST also available"), "{out}");
        assert!(out.contains("TSP for trust tasks"), "{out}");
    }

    /// The adjacent inconsistency #185 exposed: `rest_url` is stored config, so
    /// the endpoint line printed under a transport line saying REST is not
    /// offered. Both facts are true; unlabelled they read as a contradiction.
    #[test]
    fn a_configured_but_unadvertised_rest_endpoint_is_labelled_as_such() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: Some(TSP_MEDIATOR_DID.to_string()),
                mediator_did: Some(MEDIATOR_DID.to_string()),
                rest_url: None,
                error: None,
            })),
            true,
        ));
        assert!(out.contains("REST endpoint"), "{out}");
        assert!(out.contains("(configured; not advertised)"), "{out}");
    }

    /// …but only when we positively know. A probe that failed, or has not
    /// landed, is not evidence that the VTA advertises no REST.
    #[test]
    fn an_unprobed_rest_endpoint_is_not_labelled_unadvertised() {
        for state in [
            vta_managed(None),
            vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: None,
                mediator_did: None,
                rest_url: None,
                error: Some("DID did not resolve".to_string()),
            })),
        ] {
            let out = joined(&render(&state, true));
            assert!(
                !out.contains("not advertised"),
                "we have not established that: {out}"
            );
        }
    }

    /// When the VTA does advertise REST, the endpoint line carries no caveat.
    #[test]
    fn an_advertised_rest_endpoint_is_not_labelled() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: None,
                mediator_did: Some(MEDIATOR_DID.to_string()),
                rest_url: Some("https://vta.example".to_string()),
                error: None,
            })),
            true,
        ));
        assert!(out.contains("REST endpoint"), "{out}");
        assert!(!out.contains("not advertised"), "{out}");
    }

    /// A failed probe must be distinguishable from "nothing else is offered" —
    /// an unreachable publication endpoint is not the same fact (VTI R6.4).
    #[test]
    fn a_failed_probe_reads_as_unknown_not_as_unavailable() {
        let out = joined(&render(
            &vta_managed(Some(AdvertisedTransports {
                tsp_mediator_did: None,
                mediator_did: None,
                rest_url: None,
                error: Some("DID did not resolve".to_string()),
            })),
            true,
        ));
        assert!(out.contains("other transports unknown"), "{out}");
        assert!(
            out.contains("DID did not resolve"),
            "reason is shown: {out}"
        );
        assert!(
            !out.contains("only transport offered"),
            "must not claim the transports are known: {out}"
        );
    }

    /// The credential DID is what we authenticate *as*; the old "Credential:"
    /// label said nothing about that.
    #[test]
    fn the_credential_row_says_what_the_credential_is_for() {
        let out = joined(&render(&vta_managed(None), true));
        assert!(out.contains("Authenticated:"), "{out}");
    }

    // --- identity rows ------------------------------------------------------

    /// One row per party: the verified name is the value, the DID is dimmed
    /// detail below it — not a separate "Agent name" row naming the same party.
    #[test]
    fn an_identity_row_leads_with_the_name_and_keeps_the_did_below() {
        let mut state = vta_managed(None);
        state.persona_agent_name = Some("example.com/@alice".to_string());
        let out = text(&render(&state, true));

        let name_row = out
            .iter()
            .position(|l| l.contains("Persona:") && l.contains("example.com/@alice"))
            .expect("named persona row");
        assert!(
            out[name_row + 1].contains(PERSONA_DID),
            "DID sits under the name: {:?}",
            &out[name_row..name_row + 2]
        );
        assert!(
            !out.iter().any(|l| l.contains("Agent name:")),
            "no separate agent-name row: {out:?}"
        );
    }

    /// With no verified name the DID is the value and there is no second line.
    #[test]
    fn an_identity_row_without_a_name_shows_only_the_did() {
        let out = text(&render(&vta_managed(None), true));
        let rows: Vec<_> = out.iter().filter(|l| l.contains(PERSONA_DID)).collect();
        assert_eq!(rows.len(), 1, "DID appears once: {out:?}");
        assert!(rows[0].contains("Persona:"), "{rows:?}");
    }

    // --- section suppression ------------------------------------------------

    /// "Active DIDs" holding nothing but the persona restates the row already
    /// marked `active` in Context Identities, so it is suppressed.
    #[test]
    fn active_dids_is_hidden_when_it_only_restates_the_persona() {
        let mut state = vta_managed(None);
        state.active_dids = vec![ActiveDid {
            did: PERSONA_DID.to_string(),
            agent_name: None,
            label: "Persona".to_string(),
        }]
        .into();
        let out = joined(&render(&state, true));
        assert!(!out.contains("Active DIDs"), "{out}");
    }

    /// A relationship pseudonym is information the identity list does not carry,
    /// so the section comes back.
    #[test]
    fn active_dids_is_shown_once_a_relationship_pseudonym_exists() {
        let mut state = vta_managed(None);
        state.active_dids = vec![
            ActiveDid {
                did: PERSONA_DID.to_string(),
                agent_name: None,
                label: "Persona".to_string(),
            },
            ActiveDid {
                did: "did:peer:2.Ez6Mk".to_string(),
                agent_name: None,
                label: "R-DID (bob)".to_string(),
            },
        ]
        .into();
        let out = joined(&render(&state, true));
        assert!(out.contains("Active DIDs (2)"), "{out}");
    }

    // --- focus cues ---------------------------------------------------------

    /// Both manageable lists carry the same focus affordance, and only the
    /// focused one shows a selection cursor and its key hints.
    #[test]
    fn only_the_focused_identity_list_shows_a_cursor_and_hints() {
        let mut state = state_with(vec![managed_did(None)], vec![vic(None)]);

        state.focus = VtaFocus::Dids;
        let focused = joined(&render(&state, true));
        assert!(
            focused.contains("Context Identities (1)   ◀ focus"),
            "{focused}"
        );
        assert!(
            focused.contains("▸ "),
            "cursor shown when focused: {focused}"
        );
        assert!(focused.contains("n: new persona"), "{focused}");

        state.focus = VtaFocus::Vics;
        let unfocused = joined(&render(&state, true));
        assert!(
            unfocused.contains("Context Identities (1)   [Tab] focus"),
            "{unfocused}"
        );
        assert!(
            !unfocused.contains("n: new persona"),
            "hints belong to the focused list: {unfocused}"
        );
    }

    /// With the content panel itself unfocused, neither list may claim the
    /// keyboard. Both lists used to draw their affordance from `state.focus`
    /// alone, so a panel whose keys are all discarded still announced "◀ focus"
    /// and advertised `g` / `n` / `d` — the shortest path to "I pressed the key
    /// and nothing happened".
    #[test]
    fn an_unfocused_panel_points_at_the_panel_not_the_lists() {
        let mut state = state_with(vec![managed_did(None)], vec![vic(None)]);
        state.focus = VtaFocus::Dids;

        let out = joined(&render(&state, false));
        assert!(
            !out.contains("◀ focus"),
            "no list has the keyboard when the panel does not: {out}"
        );
        assert!(
            !out.contains("[Tab] focus"),
            "Tab is not the key that helps here: {out}"
        );
        assert!(out.contains("[→] focus the panel"), "{out}");
        assert!(
            !out.contains("n: new persona"),
            "hints belong to a list the keyboard can reach: {out}"
        );
    }

    /// An in-flight vault query is visible. "No invitation credentials" is a
    /// claim about the vault, and it can only be made once the vault answers —
    /// before this the load was inline, so the panel simply froze instead.
    #[test]
    fn a_loading_vic_list_says_so_instead_of_claiming_none() {
        let mut state = state_with(vec![managed_did(None)], vec![]);
        state.vic_loading = true;

        let out = joined(&render(&state, true));
        assert!(out.contains("Reading the credential vault…"), "{out}");
        assert!(
            !out.contains("No invitation credentials."),
            "an unanswered vault is not an empty one: {out}"
        );

        state.vic_loading = false;
        let settled = joined(&render(&state, true));
        assert!(settled.contains("No invitation credentials."), "{settled}");
    }

    // --- VIC issuer ---------------------------------------------------------

    #[test]
    fn vic_row_shows_the_issuers_verified_agent_name() {
        let out = text(&render(
            &state_with(vec![], vec![vic(Some("example.com/@acme"))]),
            true,
        ));
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
        let out = text(&render(&state_with(vec![], vec![vic(None)]), true));
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
        let out = text(&render(&state, true));

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
        let out = text(&render(&state, true));

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
