//! The identity pane — every surface for the holder's own identity, in one
//! place.
//!
//! Five tabs, in the order the concepts build on each other: the **personas** a
//! holder presents, the **attributes** they hold about themselves, the
//! **profiles** that project a subset of those attributes, the **communities**
//! each persona is shown to, and the **disclosures** that have actually left.
//! The first comes from `Config`; the rest come from the agent.
//!
//! # Two words, and they are not interchangeable
//!
//! A **persona** is an identity: a `did:webvh`, its keys, its mediator — the
//! thing a community sees. A **profile** is a named projection over the
//! attribute pool — the thing a persona *presents*. You bind a profile to a
//! persona in a context; the reverse is not a sentence.
//!
//! Both words are the spec's, the VTA's, the SDK's and `pnm`'s, and this pane
//! uses them the same way so that a holder reading
//! `pnm persona binding set --persona-did … --profile-id …` recognises what is
//! on screen. Where a sentence needs to be unambiguous about which layer it
//! means — the `persona/*` task family spans both — it says "persona DID".
//!
//! # What this pane will not draw
//!
//! A value the holder never asked to see. The attribute list is fetched without
//! values by default and `v` re-reads *with* them — an opt-in that costs a
//! round-trip rather than a display flag over data already in memory, because a
//! listing that holds values has already read the holder's identity whether or
//! not the panel chose to paint it.
//!
//! A number it does not have. "We could not ask the agent" and "you hold
//! nothing" are one pixel apart and one of them is a confident wrong answer
//! about the holder's own data, so every agent-served tab draws the failure
//! rather than an empty list.

use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::{
    main_page::content::{
        AttributeField, AttributeForm, BindPicker, IdentityState, PersonaConfirm, PersonaMode,
        PersonaTab, ProfileForm, ProfileFormFocus, VALUE_TYPES,
    },
    state::ConnectionState,
};
use openvtc_core::display::display_identifier;
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Width for identifiers on a row. Long enough to be checkable, short enough
/// that the label beside it survives on an 80-column terminal.
const ID_WIDTH: usize = 46;

/// Width for the DID inside a destructive confirmation, where both ends of the
/// identifier have to stay readable.
const CONFIRM_DID_WIDTH: usize = 48;

/// The identity pane.
pub struct IdentityPanel;

impl Panel for IdentityPanel {
    fn render(
        &self,
        state: &crate::state_handler::main_page::content::ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.identity)
    }
}

/// Render the pane. A form or picker owns the whole panel while it is open —
/// the lists behind it are not interactive then, and drawing them would invite
/// keys that go nowhere.
pub fn render(state: &IdentityState) -> Vec<Line<'static>> {
    match &state.mode {
        PersonaMode::Attribute(form) => render_attribute_form(form),
        PersonaMode::Profile(form) => render_profile_form(state, form),
        PersonaMode::Bind(picker) => render_bind_picker(state, picker),
        PersonaMode::View => render_tabs(state),
    }
}

// ---------------------------------------------------------------------------
// The tabbed view
// ---------------------------------------------------------------------------

fn render_tabs(state: &IdentityState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    if let Some(msg) = &state.status_message {
        super::status::push_status(&mut lines, msg, "");
        lines.push(Line::from(""));
    }

    // Tab strip.
    let mut spans = Vec::new();
    for (i, tab) in PersonaTab::all().into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" | ", Style::new().fg(COLOR_DARK_GRAY)));
        }
        let style = if state.tab == tab {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_DARK_GRAY)
        };
        spans.push(Span::styled(format!(" {} ", tab.label()), style));
    }
    lines.push(Line::from(spans));
    lines.push(Line::from(""));

    match state.tab {
        PersonaTab::Personas => render_personas(state, &mut lines),
        PersonaTab::Attributes => render_attributes(state, &mut lines),
        PersonaTab::Profiles => render_profiles(state, &mut lines),
        PersonaTab::Communities => render_communities(state, &mut lines),
        PersonaTab::Disclosures => render_disclosures(state, &mut lines),
    }

    // The confirmation prompt replaces the key hints while it is armed: a
    // destructive question and a menu of other things to press do not belong on
    // screen together.
    lines.push(Line::from(""));
    match confirm_prompt(state) {
        Some(prompt) => lines.push(Line::from(prompt).fg(COLOR_ORANGE).bold()),
        None => lines.push(Line::from(hints(state)).fg(COLOR_DARK_GRAY)),
    }
    lines
}

/// The question to put, worded so a `y` cannot be given to the wrong one.
fn confirm_prompt(state: &IdentityState) -> Option<String> {
    match &state.confirm {
        PersonaConfirm::None => None,
        PersonaConfirm::DeletePersona(i) => {
            let persona = state.personas.get(*i)?;
            // Keep *both* the name and the DID. The row the operator selected
            // shows the name, so a DID-only prompt names something they never
            // saw; but a destructive confirm must stay unambiguous, so the DID
            // is not dropped either — it is centre-truncated to keep the line
            // readable while both ends stay checkable.
            let did = openvtc_core::display::truncate_did_centered(&persona.did, CONFIRM_DID_WIDTH);
            let name = match persona
                .label
                .is_empty()
                .then_some(persona.agent_name.as_deref())
                .flatten()
                .or_else(|| (!persona.label.is_empty()).then_some(persona.label.as_str()))
            {
                Some(name) => format!("{name} ({did})"),
                None => did.into_owned(),
            };
            Some(format!("Remove {name}?   y: confirm    n: cancel"))
        }
        PersonaConfirm::DeleteAttribute { name, cascade, .. } => {
            if *cascade {
                // The cascading question names the consequence the plain one
                // does not have: profiles that show this value stop showing it.
                Some(format!(
                    "\"{name}\" is used by one or more profiles. Delete it AND remove it from \
                     them?   y: confirm    n: cancel"
                ))
            } else {
                Some(format!(
                    "Delete \"{name}\" from your pool?   y: confirm    n: cancel"
                ))
            }
        }
        PersonaConfirm::DeleteProfile { name, unbind, .. } => {
            if *unbind {
                Some(format!(
                    "A persona still presents \"{name}\". Delete it and leave that persona presenting \
                     nothing?   y: confirm    n: cancel"
                ))
            } else {
                Some(format!(
                    "Delete the profile \"{name}\"?   y: confirm    n: cancel"
                ))
            }
        }
        PersonaConfirm::Unbind { community, .. } => Some(format!(
            "Stop presenting anything to {community}?   y: confirm    n: cancel"
        )),
    }
}

fn hints(state: &IdentityState) -> &'static str {
    match state.tab {
        PersonaTab::Personas => {
            "↑/↓ select   n: new persona   g: agent names   d: remove orphan   ⇥/⇧⇥: tab"
        }
        PersonaTab::Attributes => {
            "↑/↓ select   n: new   e: edit   d: delete   v: values   r: refresh   ⇥/⇧⇥: tab"
        }
        PersonaTab::Profiles => {
            "↑/↓ select   ⏎: what it shows   n: new   e: edit   d: delete   r: refresh   ⇥/⇧⇥: tab"
        }
        PersonaTab::Communities => {
            "↑/↓ select   b: choose what this persona shows   u: show nothing   r: refresh   ⇥/⇧⇥: tab"
        }
        PersonaTab::Disclosures => "↑/↓ select   r: refresh   ⇥/⇧⇥: tab",
    }
}

// ---------------------------------------------------------------------------
// Personas
// ---------------------------------------------------------------------------

fn render_personas(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if state.personas.is_empty() {
        lines.push(Line::from(" You have no persona DIDs yet.").fg(COLOR_DARK_GRAY));
        lines.push(Line::from(""));
        lines.push(
            Line::from(
                " A persona is a did:webvh you present to a community. Mint one with `n`, hand its \
                 DID to a community, and they can issue an invitation bound to it.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    lines.push(
        Line::from(format!(
            " {} persona{}",
            state.personas.len(),
            if state.personas.len() == 1 { "" } else { "s" }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    for (i, persona) in state.personas.iter().enumerate() {
        let is_selected = i == state.persona_selected;
        // An orphan is a persona no community sees. Usually the residue of a join
        // that failed, and worth spotting: it costs keys and a mediator
        // registration while presenting nothing to anybody.
        let orphan = persona.bound_communities == 0;
        let prefix = if is_selected { "▸ " } else { "  " };
        let marker_style = if orphan {
            Style::new().fg(COLOR_ORANGE)
        } else {
            Style::new().fg(COLOR_SUCCESS)
        };
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        lines.push(Line::from(vec![
            Span::styled(prefix, marker_style),
            Span::styled(if orphan { "○ " } else { "● " }, marker_style),
            Span::styled(
                display_identifier(persona.agent_name.as_deref(), &persona.did, ID_WIDTH)
                    .into_owned(),
                row_style,
            ),
        ]));

        let name = if persona.label.is_empty() {
            "unnamed persona".to_string()
        } else {
            persona.label.clone()
        };
        let seen_by = if orphan {
            "orphan — no community".to_string()
        } else {
            format!(
                "seen by {} communit{}",
                persona.bound_communities,
                if persona.bound_communities == 1 {
                    "y"
                } else {
                    "ies"
                }
            )
        };
        let active = if persona.is_active {
            "  ·  active"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("      {name}{active}  ·  "),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Span::styled(
                seen_by,
                if orphan {
                    Style::new().fg(COLOR_ORANGE)
                } else {
                    Style::new().fg(COLOR_DARK_GRAY)
                },
            ),
        ]));
    }
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

fn render_attributes(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if push_agent_state(state, lines, "attributes") {
        return;
    }

    lines.push(Line::from(vec![
        Span::styled(
            format!(
                " {} attribute{} in your pool",
                state.attributes.len(),
                if state.attributes.len() == 1 { "" } else { "s" }
            ),
            Style::new().fg(COLOR_TEXT_DEFAULT),
        ),
        Span::styled(
            if state.show_values {
                "        values shown — v to hide"
            } else {
                "        values hidden — v to show"
            },
            if state.show_values {
                Style::new().fg(COLOR_ORANGE)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            },
        ),
    ]));
    lines.push(Line::from(""));

    if state.attributes.is_empty() {
        lines.push(
            Line::from(
                " Nothing in the pool yet. `n` adds a fact about yourself — a name, an email, a \
                 date of birth — that profiles can then draw on.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    for (i, attr) in state.attributes.iter().enumerate() {
        let is_selected = i == state.attribute_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(
                format!("{:<28}", truncate(attr.display_name(), 27)),
                row_style,
            ),
            Span::styled(
                format!("{:<20}", truncate(&attr.claim_type, 19)),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
            Span::styled(
                attr.provenance.label().to_string(),
                // A credential-backed value is the one a holder must not expect
                // to edit here, so its provenance is the part of the row that
                // stands out rather than a footnote after they have tried.
                if attr.provenance.is_editable_here() {
                    Style::new().fg(COLOR_DARK_GRAY)
                } else {
                    Style::new().fg(COLOR_ORANGE)
                },
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!(
                "      {}",
                truncate(&attr.display_value(state.show_values), 70)
            ),
            if attr.stale {
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            },
        )));
    }
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

fn render_profiles(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if let Some(detail) = &state.open_profile {
        lines.push(
            Line::from(format!(" {}", detail.summary.display_name()))
                .fg(COLOR_SUCCESS)
                .bold(),
        );
        lines.push(Line::from(""));
        if !detail.is_editable_here() {
            super::status::push_status(lines, &detail.refusal(), " ");
            lines.push(Line::from(""));
        }
        if detail.resolved.is_empty() {
            lines.push(
                Line::from(" This profile presents nothing — it has no entries.")
                    .fg(COLOR_DARK_GRAY),
            );
        } else {
            lines.push(
                Line::from(format!(
                    " Presents {} claim{}:",
                    detail.resolved.len(),
                    if detail.resolved.len() == 1 { "" } else { "s" }
                ))
                .fg(COLOR_TEXT_DEFAULT),
            );
            lines.push(Line::from(""));
            for claim in &detail.resolved {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("   {:<22}", truncate(&claim.claim_type, 21)),
                        Style::new().fg(COLOR_SOFT_PURPLE),
                    ),
                    Span::styled(
                        truncate(&claim.display_value(), 44),
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                ]));
                // An inline value lives only in this profile: it is not in the
                // pool, so correcting it in the pool will not correct it here.
                // Saying so on the row is the only place a holder finds out.
                let origin = match claim.attribute_id {
                    Some(_) => claim.provenance.label().to_string(),
                    None => format!("{} · only in this profile", claim.provenance.label()),
                };
                lines.push(Line::from(Span::styled(
                    format!("   {origin}"),
                    Style::new().fg(COLOR_DARK_GRAY),
                )));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(" ⏎/Esc: back   e: edit").fg(COLOR_DARK_GRAY));
        return;
    }

    if push_agent_state(state, lines, "profiles") {
        return;
    }

    lines.push(
        Line::from(format!(
            " {} profile{}",
            state.profiles.len(),
            if state.profiles.len() == 1 { "" } else { "s" }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    if state.profiles.is_empty() {
        lines.push(
            Line::from(
                " No profiles yet. A profile is a named subset of your pool — \"Work\", \
                 \"Gaming\" — and it is what a persona presents to a community.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    for (i, profile) in state.profiles.iter().enumerate() {
        let is_selected = i == state.profile_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(
                format!("{:<28}", truncate(profile.display_name(), 27)),
                row_style,
            ),
            Span::styled(
                format!(
                    "{} entr{}",
                    profile.entry_count,
                    if profile.entry_count == 1 { "y" } else { "ies" }
                ),
                Style::new().fg(COLOR_DARK_GRAY),
            ),
        ]));
    }
}

// ---------------------------------------------------------------------------
// Communities
// ---------------------------------------------------------------------------

fn render_communities(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if state.memberships.is_empty() {
        lines.push(Line::from(" You are not a member of any community yet.").fg(COLOR_DARK_GRAY));
        return;
    }

    lines.push(
        Line::from(format!(
            " {} membership{}",
            state.memberships.len(),
            if state.memberships.len() == 1 {
                ""
            } else {
                "s"
            }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    for (i, m) in state.memberships.iter().enumerate() {
        let is_selected = i == state.membership_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(truncate(&m.community_name, 30), row_style),
            Span::styled(
                format!("  as {}", truncate(&m.persona_label, 24)),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
        ]));

        // What that persona tells them. `unknown` is drawn, never omitted: an
        // omitted row is indistinguishable from a persona bound to nothing, and
        // "we have not asked" is not "you are sharing nothing".
        let detail = format!(
            "      {}  ·  {}",
            m.status_label,
            state.binding_for(m).describe()
        );
        lines.push(Line::from(Span::styled(
            detail,
            if is_selected {
                Style::new().fg(COLOR_SOFT_PURPLE)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            },
        )));

        // The linkage line. Two communities shown one persona can compare notes
        // and find the same person behind both, and that is the consequence a
        // holder cannot see by looking at either row on its own.
        if m.shared_with > 0 {
            lines.push(
                Line::from(format!(
                    "      ⚠ this persona is also shown to {} other communit{}",
                    m.shared_with,
                    if m.shared_with == 1 { "y" } else { "ies" }
                ))
                .fg(COLOR_ORANGE),
            );
        }
    }

    lines.push(Line::from(""));
    // The honest limit of this tab. A membership is held by a credential issued
    // to one persona DID, so which persona a community sees is fixed at the join —
    // `b` changes what that persona says, never who it is.
    lines.push(
        Line::from(
            " `b` changes what a persona presents here. To show a community a *different* persona, join \
             it again with that persona — the membership credential is bound to the persona that \
             joined.",
        )
        .fg(COLOR_DARK_GRAY),
    );
}

// ---------------------------------------------------------------------------
// Disclosures
// ---------------------------------------------------------------------------

fn render_disclosures(state: &IdentityState, lines: &mut Vec<Line<'static>>) {
    if push_agent_state(state, lines, "disclosures") {
        return;
    }

    lines.push(
        Line::from(format!(
            " {} disclosure{}, newest first",
            state.disclosures.len(),
            if state.disclosures.len() == 1 {
                ""
            } else {
                "s"
            }
        ))
        .fg(COLOR_TEXT_DEFAULT),
    );
    lines.push(Line::from(""));

    if state.disclosures.is_empty() {
        lines.push(
            Line::from(
                " Nothing has been disclosed from this agent yet. A release happens when a \
                 verifier asks and you approve it — this is the record of those, and it is \
                 read-only.",
            )
            .fg(COLOR_DARK_GRAY),
        );
        return;
    }

    for (i, row) in state.disclosures.iter().enumerate() {
        let is_selected = i == state.disclosure_selected;
        let row_style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
            Span::styled(
                format!("{:<22}", truncate(&row.disclosed_at, 21)),
                row_style,
            ),
            Span::styled(
                truncate(&row.verifier_did, 44),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("      {}", truncate(&row.describe_claims(), 70)),
            Style::new().fg(COLOR_DARK_GRAY),
        )));
        // A durable credential is the one kind of release that is still live —
        // and still revocable — rather than a thing that happened once.
        if let Some(id) = &row.durable_credential_id {
            lines.push(
                Line::from(format!(
                    "      ● still live as a credential ({})",
                    truncate(id, 40)
                ))
                .fg(COLOR_ORANGE),
            );
        }
    }
}

/// Draw the "we are still asking" / "we could not ask" states shared by the
/// agent-served tabs. Returns true when it drew one and the caller should stop.
///
/// The failure case is why this exists: an empty list and an unreachable agent
/// render identically unless something says otherwise, and of the two, "you
/// hold no attributes" is the confident wrong answer (VTI R6.4).
fn push_agent_state(state: &IdentityState, lines: &mut Vec<Line<'static>>, noun: &str) -> bool {
    if let Some(error) = &state.load_error {
        lines.push(
            Line::from(format!(" Could not read your {noun} from the agent."))
                .fg(COLOR_WARNING_ACCESSIBLE_RED),
        );
        lines.push(Line::from(""));
        super::status::push_status(lines, error, " ");
        lines.push(Line::from(""));
        lines.push(Line::from(" r: try again").fg(COLOR_DARK_GRAY));
        return true;
    }
    if state.loading && !state.loaded {
        lines.push(Line::from(format!(" Reading your {noun}…")).fg(COLOR_DARK_GRAY));
        return true;
    }
    if !state.loaded {
        lines.push(
            Line::from(format!(
                " Your {noun} have not been read yet.   r: read them"
            ))
            .fg(COLOR_DARK_GRAY),
        );
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// The attribute editor
// ---------------------------------------------------------------------------

fn render_attribute_form(form: &AttributeForm) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(if form.attribute_id.is_some() {
            " Edit attribute"
        } else {
            " New attribute"
        })
        .fg(COLOR_SUCCESS)
        .bold(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(
            " A fact about you, held once. Profiles reference it, so correcting it here corrects \
             it everywhere it is presented.",
        )
        .fg(COLOR_DARK_GRAY),
    );
    lines.push(Line::from(""));

    field(
        &mut lines,
        "Type",
        form.claim_type.value(),
        form.field == AttributeField::ClaimType,
    );
    lines.push(Line::from("      e.g. name.legal, email.work, phone.mobile").fg(COLOR_DARK_GRAY));
    field(
        &mut lines,
        "Label",
        form.label.value(),
        form.field == AttributeField::Label,
    );
    field(
        &mut lines,
        "Value type",
        &format!(
            "◂ {} ▸",
            VALUE_TYPES[form.value_type.min(VALUE_TYPES.len() - 1)]
        ),
        form.field == AttributeField::ValueType,
    );
    field(
        &mut lines,
        "Value",
        form.value.value(),
        form.field == AttributeField::Value,
    );

    lines.push(Line::from(""));
    if let Some(error) = &form.error {
        super::status::push_status(&mut lines, error, " ");
        lines.push(Line::from(""));
    }
    lines.push(
        Line::from(if form.working {
            " Saving…"
        } else {
            " ⇥: next field   ←/→: value type   ⏎: save   Esc: cancel"
        })
        .fg(COLOR_DARK_GRAY),
    );
    lines
}

// ---------------------------------------------------------------------------
// The profile editor
// ---------------------------------------------------------------------------

fn render_profile_form(state: &IdentityState, form: &ProfileForm) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(if form.profile_id.is_some() {
            " Edit profile"
        } else {
            " New profile"
        })
        .fg(COLOR_SUCCESS)
        .bold(),
    );
    lines.push(Line::from(""));

    field(
        &mut lines,
        "Name",
        form.name.value(),
        form.focus == ProfileFormFocus::Name,
    );
    lines.push(Line::from(""));

    let list_style = if form.focus == ProfileFormFocus::Entries {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_DARK_GRAY)
    };
    lines.push(Line::from(Span::styled(
        format!(" Shows these facts ({} ticked)", form.ticked.len()),
        list_style,
    )));
    lines.push(Line::from(""));

    if state.attributes.is_empty() {
        lines.push(
            Line::from("   Your pool is empty — add an attribute first.").fg(COLOR_DARK_GRAY),
        );
    } else {
        for (i, attr) in state.attributes.iter().enumerate() {
            let ticked = form.ticked.contains(&attr.attribute_id);
            let is_cursor = form.focus == ProfileFormFocus::Entries && i == form.cursor;
            let row_style = if is_cursor {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else if ticked {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            } else {
                Style::new().fg(COLOR_DARK_GRAY)
            };
            lines.push(Line::from(vec![
                Span::styled(if is_cursor { " ▸ " } else { "   " }, row_style),
                Span::styled(if ticked { "[x] " } else { "[ ] " }, row_style),
                Span::styled(
                    format!("{:<28}", truncate(attr.display_name(), 27)),
                    row_style,
                ),
                Span::styled(
                    truncate(&attr.claim_type, 24),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ),
            ]));
        }
    }

    // The entries this editor does not own, counted so a holder can see that
    // saving will not lose them.
    if !form.preserved.is_empty() {
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!(
                "   + {} pinned/overridden/inline entr{} kept as-is (edit with `pnm`)",
                form.preserved.len(),
                if form.preserved.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ))
            .fg(COLOR_DARK_GRAY),
        );
    }

    lines.push(Line::from(""));
    if let Some(error) = &form.error {
        super::status::push_status(&mut lines, error, " ");
        lines.push(Line::from(""));
    }
    lines.push(
        Line::from(if form.working {
            " Saving…"
        } else {
            " ⇥: name/list   ↑/↓: move   Space: tick   ⏎: save   Esc: cancel"
        })
        .fg(COLOR_DARK_GRAY),
    );
    lines
}

// ---------------------------------------------------------------------------
// The bind picker
// ---------------------------------------------------------------------------

fn render_bind_picker(state: &IdentityState, picker: &BindPicker) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.push(
        Line::from(format!(
            " What should {} present to {}?",
            picker.persona_label, picker.community
        ))
        .fg(COLOR_SUCCESS)
        .bold(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(
            " The values are copied into the community's context when you choose. It receives \
             what the profile resolves to — never a reference back to your pool, and nothing \
             about your other personas.",
        )
        .fg(COLOR_DARK_GRAY),
    );
    lines.push(Line::from(""));

    // Row 0 is always "nothing", because a persona that deliberately presents
    // nothing is a real choice and not the absence of one.
    for (i, label) in bind_options(state).into_iter().enumerate() {
        let is_cursor = i == picker.cursor;
        let style = if is_cursor {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_cursor { " ▸ " } else { "   " }, style),
            Span::styled(label, style),
        ]));
    }

    lines.push(Line::from(""));
    if let Some(error) = &picker.error {
        super::status::push_status(&mut lines, error, " ");
        lines.push(Line::from(""));
    }
    lines.push(
        Line::from(if picker.working {
            " Applying…"
        } else {
            " ↑/↓: move   ⏎: apply   Esc: cancel"
        })
        .fg(COLOR_DARK_GRAY),
    );
    lines
}

/// The picker's rows: "nothing", then every profile. Derived rather than stored
/// so a profile added or renamed between opening the picker and reading it
/// cannot show a stale name.
pub fn bind_options(state: &IdentityState) -> Vec<String> {
    let mut options = vec!["Nothing — present no identity here".to_string()];
    options.extend(state.profiles.iter().map(|p| {
        format!(
            "{}  ({} entr{})",
            p.display_name(),
            p.entry_count,
            if p.entry_count == 1 { "y" } else { "ies" }
        )
    }));
    options
}

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

/// One labelled form field, with the focused one marked.
fn field(lines: &mut Vec<Line<'static>>, label: &str, value: &str, focused: bool) {
    let style = if focused {
        Style::new().fg(COLOR_SUCCESS).bold()
    } else {
        Style::new().fg(COLOR_TEXT_DEFAULT)
    };
    lines.push(Line::from(vec![
        Span::styled(if focused { " ▸ " } else { "   " }, style),
        Span::styled(format!("{label:<12}"), Style::new().fg(COLOR_DARK_GRAY)),
        Span::styled(value.to_string(), style),
        Span::styled(if focused { "▏" } else { "" }, style),
    ]));
}

/// Truncate for a fixed-width column, with an ellipsis so a cut is visible.
fn truncate(text: &str, max: usize) -> String {
    openvtc_core::display::truncate_chars(text, max).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{ManagedDid, PersonaMembership};
    use openvtc_core::persona::binding::BindingSummary;
    use openvtc_core::persona::pool::PoolAttribute;

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn loaded(state: &mut IdentityState) {
        state.loaded = true;
        state.loading = false;
    }

    /// The distinction the whole pane is built around: an agent that could not
    /// be asked must never render as an empty pool. One of those sentences is a
    /// confident claim about the holder's own data, and it would be wrong.
    #[test]
    fn an_unreachable_agent_never_reads_as_an_empty_pool() {
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            ..IdentityState::default()
        };
        loaded(&mut state);
        let empty = text(&render(&state));
        assert!(empty.contains("Nothing in the pool yet"), "{empty}");

        state.load_error = Some("connection refused".to_string());
        let failed = text(&render(&state));
        assert!(
            failed.contains("Could not read your attributes"),
            "{failed}"
        );
        assert!(
            failed.contains("connection refused"),
            "the reason has to reach the operator: {failed}"
        );
        assert!(
            !failed.contains("Nothing in the pool yet"),
            "a failed read must not claim the pool is empty: {failed}"
        );
    }

    /// Values are hidden until asked for, and the row says which state it is in
    /// — otherwise "(hidden)" and "no value" are the same pixels.
    #[test]
    fn values_are_hidden_until_asked_for() {
        let attr = PoolAttribute {
            attribute_id: "01A".into(),
            claim_type: "email.work".into(),
            label: Some("Work email".into()),
            ..PoolAttribute::default()
        };
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            attributes: vec![attr].into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let hidden = text(&render(&state));
        assert!(hidden.contains("values hidden"), "{hidden}");
        assert!(hidden.contains("(hidden)"), "{hidden}");

        state.show_values = true;
        let shown = text(&render(&state));
        assert!(shown.contains("values shown"), "{shown}");
        assert!(
            shown.contains("(no value)"),
            "a listing that asked and got nothing says so: {shown}"
        );
    }

    /// A persona shown to more than one community carries the linkage warning.
    /// Nothing else on screen lets a holder work that out from a single row.
    #[test]
    fn a_reused_persona_is_flagged_as_linkable() {
        let mut state = IdentityState {
            tab: PersonaTab::Communities,
            memberships: vec![
                PersonaMembership {
                    community_name: "Acme".into(),
                    persona_label: "Work me".into(),
                    status_label: "Member".into(),
                    shared_with: 1,
                    ..PersonaMembership::default()
                },
                PersonaMembership {
                    community_name: "Chess Club".into(),
                    persona_label: "Gaming me".into(),
                    status_label: "Member".into(),
                    shared_with: 0,
                    ..PersonaMembership::default()
                },
            ]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("also shown to 1 other community"), "{out}");
        assert_eq!(
            out.matches("also shown to").count(),
            1,
            "the persona used once must not be flagged: {out}"
        );
    }

    /// "We have not asked" and "presents nothing" are different sentences on a
    /// membership row, for the same reason they are different in
    /// `BindingSummary`.
    #[test]
    fn an_unasked_binding_reads_as_unknown_not_as_nothing() {
        let membership = PersonaMembership {
            community_name: "Acme".into(),
            sub_context_id: "ctx".into(),
            persona_did: "did:webvh:example.com:alice".into(),
            persona_label: "Work me".into(),
            status_label: "Member".into(),
            shared_with: 0,
        };
        let mut state = IdentityState {
            tab: PersonaTab::Communities,
            memberships: vec![membership.clone()].into(),
            ..IdentityState::default()
        };
        loaded(&mut state);
        assert!(text(&render(&state)).contains("presents: unknown"));

        state.bindings.insert(
            ("ctx".to_string(), membership.persona_did.clone()),
            BindingSummary::default(),
        );
        assert!(text(&render(&state)).contains("presents: nothing"));
    }

    /// The two delete questions are worded differently, and the cascading one
    /// names the consequence the plain one does not have. Which is asked is
    /// decided before the prompt appears — see `persona_actions`.
    #[test]
    fn a_cascading_delete_asks_a_visibly_different_question() {
        let attr = PoolAttribute {
            attribute_id: "01A".into(),
            label: Some("Work email".into()),
            ..PoolAttribute::default()
        };
        let mut state = IdentityState {
            tab: PersonaTab::Attributes,
            attributes: vec![attr].into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        state.confirm = PersonaConfirm::DeleteAttribute {
            attribute_id: "01A".into(),
            name: "Work email".into(),
            cascade: false,
        };
        let plain = text(&render(&state));
        assert!(
            plain.contains("Delete \"Work email\" from your pool?"),
            "{plain}"
        );
        assert!(!plain.contains("profiles"), "{plain}");

        state.confirm = PersonaConfirm::DeleteAttribute {
            attribute_id: "01A".into(),
            name: "Work email".into(),
            cascade: true,
        };
        let escalated = text(&render(&state));
        assert!(
            escalated.contains("used by one or more profiles"),
            "{escalated}"
        );
    }

    /// An armed confirmation replaces the key hints: a destructive question and
    /// a menu of other keys do not belong on screen together.
    #[test]
    fn a_confirmation_replaces_the_key_hints() {
        let mut state = IdentityState {
            tab: PersonaTab::Personas,
            personas: vec![ManagedDid {
                did: "did:webvh:example.com:alice".into(),
                label: "Work me".into(),
                ..ManagedDid::default()
            }]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);
        assert!(text(&render(&state)).contains("n: new persona"));

        state.confirm = PersonaConfirm::DeletePersona(0);
        let armed = text(&render(&state));
        assert!(armed.contains("Remove Work me"), "{armed}");
        assert!(!armed.contains("n: new persona"), "{armed}");
    }

    /// The destructive confirm names what the operator selected *and* keeps the
    /// DID, so it is both recognisable and unambiguous. Moved here with the
    /// list it prompts over.
    #[test]
    fn the_persona_prompt_keeps_both_the_name_and_the_did() {
        const DID: &str = "did:webvh:QmScidAliceAAAAAAAAAAAAAAAAAAAAAA:example.com:alice";
        let mut state = IdentityState {
            tab: PersonaTab::Personas,
            personas: vec![ManagedDid {
                did: DID.into(),
                agent_name: Some("example.com/@alice".into()),
                label: String::new(),
                bound_communities: 0,
                is_active: false,
            }]
            .into(),
            confirm: PersonaConfirm::DeletePersona(0),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        let prompt = out
            .lines()
            .find(|l| l.starts_with("Remove "))
            .expect("confirm prompt rendered");
        assert!(prompt.contains("example.com/@alice"), "{prompt}");
        // The DID is centre-truncated, so both ends must still be checkable.
        assert!(prompt.contains("did:webvh:QmScidAlice"), "{prompt}");
        assert!(prompt.contains("example.com:alice"), "{prompt}");
        assert!(prompt.contains("y: confirm"), "{prompt}");
    }

    /// With no name at all the prompt falls back to the DID alone — never to an
    /// empty parenthetical or a nameless "this identity".
    #[test]
    fn the_persona_prompt_without_a_name_shows_the_did() {
        const DID: &str = "did:webvh:QmScidAliceAAAAAAAAAAAAAAAAAAAAAA:example.com:alice";
        let mut state = IdentityState {
            tab: PersonaTab::Personas,
            personas: vec![ManagedDid {
                did: DID.into(),
                ..ManagedDid::default()
            }]
            .into(),
            confirm: PersonaConfirm::DeletePersona(0),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        let prompt = out
            .lines()
            .find(|l| l.starts_with("Remove "))
            .expect("confirm prompt rendered");
        assert!(prompt.contains("did:webvh:QmScidAlice"), "{prompt}");
        assert!(prompt.contains("example.com:alice"), "{prompt}");
        assert!(
            !prompt.contains('('),
            "no empty name parenthetical: {prompt}"
        );
    }

    /// The picker always offers "nothing" first, and it is worded as a choice
    /// rather than as an empty row.
    #[test]
    fn the_bind_picker_offers_nothing_as_a_first_class_choice() {
        let state = IdentityState::default();
        let options = bind_options(&state);
        assert_eq!(options.len(), 1);
        assert!(options[0].starts_with("Nothing"));
    }

    /// The disclosure history is read-only and says so, and an empty one says
    /// what a release even is — the tab is where a holder goes to ask "what
    /// does anyone already know", and an unexplained blank answers nothing.
    #[test]
    fn an_empty_history_explains_itself_rather_than_going_blank() {
        let mut state = IdentityState {
            tab: PersonaTab::Disclosures,
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("Nothing has been disclosed"), "{out}");
        assert!(out.contains("read-only"), "{out}");
        // No verbs beyond navigation and refresh: this pane cannot disclose.
        assert!(!out.contains("n: new"), "{out}");
    }

    /// Every claim carries the rung it went out at, and a release that is still
    /// live as a credential is marked as such — it is the one kind that can
    /// still be revoked rather than only regretted.
    #[test]
    fn a_disclosure_row_shows_its_rungs_and_flags_a_live_credential() {
        use openvtc_core::persona::disclosure::{DisclosedClaim, DisclosureRow};
        let mut state = IdentityState {
            tab: PersonaTab::Disclosures,
            disclosures: vec![
                DisclosureRow {
                    verifier_did: "did:webvh:example.com:acme".into(),
                    disclosed_at: "2026-09-06T10:00:00Z".into(),
                    claims: vec![
                        DisclosedClaim {
                            claim_type: "email.work".into(),
                            rung: "whole".into(),
                        },
                        DisclosedClaim {
                            claim_type: "age.over18".into(),
                            rung: "predicate".into(),
                        },
                    ],
                    durable_credential_id: Some("urn:cred:1".into()),
                    ..DisclosureRow::default()
                },
                DisclosureRow {
                    verifier_did: "did:webvh:example.com:chess".into(),
                    disclosed_at: "2026-09-05T10:00:00Z".into(),
                    ..DisclosureRow::default()
                },
            ]
            .into(),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert!(out.contains("email.work (whole)"), "{out}");
        assert!(out.contains("age.over18 (predicate)"), "{out}");
        assert_eq!(
            out.matches("still live as a credential").count(),
            1,
            "only the durable one is flagged: {out}"
        );
    }

    /// A resolved claim with no pool attribute behind it is marked, because
    /// correcting the pool will not correct it.
    #[test]
    fn an_inline_claim_says_it_lives_only_in_the_profile() {
        use openvtc_core::persona::profile::{ProfileDetail, ProfileSummary, ResolvedClaim};
        let mut state = IdentityState {
            tab: PersonaTab::Profiles,
            open_profile: Some(ProfileDetail {
                summary: ProfileSummary {
                    profile_id: "01P".into(),
                    name: "Work".into(),
                    ..ProfileSummary::default()
                },
                resolved: vec![
                    ResolvedClaim {
                        claim_type: "email.work".into(),
                        value: Some(serde_json::json!("a@b.c")),
                        attribute_id: Some("01A".into()),
                        ..ResolvedClaim::default()
                    },
                    ResolvedClaim {
                        claim_type: "nickname".into(),
                        value: Some(serde_json::json!("Ace")),
                        attribute_id: None,
                        ..ResolvedClaim::default()
                    },
                ],
                ..ProfileDetail::default()
            }),
            ..IdentityState::default()
        };
        loaded(&mut state);

        let out = text(&render(&state));
        assert_eq!(
            out.matches("only in this profile").count(),
            1,
            "exactly the inline claim is marked: {out}"
        );
    }
}
