//! What each of your personas actually says — the face one wears in a given
//! community's context. **Context-scoped**; see the [module header](super)
//! for the boundary this sits on the low side of.
//!
//! A membership already carries both halves of the key: a
//! `CommunityRecord::sub_context_id` is the VTA context, and the persona it
//! presents has the DID. Every row in the communities panel is a
//! `(context, persona)` pair, and that pair is exactly what
//! `persona/binding/get` is addressed by.
//!
//! # Thin on purpose
//!
//! A binding read reports **whether** a persona is bound, the profile's label,
//! and how many claims it carries. Never the claim contents. Those reach a
//! consumer only through `persona/disclosure/*`, after a preview a human can be
//! shown — a binding read that returned values would make that gate
//! decorative. So there is nothing here that renders an attribute, and adding
//! one would be reaching around the disclosure path rather than extending this
//! module. [`crate::persona::profile::get`] is where a holder looks at their
//! own values, above the boundary and before anything is pushed across it.
//!
//! # Reads are best-effort; [`set`] is not
//!
//! Same rule as [`crate::devices`]: a VTA that does not serve the persona slice,
//! or a call that times out, must never stop OpenVTC starting or a panel
//! drawing. A membership works whether or not we can say what it presents, and
//! [`BindingSummary::unknown`] is the honest thing to draw while we cannot —
//! distinct from "bound to nothing", which is an answer.
//!
//! [`set`] is the exception, and it has to be: it is a decision the holder just
//! made about what a community sees. A write that quietly failed would leave
//! them believing a persona presents something it does not, so its error is
//! returned rather than softened.

use serde::{Deserialize, Serialize};
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;

/// What one persona presents in one context.
///
/// [`bound`](Self::bound) is the field to read. Do not infer it from
/// [`profile_name`](Self::profile_name) being empty: a profile may legitimately
/// carry no label, and "unlabelled" and "unbound" are different answers to
/// different questions.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BindingSummary {
    /// Whether this persona presents anything at all in this context.
    pub bound: bool,
    /// The holder's label for the bound profile, if it has one.
    pub profile_name: Option<String>,
    /// Identifier of the bound profile.
    pub profile_id: Option<String>,
    /// How many claims the binding carries. `0` for an unbound persona — a
    /// count of nothing is still a count.
    pub claim_count: u64,
    /// When the binding was last written.
    pub bound_at: Option<String>,
    /// True when the agent could not be asked, as distinct from having
    /// answered "nothing is bound".
    ///
    /// Kept as a field rather than modelled as an absent `BindingSummary`,
    /// because a caller that has to unwrap an `Option` reaches for
    /// `unwrap_or_default()` and that would render "we could not ask" as
    /// "presents nothing" — a confident wrong answer about the user's own
    /// identity, which is the one thing this panel must not give.
    pub unknown: bool,
}

impl BindingSummary {
    /// The summary to draw when the agent could not be asked.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            unknown: true,
            ..Self::default()
        }
    }

    /// A one-line description for a panel row, in the words a person reads.
    ///
    /// A persona *wears* a face in a context — the on-screen vocabulary for what
    /// the wire calls binding a profile (`design-docs/persona-vocabulary.md`).
    /// The spec's words stay in the types; they are kept off the screen.
    ///
    /// Three distinct readings, deliberately worded so they cannot be confused:
    /// we do not know; we know nothing is worn; we know what is worn.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.unknown {
            return "wears: unknown".to_string();
        }
        if !self.bound {
            return "wears: nothing".to_string();
        }
        let label = self
            .profile_name
            .clone()
            .or_else(|| self.profile_id.clone())
            .unwrap_or_else(|| "an unnamed face".to_string());
        let attributes = if self.claim_count == 1 {
            "1 attribute".to_string()
        } else {
            format!("{} attributes", self.claim_count)
        };
        format!("wears: {label} ({attributes})")
    }
}

/// Ask the agent what `persona_did` presents in `context_id`.
///
/// Errors are the caller's to log and move past; see the module header.
pub async fn get(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
) -> Result<BindingSummary, OpenVTCError> {
    let value = client
        .persona_binding_get(context_id, persona_did)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona binding read failed: {e}")))?;

    Ok(BindingSummary {
        bound: value
            .get("bound")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        profile_name: value
            .get("profileName")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        profile_id: value
            .get("profileId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        claim_count: value
            .get("claimCount")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        bound_at: value
            .get("boundAt")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        unknown: false,
    })
}

/// Ask once, and fall back to [`BindingSummary::unknown`] rather than failing.
///
/// The form a panel wants: it has a row to draw either way, and the question is
/// only whether it can say anything true about what that row presents.
pub async fn get_or_unknown(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
) -> BindingSummary {
    match get(client, context_id, persona_did).await {
        Ok(summary) => summary,
        Err(e) => {
            tracing::debug!(
                context_id,
                persona_did,
                error = %e,
                "persona binding unavailable; drawing as unknown"
            );
            BindingSummary::unknown()
        }
    }
}

/// Decide what one persona presents in one context.
///
/// `profile_id: None` clears the binding — a persona that presents nothing is a
/// legitimate, common state (a throwaway persona), not an absence to be inferred,
/// so clearing is a first-class call rather than a delete.
///
/// This is the push across the boundary. The VTA resolves the profile *above*
/// the context and writes a materialised projection into it: the context
/// receives values, never pool identifiers, so nothing inside it can walk back
/// to the holder's other personas. That is why there is no "read the pool from a
/// context" counterpart to this function anywhere in the module.
///
/// `publicEntries` is deliberately sent empty. It publishes attributes on the
/// persona's own public surface, where every relying party sees one identical
/// value — a permanent correlation point, and the exact thing per-verifier
/// projection exists to avoid. Offering it behind a keystroke would make it the
/// accidental default; a holder who wants it can say so through `pnm`.
pub async fn set(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
    profile_id: Option<&str>,
) -> Result<(), OpenVTCError> {
    client
        .persona_binding_set(context_id, persona_did, profile_id, Vec::new(), None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona binding write failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_not_the_same_as_unbound() {
        assert_eq!(BindingSummary::unknown().describe(), "wears: unknown");
        assert_eq!(BindingSummary::default().describe(), "wears: nothing");
    }

    /// The distinction the `unknown` flag exists to preserve.
    ///
    /// `BindingSummary::default()` is a *known* empty answer. If "could not
    /// ask" were modelled as an absent value, the natural
    /// `unwrap_or_default()` would collapse the two and tell the user their
    /// persona presents nothing when the truth is that nobody asked.
    #[test]
    fn a_default_summary_never_reads_as_unknown() {
        assert!(!BindingSummary::default().unknown);
        assert!(BindingSummary::unknown().unknown);
    }

    #[test]
    fn a_bound_profile_is_described_by_label_and_count() {
        let s = BindingSummary {
            bound: true,
            profile_name: Some("work".into()),
            claim_count: 3,
            ..Default::default()
        };
        assert_eq!(s.describe(), "wears: work (3 attributes)");
    }

    /// One claim is not "1 claims". Small, and the kind of thing that makes a
    /// panel look unfinished.
    #[test]
    fn a_single_fact_is_singular() {
        let s = BindingSummary {
            bound: true,
            profile_name: Some("gaming".into()),
            claim_count: 1,
            ..Default::default()
        };
        assert_eq!(s.describe(), "wears: gaming (1 attribute)");
    }

    /// A profile with no label falls back to its id, and then to a phrase —
    /// never to the empty string, which would render as "presents:  (2
    /// claims)".
    #[test]
    fn an_unlabelled_profile_still_describes_itself() {
        let by_id = BindingSummary {
            bound: true,
            profile_id: Some("01J8".into()),
            claim_count: 2,
            ..Default::default()
        };
        assert_eq!(by_id.describe(), "wears: 01J8 (2 attributes)");

        let bare = BindingSummary {
            bound: true,
            claim_count: 2,
            ..Default::default()
        };
        assert_eq!(bare.describe(), "wears: an unnamed face (2 attributes)");
    }
}
