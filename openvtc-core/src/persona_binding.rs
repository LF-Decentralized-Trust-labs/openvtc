//! What each of your faces actually says — the profile a persona presents in
//! one community's context.
//!
//! # Two meanings of "persona", and they compose
//!
//! This crate already has a [`PersonaRecord`](crate::config::account::PersonaRecord):
//! a `did:webvh`, its key references, its mediator. That is a face as an
//! *identity* — the DID a community sees and the connection material behind
//! it.
//!
//! The agent's `persona/*` Trust Tasks use the same word for the same thing one
//! layer up: a persona DID that a **profile** of identity attributes is bound
//! to, within a trust context. The two are not competing definitions. This
//! crate holds the face; the agent holds what the face says.
//!
//! They join on the pair this module takes. A community membership already
//! carries both halves — `CommunityRecord::sub_context_id` is the VTA context,
//! and the persona it presents has the DID — which is exactly the key
//! `persona/binding/get` is addressed by. Every membership row in the
//! communities panel is already a `(context, persona)` pair; this is what that
//! pair looks up.
//!
//! # Thin on purpose
//!
//! A binding read reports **whether** a persona is bound, the profile's label,
//! and how many claims it carries. Never the claim contents. Those reach a
//! consumer only through `persona/disclosure/*`, after a preview a human can be
//! shown — a binding read that returned values would make that gate
//! decorative. So there is nothing here that renders an attribute, and adding
//! one would be reaching around the disclosure path rather than extending this
//! module.
//!
//! # Everything here is best-effort
//!
//! Same rule as [`crate::devices`]: a VTA that does not serve the persona slice,
//! or a call that times out, must never stop OpenVTC starting or a panel
//! drawing. A membership works whether or not we can say what it presents, and
//! [`BindingSummary::unknown`] is the honest thing to draw while we cannot —
//! distinct from "bound to nothing", which is an answer.

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

    /// A one-line description for a panel row.
    ///
    /// Three distinct readings, deliberately worded so they cannot be confused:
    /// we do not know; we know nothing is bound; we know what is bound.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.unknown {
            return "presents: unknown".to_string();
        }
        if !self.bound {
            return "presents: nothing".to_string();
        }
        let label = self
            .profile_name
            .clone()
            .or_else(|| self.profile_id.clone())
            .unwrap_or_else(|| "an unlabelled profile".to_string());
        let claims = if self.claim_count == 1 {
            "1 claim".to_string()
        } else {
            format!("{} claims", self.claim_count)
        };
        format!("presents: {label} ({claims})")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_not_the_same_as_unbound() {
        assert_eq!(BindingSummary::unknown().describe(), "presents: unknown");
        assert_eq!(BindingSummary::default().describe(), "presents: nothing");
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
        assert_eq!(s.describe(), "presents: work (3 claims)");
    }

    /// One claim is not "1 claims". Small, and the kind of thing that makes a
    /// panel look unfinished.
    #[test]
    fn a_single_claim_is_singular() {
        let s = BindingSummary {
            bound: true,
            profile_name: Some("gaming".into()),
            claim_count: 1,
            ..Default::default()
        };
        assert_eq!(s.describe(), "presents: gaming (1 claim)");
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
        assert_eq!(by_id.describe(), "presents: 01J8 (2 claims)");

        let bare = BindingSummary {
            bound: true,
            claim_count: 2,
            ..Default::default()
        };
        assert_eq!(
            bare.describe(),
            "presents: an unlabelled profile (2 claims)"
        );
    }
}
