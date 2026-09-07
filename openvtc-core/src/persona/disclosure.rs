//! What has actually left — the permanent record of every release.
//! **Holder-scoped**, and the one read in this module family that deliberately
//! spans every context at once.
//!
//! # Read-only here, and that is the design
//!
//! The two writing halves of `persona/disclosure/*` are a preview and the
//! present it authorises, and they exist to be driven by a verifier's request:
//! a site asks, a human is shown exactly what would go, and only then is
//! anything signed. OpenVTC is not a verifier and has nothing asking, so a
//! "disclose something now" button here would be a request with no requester —
//! the one shape the two-call gate exists to prevent.
//!
//! What the TUI can usefully answer is the question after the fact: what does
//! anyone already know, and how did they come to know it. That is this module.
//!
//! # A rung is not a detail
//!
//! The same claim type released at two proof rungs is two very different
//! disclosures — `whole` hands every verifier an identical issuer signature to
//! join on, while `predicate` proves a statement without handing over the
//! claim. A history that listed types and dropped rungs would show two
//! materially different acts as one line repeated.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;

/// One claim in a release, as the history reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosedClaim {
    /// The vocabulary token — `email.work`.
    pub claim_type: String,
    /// How strongly it was hidden: `predicate`, `derived`, `selective`,
    /// `whole`, ordered most private first.
    pub rung: String,
}

/// One release, already reduced to what a panel row needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureRow {
    pub disclosure_id: String,
    /// The trust context it happened in.
    pub context_id: String,
    /// Who it went to.
    pub verifier_did: String,
    /// The persona it was made as.
    pub persona_did: String,
    pub claims: Vec<DisclosedClaim>,
    /// What the verifier said it was for, if they said.
    pub purpose: Option<String>,
    /// Set when the release minted a durable credential — the one kind that is
    /// still live and still revocable, which is why it is named rather than
    /// folded in with the rest.
    pub durable_credential_id: Option<String>,
    pub disclosed_at: String,
}

impl DisclosureRow {
    fn from_wire(value: &Value) -> Self {
        let string_at = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_default()
        };
        Self {
            disclosure_id: string_at("disclosureId"),
            context_id: string_at("contextId"),
            verifier_did: string_at("verifierDid"),
            persona_did: string_at("personaDid"),
            claims: value
                .get("claims")
                .and_then(Value::as_array)
                .map(|claims| {
                    claims
                        .iter()
                        .map(|claim| DisclosedClaim {
                            claim_type: claim
                                .get("type")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            // An unrecorded rung reads as `whole`, the least
                            // private answer. The conservative reading for an
                            // unassessed disclosure is the one that overstates
                            // exposure — claiming an unlinkability the proof
                            // may not have provided is the error that cannot be
                            // undone.
                            rung: claim
                                .get("rung")
                                .and_then(Value::as_str)
                                .unwrap_or("whole")
                                .to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            purpose: value
                .get("purpose")
                .and_then(Value::as_str)
                .map(str::to_string),
            durable_credential_id: value
                .get("durableCredentialId")
                .and_then(Value::as_str)
                .map(str::to_string),
            disclosed_at: string_at("disclosedAt"),
        }
    }

    /// The facts as one line: `email.work (whole), age.over18 (yes/no only)`.
    ///
    /// The rung travels with every fact rather than being summarised, because
    /// there is no summary of a mixed release that is not misleading in one
    /// direction or the other — and because severity inverts intuition: a
    /// credential shown *whole* links the holder more than a fact they simply
    /// asserted.
    #[must_use]
    pub fn describe_claims(&self) -> String {
        if self.claims.is_empty() {
            return "no facts recorded".to_string();
        }
        self.claims
            .iter()
            .map(|c| format!("{} ({})", c.claim_type, rung_label(&c.rung)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What a person reads for a proof rung
/// (`design-docs/persona-vocabulary.md`). An unrecognised rung is shown
/// verbatim rather than mapped to a friendlier neighbour: the words carry a
/// privacy ordering, and guessing one would misstate how much left.
#[must_use]
fn rung_label(rung: &str) -> &str {
    match rung {
        "whole" => "whole",
        "selectiveDisclosure" => "partly",
        "derived" => "derived",
        "predicate" => "yes/no only",
        other => other,
    }
}

/// Every release, newest first, across every context.
///
/// `limit` caps the read: a history is append-only and unbounded, and a panel
/// that asked for all of it would grow slower for the whole life of the
/// account.
pub async fn history(
    client: &VtaClient,
    limit: std::num::NonZeroU64,
) -> Result<Vec<DisclosureRow>, OpenVTCError> {
    let value = client
        .persona_disclosure_history(None, None, None, None, Some(limit), None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona disclosure history failed: {e}")))?;

    let mut rows: Vec<DisclosureRow> = value
        .get("disclosures")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(DisclosureRow::from_wire).collect())
        .unwrap_or_default();
    // Newest first: the question a holder opens this with is almost always
    // "what just went out", not "what went out when I set the account up".
    rows.sort_by(|a, b| b.disclosed_at.cmp(&a.disclosed_at));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rungs are shown in the words the vocabulary fixes, and an unrecognised
    /// one is passed through rather than mapped to a friendlier neighbour — the
    /// four words carry a privacy ordering, so guessing would misstate how much
    /// of the fact left.
    #[test]
    fn a_fact_carries_its_rung_into_the_row() {
        let row = DisclosureRow::from_wire(&serde_json::json!({
            "disclosureId": "01D",
            "contextId": "ctx",
            "verifierDid": "did:webvh:example.com:acme",
            "claims": [
                { "type": "email.work", "rung": "whole" },
                { "type": "age.over18", "rung": "predicate" },
            ],
            "disclosedAt": "2026-09-06T10:00:00Z",
        }));
        assert_eq!(
            row.describe_claims(),
            "email.work (whole), age.over18 (yes/no only)"
        );
    }

    #[test]
    fn an_unknown_rung_is_shown_verbatim() {
        let row = DisclosureRow::from_wire(&serde_json::json!({
            "claims": [{ "type": "email.work", "rung": "someFutureRung" }],
        }));
        assert_eq!(row.describe_claims(), "email.work (someFutureRung)");
    }

    /// An unrecorded rung reads as `whole`.
    ///
    /// It is the least private of the four, and the conservative answer for an
    /// unassessed release is the one that *overstates* what left. Defaulting
    /// the other way would tell a holder a claim was proved without being
    /// handed over, when nothing in the record says so.
    #[test]
    fn an_unrecorded_rung_reads_as_the_least_private_one() {
        let row = DisclosureRow::from_wire(&serde_json::json!({
            "claims": [{ "type": "email.work" }],
        }));
        assert_eq!(row.claims[0].rung, "whole");
    }

    /// A release with nothing recorded says so, rather than rendering as a
    /// blank line that reads like a release of nothing.
    #[test]
    fn a_factless_record_says_so() {
        let row = DisclosureRow::default();
        assert_eq!(row.describe_claims(), "no facts recorded");
    }
}
