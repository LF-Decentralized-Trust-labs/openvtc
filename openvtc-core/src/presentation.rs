//! Answering a verifier's DCQL query: what would be disclosed, and — only after
//! the holder agrees — the signed `vp_token` that discloses it.
//!
//! This is the client half of the VTC's *verified* join path. The VTC issues a
//! single-use `credential-exchange/query` carrying a DCQL
//! `presentation_definition`, a `nonce` and a `purpose`; the holder answers with
//! `credential-exchange/present` carrying a `vp_token`, which the VTC verifies
//! cryptographically (holder proof bound to that nonce and audience) before
//! running its join policy.
//!
//! Deliberately **not** the join-submit `vp` slot. That field is opaque JSON to
//! the VTC — its `presentation.verified` rests on a route-layer signature, not on
//! VP cryptography — so a real presentation there would be correct work with no
//! security value. The query/present exchange is the path that actually verifies.
//!
//! ## The consent gate is the module's shape, not a flag
//!
//! Disclosure is split into two calls that cannot be collapsed:
//!
//! 1. [`evaluate_query`] decides *what would be disclosed* and returns a
//!    [`DisclosureRequest`] — verifier, purpose, and every credential and claim
//!    path that answering would reveal. It signs nothing and sends nothing.
//! 2. [`present`] consumes that request **by value** and produces the signed
//!    `vp_token`.
//!
//! So there is no path to a `vp_token` that does not first produce the summary a
//! human is shown. A future edit can still call both in a row, but it has to do
//! so deliberately — the ordering is not an `if` someone can forget. Credential
//! disclosure is exactly the operation that should not be reachable by accident.

use serde_json::Value;
use vta_sdk::vp::{CandidateSet, HeldCredential, VpError, build_vp_token, select_credentials};

use crate::config::account::CommunityRecord;

/// The DCQL `format` for the W3C Data-Integrity credentials this client holds.
///
/// Everything in the wallet is `eddsa-jcs-2022` Data Integrity — issued VMCs and
/// received VRCs alike — so a query asking for `dc+sd-jwt` or `mso_mdoc` matches
/// nothing here, which is the correct answer rather than an error.
const LDP_VC: &str = "ldp_vc";

/// One credential a [`DisclosureRequest`] would reveal, in terms a person can
/// weigh: what it is and who issued it.
///
/// Built for display. The machine-readable selection stays inside the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureItem {
    /// Which credential-query in the DCQL this answers.
    pub credential_query_id: String,
    /// The credential's `type` (minus the generic `VerifiableCredential`), or the
    /// wallet id when it carries no usable type.
    pub kind: String,
    /// Issuer DID, if the credential names one.
    pub issuer: Option<String>,
}

// Deliberately no "requested claims" field. The DCQL match does carry the paths
// the verifier asked for, but `eddsa-jcs-2022` credentials cannot be redacted, so
// the credential is presented **whole** regardless. Listing the asked-for claims
// in a consent prompt would tell the user they are revealing a subset when they
// are revealing everything — the one misstatement this prompt must not make. See
// [`DisclosureRequest::discloses_whole_credentials`].

/// A verifier's request, evaluated against what the holder actually holds, ready
/// to put in front of a person.
///
/// Produced by [`evaluate_query`]; consumed by [`present`].
#[derive(Debug, Clone)]
pub struct DisclosureRequest {
    /// The DID asking. Render it through the usual name resolution before showing
    /// it — a raw DID tells the operator nothing about who is asking.
    pub verifier_did: String,
    /// Why the verifier says it wants this. Purpose binding is never optional in
    /// the protocol, so this is always shown.
    pub purpose: String,
    /// What answering would reveal.
    pub items: Vec<DisclosureItem>,
    /// The verifier's single-use challenge, carried through to [`present`].
    nonce: String,
    /// The matched selection. Private: the only way to act on it is [`present`].
    selection: CandidateSet,
}

impl DisclosureRequest {
    /// Always `true` today, and stated explicitly rather than assumed.
    ///
    /// Data-Integrity credentials cannot be selectively redacted, so accepting
    /// discloses each matched credential **in full**, not merely the claims the
    /// verifier asked for. A consent prompt that implied otherwise would
    /// misdescribe the very thing the user is consenting to.
    #[must_use]
    pub fn discloses_whole_credentials(&self) -> bool {
        true
    }
}

/// Why a query could not be answered.
#[derive(Debug, thiserror::Error)]
pub enum PresentationError {
    /// The query was malformed, or nothing held satisfies it. Not an error state
    /// for the user to fix — a community may simply be asking for a credential
    /// this persona does not have.
    #[error("no held credential satisfies the request: {0}")]
    NoMatch(String),
    /// Signing or assembling the presentation failed.
    #[error("could not build the presentation: {0}")]
    Build(String),
}

/// Gather everything this persona could present to a verifier.
///
/// Two sources, both already on disk:
///
/// - the community-issued credentials on `membership` (the MembershipCredential
///   and any role credentials), and
/// - the VRCs received from relationship counterparties.
///
/// Ids are stable within a call and meaningful in logs (`community:<kind>`,
/// `vrc:<id>`) rather than opaque indices, so a match that selects the wrong
/// credential is diagnosable from the summary alone.
#[must_use]
pub fn held_credentials(
    membership: Option<&CommunityRecord>,
    vrcs: &crate::vrc::Vrcs,
) -> Vec<HeldCredential> {
    let mut held = Vec::new();

    if let Some(community) = membership {
        for (kind, credential) in &community.credentials {
            held.push(HeldCredential {
                id: format!("community:{}", kind.config_key()),
                format: LDP_VC.to_string(),
                claims: credential.clone(),
                vct: None,
                doctype: None,
                supports_holder_binding: true,
                vc: credential.clone(),
            });
        }
    }

    for per_remote in vrcs.values() {
        for (vrc_id, credential) in per_remote {
            let Ok(claims) = serde_json::to_value(credential.as_ref()) else {
                continue;
            };
            held.push(HeldCredential {
                id: format!("vrc:{vrc_id}"),
                format: LDP_VC.to_string(),
                claims: claims.clone(),
                vct: None,
                doctype: None,
                supports_holder_binding: true,
                vc: claims,
            });
        }
    }

    held
}

/// Evaluate a verifier's DCQL query against `held`, producing the summary a
/// person is shown before anything is signed or sent.
///
/// Signs nothing, sends nothing, and reveals nothing. `Err(NoMatch)` when the
/// wallet cannot satisfy the query — the honest answer, and not something the
/// user should be prompted about.
pub fn evaluate_query(
    presentation_definition: &Value,
    held: &[HeldCredential],
    verifier_did: &str,
    purpose: &str,
    nonce: &str,
) -> Result<DisclosureRequest, PresentationError> {
    let selection = select_credentials(presentation_definition, held)
        .map_err(|e| PresentationError::NoMatch(e.to_string()))?;

    let items = selection
        .entries
        .iter()
        .map(|selected| DisclosureItem {
            credential_query_id: selected.credential_query_id.clone(),
            kind: credential_kind(&selected.credential),
            issuer: issuer_of(&selected.credential.claims),
        })
        .collect();

    Ok(DisclosureRequest {
        verifier_did: verifier_did.to_string(),
        purpose: purpose.to_string(),
        items,
        nonce: nonce.to_string(),
        selection,
    })
}

/// Build the signed `vp_token` for an **approved** request.
///
/// Takes the request by value: consent is spent, and a stale approval cannot be
/// replayed against a later challenge. `audience` is the verifier the token is
/// bound to — pass the community's DID, which is what the VTC checks.
pub async fn present(
    request: DisclosureRequest,
    holder_signer: &affinidi_tdk::secrets_resolver::secrets::Secret,
    audience: &str,
) -> Result<Value, PresentationError> {
    build_vp_token(&request.selection, holder_signer, &request.nonce, audience)
        .await
        .map_err(|e: VpError| PresentationError::Build(e.to_string()))
}

/// The credential's `type`, minus the generic `VerifiableCredential` every VC
/// carries. Falls back to the wallet id, which is never empty.
fn credential_kind(credential: &HeldCredential) -> String {
    credential
        .claims
        .get("type")
        .and_then(Value::as_array)
        .and_then(|types| {
            types
                .iter()
                .filter_map(Value::as_str)
                .find(|t| *t != "VerifiableCredential")
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| credential.id.clone())
}

/// The issuer DID, accepting both shapes the wild uses: a bare string, or an
/// object with an `id`.
fn issuer_of(claims: &Value) -> Option<String> {
    match claims.get("issuer")? {
        Value::String(did) => Some(did.clone()),
        Value::Object(map) => map.get("id")?.as_str().map(ToString::to_string),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VERIFIER: &str = "did:webvh:QmScidVtc:vtc.example:acme";
    const ISSUER: &str = "did:webvh:QmScidIssuer:issuer.example:acme";

    fn membership_vc() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": ISSUER,
            "credentialSubject": { "id": "did:key:zHolder", "role": "member" },
        })
    }

    fn held(id: &str, vc: Value) -> HeldCredential {
        HeldCredential {
            id: id.to_string(),
            format: LDP_VC.to_string(),
            claims: vc.clone(),
            vct: None,
            doctype: None,
            supports_holder_binding: true,
            vc,
        }
    }

    /// A DCQL query asking for a `MembershipCredential`.
    fn membership_query() -> Value {
        json!({
            "credentials": [{
                "id": "membership",
                "format": "ldp_vc",
                "claims": [{ "path": ["credentialSubject", "role"] }],
            }],
        })
    }

    #[test]
    fn a_matching_credential_is_summarised_for_the_prompt() {
        let held = vec![held("community:membership_credential", membership_vc())];
        let request = evaluate_query(
            &membership_query(),
            &held,
            VERIFIER,
            "Verify your membership to join",
            "nonce-1",
        )
        .expect("the held membership credential satisfies the query");

        assert_eq!(request.verifier_did, VERIFIER);
        assert_eq!(request.purpose, "Verify your membership to join");
        assert_eq!(request.items.len(), 1);
        assert_eq!(request.items[0].kind, "MembershipCredential");
        assert_eq!(request.items[0].issuer.as_deref(), Some(ISSUER));
    }

    /// A community asking for something this persona does not hold is a normal
    /// outcome, not a fault — and must not reach the user as a prompt.
    #[test]
    fn an_unsatisfiable_query_does_not_match() {
        let held = vec![held("community:membership_credential", membership_vc())];
        let query = json!({
            "credentials": [{
                "id": "passport",
                "format": "ldp_vc",
                "claims": [{ "path": ["credentialSubject", "passportNumber"] }],
            }],
        });

        assert!(matches!(
            evaluate_query(&query, &held, VERIFIER, "why", "nonce-1"),
            Err(PresentationError::NoMatch(_))
        ));
    }

    /// An empty wallet cannot answer anything. Asserted separately from the
    /// unsatisfiable case because an empty-input crash would be an easy bug.
    #[test]
    fn an_empty_wallet_matches_nothing() {
        assert!(matches!(
            evaluate_query(&membership_query(), &[], VERIFIER, "why", "n"),
            Err(PresentationError::NoMatch(_))
        ));
    }

    /// The prompt must be able to say "in full" truthfully. If a selective
    /// disclosure format is ever added, this test fails and forces the prompt
    /// wording to be revisited with it.
    #[test]
    fn disclosure_is_whole_credential() {
        let held = vec![held("community:membership_credential", membership_vc())];
        let request =
            evaluate_query(&membership_query(), &held, VERIFIER, "why", "n").expect("matches");
        assert!(request.discloses_whole_credentials());
    }

    /// A credential with no specific type still renders something a person can
    /// read, rather than an empty row in the consent prompt.
    #[test]
    fn a_typeless_credential_falls_back_to_its_wallet_id() {
        let vc = json!({
            "type": ["VerifiableCredential"],
            "credentialSubject": { "role": "member" },
        });
        let held = vec![held("vrc:abc123", vc)];
        let request = evaluate_query(
            &json!({
                "credentials": [{
                    "id": "any",
                    "format": "ldp_vc",
                    "claims": [{ "path": ["credentialSubject", "role"] }],
                }],
            }),
            &held,
            VERIFIER,
            "why",
            "n",
        )
        .expect("matches");
        assert_eq!(request.items[0].kind, "vrc:abc123");
        assert_eq!(request.items[0].issuer, None);
    }

    /// Both issuer shapes appear in the wild; neither should read as "unknown".
    #[test]
    fn an_object_issuer_is_read_as_well_as_a_string_one() {
        assert_eq!(
            issuer_of(&json!({ "issuer": { "id": ISSUER, "name": "Acme" } })).as_deref(),
            Some(ISSUER)
        );
        assert_eq!(
            issuer_of(&json!({ "issuer": ISSUER })).as_deref(),
            Some(ISSUER)
        );
        assert_eq!(issuer_of(&json!({})), None);
    }
}
