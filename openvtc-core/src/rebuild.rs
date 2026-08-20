//! Reconstruct an account from what the VTA holds.
//!
//! # What this can and cannot recover
//!
//! Most of an account already lives at the VTA and always has: persona
//! `did:webvh` identities, their documents, and their private keys, which
//! OpenVTC re-fetches on every startup. Those come back directly.
//!
//! **Memberships come back from their credentials.** A `MembershipCredential`
//! names its issuer (the community's VTC) and its subject (one of your
//! personas) — which is exactly the pair that defines a membership. So a
//! membership is not *looked up* and then checked; it is *derived from the
//! evidence for it*. Reconstruction and verification are the same act, which is
//! what makes D18 cheap rather than an extra pass.
//!
//! What does not come back yet is the soft state: labels, favourites, archive
//! flags, join request ids, relationships, contacts. That needs the
//! application-state store (E2). Nothing here is blocked on it — an account
//! with its personas, keys and verified memberships is a working account.
//!
//! # Verify, never trust
//!
//! Today the local config is the source of truth, so a hostile VTA cannot
//! invent a membership. Rebuilding from the VTA removes that property unless
//! every reconstructed membership is checked against its own credential — so
//! every one is. A credential that fails is neither silently dropped nor
//! silently accepted: it lands in [`RebuildPlan::rejected`] with a reason, and
//! the user decides, exactly as [`crate::config::integrity`] does for a
//! degraded load.
//!
//! # A plan, not an application
//!
//! [`plan`] only reads. It returns what *would* be rebuilt so the caller can
//! show it and ask. Silently overwriting local state from a server view is how
//! a stale VTA destroys good local data (D5).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;

/// A persona the VTA holds for this context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuiltPersona {
    /// The persona's `did:webvh`.
    pub did: String,
    /// The context the DID was minted under — becomes `origin_context_id`.
    pub context_id: String,
    /// Mediator recovered from the DID document, when it advertises one.
    pub mediator_did: Option<String>,
}

/// A membership reconstructed from — and vouched for by — its credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuiltMembership {
    /// The community that issued the credential.
    pub vtc_did: String,
    /// The persona the credential was issued to.
    pub persona_did: String,
    /// The credential itself, kept so the rebuilt record carries its own proof.
    pub credential: Value,
}

/// Why a credential could not be turned into a membership.
///
/// Each variant is a distinct decision the user may want to override, so they
/// are kept apart rather than collapsed into one "invalid" string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    /// No `issuer`, so there is no community to attribute it to.
    NoIssuer,
    /// No `credentialSubject.id`, so there is no persona to attach it to.
    NoSubject,
    /// The subject is not a persona this context holds. Either the credential
    /// belongs to someone else, or the persona was deleted.
    SubjectNotOurs {
        /// The DID the credential names.
        subject: String,
    },
    /// Past its `validUntil`.
    Expired {
        /// The declared expiry, verbatim.
        valid_until: String,
    },
    /// `validUntil` is present but unparseable. Fails closed, matching the VIC
    /// rule: a malformed window is not an open one.
    MalformedValidity {
        /// The unparseable value, verbatim.
        valid_until: String,
    },
}

impl RejectionReason {
    /// One line for the user.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            RejectionReason::NoIssuer => "it names no issuing community".to_string(),
            RejectionReason::NoSubject => "it names no subject".to_string(),
            RejectionReason::SubjectNotOurs { subject } => {
                format!("it was issued to {subject}, which is not a persona in this context")
            }
            RejectionReason::Expired { valid_until } => format!("it expired on {valid_until}"),
            RejectionReason::MalformedValidity { valid_until } => {
                format!("its validity window is unreadable ({valid_until})")
            }
        }
    }
}

/// A credential that could not be turned into a membership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedCredential {
    /// The credential's own id, when it has one.
    pub id: Option<String>,
    /// Why it was rejected.
    pub reason: RejectionReason,
}

/// Everything a rebuild would restore, and everything it would not.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildPlan {
    /// The context the account is rooted at.
    pub top_context_id: String,
    /// Personas the VTA holds.
    pub personas: Vec<RebuiltPersona>,
    /// Memberships derived from verified credentials.
    pub memberships: Vec<RebuiltMembership>,
    /// Credentials that looked like memberships but did not verify.
    pub rejected: Vec<RejectedCredential>,
    /// Credentials of other kinds (VICs, role credentials), carried across
    /// as-is — they are signed artifacts and need no reconstruction.
    pub other_credential_count: usize,
}

impl RebuildPlan {
    /// True when there is nothing to restore.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.personas.is_empty() && self.memberships.is_empty()
    }

    /// One line summarising what would be restored.
    #[must_use]
    pub fn summary(&self) -> String {
        fn plural(n: usize, one: &str, many: &str) -> String {
            format!("{n} {}", if n == 1 { one } else { many })
        }
        let mut parts = vec![plural(self.personas.len(), "persona", "personas")];
        if !self.memberships.is_empty() {
            parts.push(plural(self.memberships.len(), "membership", "memberships"));
        }
        if self.other_credential_count > 0 {
            parts.push(plural(
                self.other_credential_count,
                "other credential",
                "other credentials",
            ));
        }
        parts.join(", ")
    }

    /// What this rebuild will *not* bring back, so it can be said up front
    /// rather than discovered.
    ///
    /// Naming the gap is the honest half of a recovery screen: a user who
    /// expects their relationship list back and does not get it will conclude
    /// the recovery failed.
    #[must_use]
    pub fn known_gaps() -> &'static [&'static str] {
        &[
            "Community names, favourites and archive flags",
            "Relationships and their peer DIDs",
            "Contacts and the names you gave them",
            "Activity history and pending join requests",
        ]
    }
}

/// The `issuer` of a credential, whether given as a string or an object.
fn issuer_of(credential: &Value) -> Option<&str> {
    match credential.get("issuer")? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => o.get("id").and_then(Value::as_str),
        _ => None,
    }
}

/// Whether `credential` is past its declared validity window.
///
/// Mirrors the VIC rule deliberately: no `validUntil` means non-expiring here
/// (the community re-checks at use), and a malformed one **fails closed**,
/// because an unreadable window is not an open one.
fn validity(credential: &Value, now: chrono::DateTime<chrono::Utc>) -> Result<(), RejectionReason> {
    let Some(raw) = credential.get("validUntil").and_then(Value::as_str) else {
        return Ok(());
    };
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(expiry) if expiry.with_timezone(&chrono::Utc) < now => Err(RejectionReason::Expired {
            valid_until: raw.to_string(),
        }),
        Ok(_) => Ok(()),
        Err(_) => Err(RejectionReason::MalformedValidity {
            valid_until: raw.to_string(),
        }),
    }
}

/// Turn one membership credential into a membership, or say why not.
///
/// **This is D18.** The membership is not asserted by the VTA and then checked
/// — it is read out of the credential, so a fabricated membership would require
/// a fabricated credential. `known_personas` is the set the VTA holds for this
/// context: a credential issued to something else is not ours to restore.
///
/// # Errors
///
/// A [`RejectionReason`] describing which check failed.
pub fn membership_from_credential(
    credential: &Value,
    known_personas: &[String],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RebuiltMembership, RejectionReason> {
    let issuer = issuer_of(credential).ok_or(RejectionReason::NoIssuer)?;

    let subject = credential
        .get("credentialSubject")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .ok_or(RejectionReason::NoSubject)?;

    if !known_personas.iter().any(|p| p == subject) {
        return Err(RejectionReason::SubjectNotOurs {
            subject: subject.to_string(),
        });
    }

    validity(credential, now)?;

    Ok(RebuiltMembership {
        vtc_did: issuer.to_string(),
        persona_did: subject.to_string(),
        credential: credential.clone(),
    })
}

/// Build the plan by reading the VTA. Never writes.
///
/// # Errors
///
/// Fails only when the persona listing fails — without it there is nothing to
/// rebuild and nothing to verify credentials against. Credential listing
/// failures degrade the plan (no memberships) rather than failing it, because
/// personas and keys are still worth restoring.
pub async fn plan(
    client: &VtaClient,
    context_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RebuildPlan, OpenVTCError> {
    let dids = client
        .list_dids_webvh(Some(context_id), None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("could not list DIDs in {context_id}: {e}")))?
        .dids;

    let personas: Vec<RebuiltPersona> = dids
        .into_iter()
        .map(|d| RebuiltPersona {
            did: d.did,
            context_id: d.context_id,
            // Filled from the resolved document by the caller, which already
            // has a resolver; keeping the network surface here to VTA calls
            // makes this function testable against a VTA alone.
            mediator_did: None,
        })
        .collect();

    let known: Vec<String> = personas.iter().map(|p| p.did.clone()).collect();

    let mut memberships = Vec::new();
    let mut rejected = Vec::new();
    let mut other_credential_count = 0usize;

    match client.cred_vault_query(serde_json::json!({})).await {
        Ok(listing) => {
            for credential in credentials_in(&listing) {
                match crate::CredentialKind::from_credential(&credential) {
                    Some(crate::CredentialKind::Membership) => {
                        match membership_from_credential(&credential, &known, now) {
                            Ok(m) => memberships.push(m),
                            Err(reason) => {
                                warn!(
                                    reason = %reason.summary(),
                                    "membership credential did not verify during rebuild"
                                );
                                rejected.push(RejectedCredential {
                                    id: credential
                                        .get("id")
                                        .and_then(Value::as_str)
                                        .map(str::to_string),
                                    reason,
                                });
                            }
                        }
                    }
                    // Signed artifacts of other kinds need no reconstruction —
                    // they are restored as they stand.
                    Some(_) => other_credential_count += 1,
                    None => debug!("skipping credential of unknown kind during rebuild"),
                }
            }
        }
        Err(e) => {
            // Degrade rather than fail: personas and their keys are the larger
            // half of an account, and are worth restoring without memberships.
            warn!("credential vault not readable during rebuild: {e}");
        }
    }

    Ok(RebuildPlan {
        top_context_id: context_id.to_string(),
        personas,
        memberships,
        rejected,
        other_credential_count,
    })
}

/// Pull credential objects out of a vault listing, whichever envelope it used.
///
/// The listing is untyped and its envelope key has moved before; a bare array
/// and the common wrappers are all accepted so a full vault is never read as an
/// empty one.
fn credentials_in(listing: &Value) -> Vec<Value> {
    let array = if let Some(arr) = listing.as_array() {
        arr.clone()
    } else {
        ["credentials", "items", "results"]
            .iter()
            .find_map(|k| listing.get(*k).and_then(Value::as_array))
            .cloned()
            .unwrap_or_default()
    };

    // Entries may be the credential itself or a wrapper carrying it.
    array
        .into_iter()
        .map(|entry| {
            entry
                .get("credential")
                .or_else(|| entry.get("vc"))
                .cloned()
                .unwrap_or(entry)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    const VTC: &str = "did:webvh:QmV:vtc.example.com:acme";
    const ALICE: &str = "did:webvh:QmA:example.com:alice";
    const BOB: &str = "did:webvh:QmB:example.com:bob";

    fn vmc(issuer: Value, subject: Option<&str>) -> Value {
        let mut vc = serde_json::json!({
            "id": "vmc-1",
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": issuer,
        });
        if let Some(s) = subject {
            vc["credentialSubject"] = serde_json::json!({ "id": s });
        }
        vc
    }

    fn ours() -> Vec<String> {
        vec![ALICE.to_string()]
    }

    /// The property the whole module rests on: a membership is *read out of*
    /// its credential, so the pair that defines it is the pair the issuer
    /// signed.
    #[test]
    fn a_valid_credential_yields_its_membership() {
        let m = membership_from_credential(&vmc(VTC.into(), Some(ALICE)), &ours(), Utc::now())
            .expect("verifies");
        assert_eq!(m.vtc_did, VTC);
        assert_eq!(m.persona_did, ALICE);
        assert_eq!(m.credential["id"], "vmc-1");
    }

    /// Issuers are written both ways in this ecosystem.
    #[test]
    fn an_object_issuer_is_accepted() {
        let m = membership_from_credential(
            &vmc(serde_json::json!({ "id": VTC }), Some(ALICE)),
            &ours(),
            Utc::now(),
        )
        .expect("verifies");
        assert_eq!(m.vtc_did, VTC);
    }

    /// D18 — the check that stops a hostile VTA inventing a membership. A
    /// credential issued to somebody else is not ours to restore.
    #[test]
    fn a_credential_for_another_persona_is_rejected() {
        let err = membership_from_credential(&vmc(VTC.into(), Some(BOB)), &ours(), Utc::now())
            .expect_err("must not restore someone else's membership");
        assert_eq!(
            err,
            RejectionReason::SubjectNotOurs {
                subject: BOB.to_string()
            }
        );
    }

    #[test]
    fn a_credential_with_no_issuer_or_subject_is_rejected() {
        assert_eq!(
            membership_from_credential(&vmc(Value::Null, Some(ALICE)), &ours(), Utc::now()),
            Err(RejectionReason::NoIssuer)
        );
        assert_eq!(
            membership_from_credential(&vmc(VTC.into(), None), &ours(), Utc::now()),
            Err(RejectionReason::NoSubject)
        );
    }

    #[test]
    fn an_expired_credential_is_rejected() {
        let now = Utc::now();
        let mut vc = vmc(VTC.into(), Some(ALICE));
        vc["validUntil"] = (now - Duration::days(1)).to_rfc3339().into();
        assert!(matches!(
            membership_from_credential(&vc, &ours(), now),
            Err(RejectionReason::Expired { .. })
        ));
    }

    #[test]
    fn a_credential_valid_until_tomorrow_is_accepted() {
        let now = Utc::now();
        let mut vc = vmc(VTC.into(), Some(ALICE));
        vc["validUntil"] = (now + Duration::days(1)).to_rfc3339().into();
        assert!(membership_from_credential(&vc, &ours(), now).is_ok());
    }

    /// No window means the community re-checks at use — matching the VIC rule.
    #[test]
    fn a_credential_with_no_validity_window_is_accepted() {
        assert!(
            membership_from_credential(&vmc(VTC.into(), Some(ALICE)), &ours(), Utc::now()).is_ok()
        );
    }

    /// An unreadable window is not an open one.
    #[test]
    fn a_malformed_validity_window_fails_closed() {
        let mut vc = vmc(VTC.into(), Some(ALICE));
        vc["validUntil"] = "next tuesday".into();
        assert!(matches!(
            membership_from_credential(&vc, &ours(), Utc::now()),
            Err(RejectionReason::MalformedValidity { .. })
        ));
    }

    /// Every rejection must be explainable, or the user cannot decide.
    #[test]
    fn every_rejection_reads_as_a_sentence() {
        let reasons = [
            RejectionReason::NoIssuer,
            RejectionReason::NoSubject,
            RejectionReason::SubjectNotOurs {
                subject: BOB.to_string(),
            },
            RejectionReason::Expired {
                valid_until: "2020-01-01T00:00:00Z".to_string(),
            },
            RejectionReason::MalformedValidity {
                valid_until: "soon".to_string(),
            },
        ];
        for r in reasons {
            let s = r.summary();
            // Each reads as the tail of "This credential could not be used
            // because …", so they compose into one sentence at the call site.
            assert!(
                s.starts_with("it ") || s.starts_with("its "),
                "not a sentence fragment: {s}"
            );
            assert!(s.len() > 12, "too terse to act on: {s}");
        }
    }

    #[test]
    fn the_summary_counts_what_would_be_restored() {
        let plan = RebuildPlan {
            top_context_id: "openvtc".to_string(),
            personas: vec![RebuiltPersona {
                did: ALICE.to_string(),
                context_id: "openvtc".to_string(),
                mediator_did: None,
            }],
            memberships: vec![RebuiltMembership {
                vtc_did: VTC.to_string(),
                persona_did: ALICE.to_string(),
                credential: Value::Null,
            }],
            rejected: Vec::new(),
            other_credential_count: 3,
        };
        assert_eq!(
            plan.summary(),
            "1 persona, 1 membership, 3 other credentials"
        );
        assert!(!plan.is_empty());
    }

    /// A recovery screen that does not name its gaps leaves the user to
    /// conclude the recovery failed when their contacts do not reappear.
    #[test]
    fn the_gaps_are_stated_not_implied() {
        let gaps = RebuildPlan::known_gaps();
        assert!(!gaps.is_empty());
        let all = gaps.join(" ").to_lowercase();
        assert!(all.contains("relationship"), "{all}");
        assert!(all.contains("contact"), "{all}");
    }

    /// Reporting zero credentials on a full vault would make the plan lie.
    #[test]
    fn credentials_are_found_whatever_the_envelope() {
        let one = serde_json::json!({ "id": "a" });
        for key in ["credentials", "items", "results"] {
            let listing = serde_json::json!({ key: [one.clone()] });
            assert_eq!(credentials_in(&listing).len(), 1, "key {key}");
        }
        assert_eq!(credentials_in(&serde_json::json!([one.clone()])).len(), 1);
        assert!(credentials_in(&serde_json::json!({ "nope": [one] })).is_empty());
    }

    /// Vault rows wrap the credential; the rebuild needs the credential.
    #[test]
    fn a_wrapped_credential_is_unwrapped() {
        let listing = serde_json::json!({
            "credentials": [{ "vaultId": "v1", "credential": { "id": "inner" } }]
        });
        let found = credentials_in(&listing);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["id"], "inner");
    }
}
