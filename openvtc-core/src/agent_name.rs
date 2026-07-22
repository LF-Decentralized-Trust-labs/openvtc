//! Agent names — human-memorable shortcuts that resolve to DIDs.
//!
//! An agent name is a URL whose path begins with `/@`
//! (`example.com/@alice`). It is **not** a DID method; it is a shortcut layer
//! in front of DID resolution. Resolution is three stages and the third is
//! mandatory:
//!
//! 1. the name URL redirects to a DID,
//! 2. the DID resolves to a document,
//! 3. **the document must claim the name back via `alsoKnownAs`.**
//!
//! Stage 1 is served by the name's own web server, so on its own it proves
//! nothing — anyone can publish a redirect at somebody else's DID. Stage 3 is
//! what makes the binding real: only the DID's controller can add an
//! `alsoKnownAs` entry. This module never surfaces a name that has not
//! completed all three, so a hostile DID cannot make the UI display it under a
//! name it does not actually own.
//!
//! All parsing, canonicalisation and `alsoKnownAs` matching delegates to the
//! [`agent_names`] crate. Canonicalisation is unspecified by the agent-name
//! spec, so two implementations that normalise differently disagree about
//! whether a name verifies — hand-rolling any of it is how the two sides drift.
//! This is the same rule the crate states for `didwebvh-rs`.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, errors::DIDCacheError};
use affinidi_tdk::did_common::Document;
use agent_names::AgentName;

/// How many `alsoKnownAs` candidates we are willing to round-trip per document
/// before giving up. A document that claims a name makes us do one network
/// resolve per candidate; a hostile document could list hundreds, so we cap it.
/// The first candidate that verifies wins, so a well-formed document (one or a
/// few names) is unaffected.
const MAX_CANDIDATES: usize = 4;

/// Cheap syntactic test — no network. A string containing the `/@` marker is
/// treated as an agent name; everything else is a DID (or nonsense) for the
/// resolver to judge.
#[must_use]
pub fn looks_like_agent_name(input: &str) -> bool {
    AgentName::looks_like_agent_name(input)
}

/// Resolve `did` to a **verified** agent name for display, or `None`.
///
/// Returns `Some(name)` only when a name the document claims round-trips: the
/// name resolves forward (via [`DIDCacheClient::resolve_any`], which performs
/// the mandatory `alsoKnownAs` check on the document *it* fetches) **and** that
/// forward resolution lands on the same `did` we are labelling. The returned
/// string is the scheme-less spelling (`example.com/@alice`).
///
/// Anything short of that — the name points at a different DID (a spoof), the
/// name no longer redirects, the host is unreachable — yields `None`, and the
/// caller falls back to showing the DID. A name is a mutable web redirect; the
/// verification is what stops the UI from becoming a phishing surface, so a
/// failure to verify is deliberately indistinguishable here from "no name".
pub async fn verified_agent_name(
    resolver: &DIDCacheClient,
    did: &str,
    doc: &Document,
) -> Option<String> {
    let candidates = agent_names::extract_agent_names(doc);
    verify_candidates(did, candidates, |name| async move {
        // resolve_any performs the mandatory `alsoKnownAs` check on the document
        // it fetches; we additionally require its resolved DID to be the one we
        // are labelling, which ties the name's forward redirect back to `did`.
        resolver.resolve_any(&name).await.ok().map(|resp| resp.did)
    })
    .await
}

/// The verification decision, factored out so the spoof guard is testable
/// without a live resolver: accept the first candidate whose forward resolution
/// lands on `did`; a candidate resolving to a *different* DID (a spoof) or not
/// resolving at all is skipped. Capped at [`MAX_CANDIDATES`].
///
/// `resolve` maps a name's canonical string to the DID it forward-resolves to
/// (`None` on any failure).
async fn verify_candidates<F, Fut>(
    did: &str,
    candidates: Vec<AgentName>,
    resolve: F,
) -> Option<String>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    for name in candidates.into_iter().take(MAX_CANDIDATES) {
        if resolve(name.as_str().to_string()).await.as_deref() == Some(did) {
            return Some(name.without_scheme().to_string());
        }
    }
    None
}

/// Why an identifier the user typed could not be turned into a DID.
///
/// The variants exist so the operator can tell the failure modes apart, rather
/// than getting one fixed hint for every failure. `resolve_any` collapses the
/// underlying [`agent_names::AgentNameError`] into a string, so [`Self::AgentName`]
/// carries that already-descriptive message (e.g. "did not redirect (HTTP 404)"
/// vs "is not authorized by DID" vs "resolves to the non-public address")
/// rather than re-deriving a typed variant by string-matching.
#[derive(Debug, thiserror::Error)]
pub enum IdentifierError {
    /// An agent name failed to resolve or verify. The message distinguishes the
    /// cause (not-found / not-a-DID / not-claimed-back / blocked address).
    #[error("agent name '{input}' could not be resolved: {detail}")]
    AgentName { input: String, detail: String },

    /// The resolver could not reach the network (timeout or transport failure).
    #[error("could not reach the network resolving '{input}'")]
    Unreachable { input: String },

    /// It was not an agent name, and it is not a resolvable DID either.
    #[error("'{input}' is not a resolvable DID")]
    InvalidDid { input: String },
}

/// Resolve user input that may be a DID **or** an agent name to a DID string.
///
/// A DID is passed straight through the resolver; an agent name goes through
/// the full three-stage resolve-and-verify. On success the caller should
/// persist the returned **DID**, never the name — a name is a mutable web
/// redirect, and persisting one would let a redirect change silently repoint a
/// saved identity.
pub async fn resolve_identifier(
    resolver: &DIDCacheClient,
    input: &str,
) -> Result<String, IdentifierError> {
    let input = input.trim();
    match resolver.resolve_any(input).await {
        Ok(resp) => Ok(resp.did),
        Err(e) => Err(classify(input, e)),
    }
}

/// Map a [`DIDCacheError`] onto the operator-facing [`IdentifierError`], using
/// whether the input looked like a name to disambiguate the parse/DID buckets.
fn classify(input: &str, err: DIDCacheError) -> IdentifierError {
    let input = input.to_string();
    match err {
        // `AgentNameError` is gated behind the cache-sdk's `agent-names`
        // feature, which this workspace always enables (see the root
        // `Cargo.toml`), so the variant is always present in our build.
        DIDCacheError::AgentNameError(detail) => IdentifierError::AgentName { input, detail },
        DIDCacheError::NetworkTimeout | DIDCacheError::TransportError(_) => {
            IdentifierError::Unreachable { input }
        }
        // A DID-parse / method / config failure. If the user typed a name, the
        // name-shaped failure is the useful framing; otherwise it is a bad DID.
        other => {
            if looks_like_agent_name(&input) {
                IdentifierError::AgentName {
                    input,
                    detail: other.to_string(),
                }
            } else {
                IdentifierError::InvalidDid { input }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    fn name(s: &str) -> AgentName {
        AgentName::parse(s).expect("valid agent name in test")
    }

    /// The spoof case, and the single most important behaviour in this module:
    /// a document claims `example.com/@alice`, but that name forward-resolves to
    /// a *different* DID. It must NOT be displayed as our name.
    #[tokio::test]
    async fn rejects_name_resolving_to_a_different_did() {
        let got = verify_candidates(
            "did:webvh:us:example.com",
            vec![name("example.com/@alice")],
            // The name points at somebody else's DID.
            |_| async { Some("did:webvh:them:evil.example".to_string()) },
        )
        .await;
        assert_eq!(
            got, None,
            "a name pointing at a different DID must be rejected"
        );
    }

    /// The happy path: the claimed name forward-resolves back to the DID we are
    /// labelling. Returned scheme-less.
    #[tokio::test]
    async fn accepts_name_that_round_trips() {
        let did = "did:webvh:us:example.com";
        let got = verify_candidates(did, vec![name("example.com/@alice")], |n| {
            let did = did.to_string();
            async move {
                assert_eq!(n, "https://example.com/@alice");
                Some(did)
            }
        })
        .await;
        assert_eq!(got.as_deref(), Some("example.com/@alice"));
    }

    /// A name that does not resolve at all (host down, no redirect) yields no
    /// name rather than an error — the caller falls back to the DID.
    #[tokio::test]
    async fn skips_unresolvable_name() {
        let got = verify_candidates(
            "did:webvh:us:example.com",
            vec![name("example.com/@alice")],
            |_| async { None },
        )
        .await;
        assert_eq!(got, None);
    }

    /// A document that claims many names must not trigger an unbounded number of
    /// network resolves; verification stops at MAX_CANDIDATES.
    #[tokio::test]
    async fn caps_the_number_of_candidates_verified() {
        let calls = Cell::new(0usize);
        let candidates: Vec<AgentName> = (0..(MAX_CANDIDATES + 5))
            .map(|i| name(&format!("example.com/@name{i}")))
            .collect();
        let got = verify_candidates("did:webvh:us:example.com", candidates, |_| {
            calls.set(calls.get() + 1);
            // None of them match, so every attempt (up to the cap) is made.
            async { Some("did:webvh:other:host".to_string()) }
        })
        .await;
        assert_eq!(got, None);
        assert_eq!(calls.get(), MAX_CANDIDATES, "must not resolve past the cap");
    }

    /// The first verifying candidate wins; later ones are not resolved.
    #[tokio::test]
    async fn stops_at_first_verified_candidate() {
        let did = "did:webvh:us:example.com";
        let calls = Cell::new(0usize);
        let candidates = vec![name("example.com/@first"), name("example.com/@second")];
        let got = verify_candidates(did, candidates, |_| {
            calls.set(calls.get() + 1);
            let did = did.to_string();
            async move { Some(did) }
        })
        .await;
        assert_eq!(got.as_deref(), Some("example.com/@first"));
        assert_eq!(calls.get(), 1, "must short-circuit on the first match");
    }

    #[test]
    fn recognises_agent_names() {
        assert!(looks_like_agent_name("example.com/@alice"));
        assert!(looks_like_agent_name("https://connect.me/@bob"));
        assert!(looks_like_agent_name(
            "firstperson.network/@drummond/h2hsummit"
        ));
    }

    #[test]
    fn rejects_non_agent_names() {
        assert!(!looks_like_agent_name("did:webvh:QmScid:example.com"));
        assert!(!looks_like_agent_name("did:web:example.com"));
        // An email is not an agent name — the marker is `/@`, not `@`.
        assert!(!looks_like_agent_name("alice@example.com"));
        // A bare handle with no host is not resolvable and not an agent name.
        assert!(!looks_like_agent_name("@alice"));
        assert!(!looks_like_agent_name(""));
    }

    /// A non-name, non-DID string that the resolver rejects with a DID-parse
    /// error surfaces as `InvalidDid`, not as an agent-name failure.
    #[test]
    fn classify_non_name_did_error_is_invalid_did() {
        let err = classify("not-a-did", DIDCacheError::DIDError("bad".into()));
        assert!(matches!(err, IdentifierError::InvalidDid { .. }));
    }

    /// The same DID-parse error, when the input *looked* like a name, is framed
    /// as an agent-name failure so the operator gets the name-shaped hint.
    #[test]
    fn classify_name_shaped_parse_error_is_agent_name() {
        let err = classify("example.com/@alice", DIDCacheError::DIDError("bad".into()));
        assert!(matches!(err, IdentifierError::AgentName { .. }));
    }

    /// Network failures are their own bucket regardless of input shape, so the
    /// operator can tell "the host is down" from "the name isn't claimed".
    #[test]
    fn classify_network_errors_are_unreachable() {
        assert!(matches!(
            classify("example.com/@alice", DIDCacheError::NetworkTimeout),
            IdentifierError::Unreachable { .. }
        ));
        assert!(matches!(
            classify("did:web:x", DIDCacheError::TransportError("refused".into())),
            IdentifierError::Unreachable { .. }
        ));
    }

    /// The agent-name resolver's descriptive message is preserved verbatim, so
    /// distinct causes (not-found vs not-claimed vs blocked) reach the user.
    #[test]
    fn classify_agent_name_error_preserves_detail() {
        let err = classify(
            "example.com/@alice",
            DIDCacheError::AgentNameError(
                "Agent name 'example.com/@alice' did not redirect (HTTP 404)".into(),
            ),
        );
        match err {
            IdentifierError::AgentName { detail, .. } => {
                assert!(detail.contains("did not redirect"), "detail was: {detail}");
            }
            other => panic!("expected AgentName, got {other:?}"),
        }
    }
}
