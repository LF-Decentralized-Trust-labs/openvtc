//! End-to-end resolve → verify for agent names, against a mock host.
//!
//! The consumer-side unit tests cover the decision logic in isolation (the spoof
//! guard with an injected resolver, error classification). These drive the whole
//! chain through a real [`DIDCacheClient`]: the `/@name` → 302 → DID redirect is
//! served by a wiremock server the resolver actually fetches, and the DID's
//! document is seeded into the cache so the mandatory `alsoKnownAs` verification
//! runs against a document we control — no live host, fully deterministic.
//!
//! Scheme note: over a plain-HTTP mock the agent name must carry an explicit
//! `http://`. A scheme-less name canonicalises to `https`, which would not hit
//! the mock — so both the input and the document's `alsoKnownAs` use the mock's
//! own `http://127.0.0.1:PORT` origin.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::did_common::{Document, DocumentBuilder};
use agent_names::HttpRedirectResolver;
use openvtc_core::agent_name::{
    IdentifierError, resolve_identifier, resolve_verified_name, verified_agent_name,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Two immutable `did:key`s so the seeded documents need no network resolution
/// and the "resolves to a different DID" spoof case has a concrete other DID.
const DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const OTHER_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

/// A `DIDCacheClient` whose only agent-name backend is a redirect resolver
/// relaxed for the loopback mock (plain HTTP + private addresses).
async fn client() -> DIDCacheClient {
    let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("build DID cache client");
    client.set_agent_name_resolvers(vec![Box::new(
        HttpRedirectResolver::new()
            .allow_insecure_http(true)
            .allow_private_addresses(true),
    )]);
    client
}

/// Seed `did`'s document into the cache, claiming `also_known_as`, so DID
/// resolution returns a document we control (no network).
async fn seed(client: &mut DIDCacheClient, did: &str, also_known_as: &[&str]) {
    let doc: Document = DocumentBuilder::new(did)
        .unwrap()
        .also_known_as_many(also_known_as.iter().copied())
        .build();
    client.add_did_document(did, doc).await;
}

/// Start a mock host that 302-redirects `GET /@{local}` to `did`.
async fn redirect_host(local: &str, did: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/@{local}")))
        .respond_with(ResponseTemplate::new(302).insert_header("location", did))
        .mount(&server)
        .await;
    server
}

/// The happy path, both directions: a name that redirects to `DID`, whose
/// document claims the name back, resolves as input *and* is returned for
/// display.
#[tokio::test]
async fn verified_name_resolves_and_displays() {
    let host = redirect_host("alice", DID).await;
    let name = format!("{}/@alice", host.uri()); // http://127.0.0.1:PORT/@alice
    let mut client = client().await;
    seed(&mut client, DID, &[&name]).await;

    // Input direction: a typed agent name resolves to the DID.
    let did = resolve_identifier(&client, &name)
        .await
        .expect("agent name resolves to a DID");
    assert_eq!(did, DID, "resolve_identifier returns the DID, not the name");

    // Display direction: the DID resolves back to the verified name (scheme-less).
    let shown = resolve_verified_name(&client, DID).await;
    assert_eq!(
        shown.as_deref(),
        Some(name.trim_start_matches("http://")),
        "resolve_verified_name returns the scheme-less name"
    );
}

/// The spoofing case, and the single most important guarantee: a document that
/// claims a name which actually redirects to a *different* DID must not be
/// displayed under that name.
#[tokio::test]
async fn name_pointing_at_a_different_did_is_rejected() {
    // The name redirects to OTHER_DID...
    let host = redirect_host("mallory", OTHER_DID).await;
    let name = format!("{}/@mallory", host.uri());
    let mut client = client().await;
    // ...but DID's document falsely claims that name.
    seed(&mut client, DID, &[&name]).await;
    // OTHER_DID's own document does not claim the name, so nothing legitimises it.
    seed(&mut client, OTHER_DID, &[]).await;

    let doc = client.resolve(DID).await.unwrap().doc;
    let shown = verified_agent_name(&client, DID, &doc).await;
    assert_eq!(
        shown, None,
        "a name resolving to a different DID must be rejected, not displayed"
    );
}

/// A document that claims no names yields no display name (the common case for a
/// DID with no agent name).
#[tokio::test]
async fn did_without_a_claimed_name_has_no_display_name() {
    let mut client = client().await;
    seed(&mut client, DID, &[]).await;
    assert_eq!(resolve_verified_name(&client, DID).await, None);
}

/// A name that redirects to a DID whose document does **not** claim it back
/// fails the mandatory `alsoKnownAs` check — surfaced as an agent-name error on
/// input, distinct from a network failure.
#[tokio::test]
async fn name_not_claimed_back_fails_to_resolve() {
    let host = redirect_host("alice", DID).await;
    let name = format!("{}/@alice", host.uri());
    let mut client = client().await;
    // DID resolves, but claims nothing — the reverse binding is missing.
    seed(&mut client, DID, &[]).await;

    match resolve_identifier(&client, &name).await {
        Err(IdentifierError::AgentName { .. }) => {}
        other => panic!("expected an AgentName error for an unclaimed name, got {other:?}"),
    }
}

/// A plain DID passes straight through `resolve_identifier` unchanged.
#[tokio::test]
async fn a_plain_did_passes_through() {
    let mut client = client().await;
    seed(&mut client, DID, &[]).await;
    let did = resolve_identifier(&client, DID)
        .await
        .expect("a resolvable DID passes through");
    assert_eq!(did, DID);
}
