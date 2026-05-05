//! Smoke test for the in-process mediator harness.
//!
//! Asserts that [`common::MockMediator::start`] actually brings up an
//! HTTP server we can reach and that the discovery endpoint
//! (`well-known/did.json`) responds with a DID Document. This is the
//! base-case any subsequent integration test (relationship E2E, VRC,
//! trust-ping round-trip…) builds on.
//!
//! Marked `#[ignore]` because spawning the mediator is several seconds
//! — too slow for the default `cargo test`. CI runs ignored tests in
//! the dedicated coverage job (`cargo llvm-cov ... -- --include-ignored`).

mod common;

use common::MockMediator;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spins up a real mediator binary in-process"]
async fn mediator_starts_and_serves_well_known() {
    let mediator = MockMediator::start().await.expect("mediator start");

    // Sanity: the handle should report a real bound port.
    assert_ne!(mediator.handle.bound_addr().port(), 0);
    assert!(
        mediator.mediator_url.starts_with("http://127.0.0.1:"),
        "expected loopback HTTP url, got {}",
        mediator.mediator_url
    );

    // Reach the well-known DID document. 200 means it's published;
    // 404 means a different discovery scheme — either way the server
    // is up. Anything 5xx means the mediator broke at startup.
    let well_known = format!(
        "{}.well-known/did.json",
        mediator
            .mediator_url
            .trim_end_matches('/')
            .trim_end_matches("mediator/v1")
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let resp = client
        .get(&well_known)
        .send()
        .await
        .expect("well-known request");
    assert!(
        resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND,
        "mediator HTTP not reachable: {}",
        resp.status()
    );

    assert!(
        mediator.mediator_did.starts_with("did:peer:"),
        "mediator DID looks wrong: {}",
        mediator.mediator_did
    );
    // Pre-registered profiles should also have did:peer identifiers.
    assert!(mediator.alice.did.starts_with("did:peer:"));
    assert!(mediator.bob.did.starts_with("did:peer:"));
}
