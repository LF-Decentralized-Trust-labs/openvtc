//! End-to-end relationship establishment over a real in-process mediator.
//!
//! This file lays out the intended shape for the B11 integration tests
//! identified in the v0.2.0 review:
//!
//!   1. Two `TDKProfile` instances (Alice + Bob), each with a `did:peer`
//!      identity, register with the [`MockMediator`] from `tests/common`.
//!   2. Alice sends a `RelationshipRequest` DIDComm message addressed to
//!      Bob's persona DID; the mediator routes it to Bob's pickup queue.
//!   3. Bob's openvtc-core message dispatcher (`process_inbound_message`)
//!      consumes the message and queues a task in the inbox.
//!   4. Bob's UI accept handler (`accept_relationship_request`) builds
//!      the acceptance message and sends it; the mediator routes back
//!      to Alice.
//!   5. Alice's dispatcher consumes the acceptance and transitions her
//!      relationship state to `Established`. A subsequent trust-ping
//!      round-trips the same way.
//!   6. Both sides assert the resulting `Config.private.relationships`
//!      contents — same `task_id`, `Established` on both ends, contact
//!      aliases populated.
//!
//! Implementation status:
//!   * Mediator harness is in place (`tests/common/mod.rs`, smoke
//!     test `tests/mediator_smoke.rs` passes).
//!   * Profile-registration / mediator-account-provisioning step is
//!     non-trivial — the mediator gates new accounts on an admin
//!     credential and requires an ACL push before message routing
//!     works. That's the next layer of harness work and is intentionally
//!     deferred so the piece below can land in tractable steps.
//!
//! Once the profile-registration helper exists in `tests/common`, the
//! body of [`relationship_request_to_established_round_trip`] can fill
//! in. The test is `#[ignore]` until then so the default `cargo test`
//! suite stays green and CI doesn't run a half-finished integration
//! test.

mod common;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "WIP: needs MockMediator profile-registration helper before the body can drive a real round-trip"]
async fn relationship_request_to_established_round_trip() {
    let _mediator = common::MockMediator::start().await.expect("mediator start");

    // TODO(B11): wire up Alice + Bob TDKProfiles against `_mediator`,
    // exchange a relationship request, assert both sides land at
    // `RelationshipState::Established`. Tracked in the v0.2.0 review
    // backlog under "Tier-3 integration tests".
}
