//! End-to-end DIDComm exchange over a real in-process mediator.
//!
//! Uses the [`MockMediator`] harness to spin up the real
//! `affinidi-messaging-mediator` server, registers two DIDComm
//! profiles (Alice + Bob) through `DIDCommService`, and verifies
//! that a message Alice sends through the mediator is delivered to
//! Bob's handler.
//!
//! Status: the mediator boots and binds, both profiles construct,
//! and `DIDCommService::start` returns successfully. The connect
//! step then loops on `AuthenticationAbort("No service endpoint
//! found. DID doesn't contain a #auth service")` — the SDK requires
//! the mediator's DID document to publish a service whose id ends
//! in `#auth`, which `affinidi-tdk 0.6`'s `generate_did_peer` helper
//! doesn't expose. `affinidi-tdk 0.7` exposes
//! `generate_did_peer_with_services` for exactly this case; bumping
//! the workspace TDK or going through `affinidi-did-common` directly
//! is the next step. The body below is intentionally compiled and
//! linked so the API stays current; it runs only under
//! `cargo test -- --ignored` and currently fails the assertion at
//! the `wait_connected` line.

mod common;

use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, HandlerContext,
    ListenerConfig, RestartPolicy, RetryConfig, Router, handler_fn, ignore_handler,
    trust_ping_handler,
};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use common::{MockMediator, TestProfile};

const TEST_MESSAGE_TYPE: &str = "https://example.com/openvtc-test/1.0/echo";

/// Build a `DIDCommService` for `profile` with a router that captures
/// any inbound `TEST_MESSAGE_TYPE` payload into `inbound_tx`. Returns
/// the running service plus the cancellation token guarding its
/// background tasks.
async fn start_profile_service(
    profile: TestProfile,
    inbound_tx: mpsc::UnboundedSender<Message>,
) -> Result<(DIDCommService, CancellationToken), Box<dyn std::error::Error + Send + Sync>> {
    let TestProfile {
        alias,
        did,
        secrets,
        mediator_did,
    } = profile;

    let tdk_profile = TDKProfile::new(&alias, &did, Some(&mediator_did), secrets);

    let config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: alias.clone(),
            profile: tdk_profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig::default(),
            },
            // Use the default acl_mode (None) — the mediator's own
            // global mode (ExplicitDeny by default) is what governs
            // whether new accounts are accepted.
            ..Default::default()
        }],
    };

    let capture_handler = handler_fn(move |_ctx: HandlerContext, msg: Message| {
        let tx = inbound_tx.clone();
        async move {
            let _ = tx.send(msg);
            Ok::<Option<DIDCommResponse>, DIDCommServiceError>(None)
        }
    });

    let router = Router::new()
        // Built-in trust-ping responder so the mediator sees a connected
        // and well-behaved listener.
        .route(
            affinidi_messaging_didcomm_service::TRUST_PING_TYPE,
            handler_fn(trust_ping_handler),
        )?
        // Drop pickup-status messages — the SDK handles them internally
        // but the router still gets them as a courtesy event.
        .route(
            affinidi_messaging_didcomm_service::MESSAGE_PICKUP_STATUS_TYPE,
            handler_fn(ignore_handler),
        )?
        // Capture our test-protocol message into the channel so the
        // test harness can assert on it.
        .route(TEST_MESSAGE_TYPE, capture_handler)?;

    let shutdown = CancellationToken::new();
    let service = DIDCommService::start(config, router, shutdown.clone()).await?;
    Ok((service, shutdown))
}

/// Install a tracing subscriber so the mediator's logs surface in
/// `cargo test -- --nocapture`. Idempotent — subsequent calls are
/// no-ops once a global subscriber is installed.
fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "WIP: needs `#auth` service entry on the mediator's DID document — see module docs"]
async fn alice_sends_to_bob_via_mediator() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");

    let alice = mediator.make_profile("alice").expect("alice profile");
    let bob = mediator.make_profile("bob").expect("bob profile");

    // Capture both DIDs before the profiles get moved into their
    // respective service configs.
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    // Bob comes up first so his pickup queue is ready when Alice
    // pushes to the mediator.
    let (bob_inbound_tx, mut bob_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (bob_service, _bob_shutdown) = start_profile_service(bob, bob_inbound_tx)
        .await
        .expect("bob service");

    // Alice's inbound channel is unused for this direction — we only
    // assert delivery on Bob's side — but the service still needs it.
    let (alice_inbound_tx, _alice_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (alice_service, _alice_shutdown) = start_profile_service(alice, alice_inbound_tx)
        .await
        .expect("alice service");

    // Wait for both listeners to settle into Connected state. The
    // SDK's wait_connected drains pickup-status, completes auth, and
    // resolves once messages can flow.
    bob_service
        .wait_connected("bob", Duration::from_secs(15))
        .await
        .expect("bob connect");
    alice_service
        .wait_connected("alice", Duration::from_secs(15))
        .await
        .expect("alice connect");

    // Build a plaintext DIDComm message from Alice to Bob in our
    // test protocol. The DIDCommService send path packs (encrypts)
    // it for the recipient and routes it through the mediator.
    let payload = serde_json::json!({"hello": "from-alice"});
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        TEST_MESSAGE_TYPE.to_string(),
        payload,
    )
    .from(alice_did)
    .to(bob_did.clone())
    .finalize();

    alice_service
        .send_message_with_retry("alice", msg, &bob_did, 3, Duration::from_secs(2))
        .await
        .expect("alice send");

    // Mediator picks it up, queues for Bob, Bob's listener pulls it
    // and dispatches to our capture handler. Allow a generous timeout
    // for the round-trip through the message-pickup protocol.
    let received = tokio::time::timeout(Duration::from_secs(15), bob_inbound_rx.recv())
        .await
        .expect("bob received within 15s")
        .expect("inbound channel still open");

    assert_eq!(received.typ, TEST_MESSAGE_TYPE);
    assert_eq!(
        received.body.get("hello").and_then(|v| v.as_str()),
        Some("from-alice")
    );

    // Tear down — handles drop on scope exit; explicit cancellation
    // would race the background flush.
    let _ = (alice_service, bob_service);
    drop(mediator);
}
