//! End-to-end DIDComm exchange over a real in-process mediator.
//!
//! Uses the [`MockMediator`] harness to spin up the real
//! `affinidi-messaging-mediator` server, registers two DIDComm
//! profiles (Alice + Bob) through `DIDCommService`, and verifies
//! that messages Alice sends through the mediator are delivered to
//! Bob's handler. Two scenarios:
//!
//!   * `alice_sends_to_bob_via_mediator` — generic test-protocol
//!     payload, asserts the message lands at Bob's router.
//!   * `relationship_request_round_trip` — sends a real openvtc-core
//!     `RelationshipRequestBody` and asserts Bob can deserialise it,
//!     proving the harness drives the actual production protocol
//!     types and not just opaque JSON.
//!
//! All `#[ignore]`'d because the mediator boot + auth handshake +
//! WS connect adds ~1s. CI's coverage job runs them via
//! `cargo llvm-cov ... -- --include-ignored`.

mod common;

use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, HandlerContext,
    ListenerConfig, RestartPolicy, RetryConfig, Router, handler_fn, ignore_handler,
    trust_ping_handler,
};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use openvtc_core::protocol_urls::RELATIONSHIP_REQUEST;
use openvtc_core::relationships::RelationshipRequestBody;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use common::{MockMediator, TestProfile};

const TEST_MESSAGE_TYPE: &str = "https://example.com/openvtc-test/1.0/echo";

/// Build a `DIDCommService` for `profile` with a router that captures
/// any inbound message in `routes` into `inbound_tx`. Returns the
/// running service plus the cancellation token guarding its background
/// tasks.
async fn start_profile_service(
    profile: TestProfile,
    routes: &[&'static str],
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

    let make_capture = || {
        let tx = inbound_tx.clone();
        handler_fn(move |_ctx: HandlerContext, msg: Message| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(msg);
                Ok::<Option<DIDCommResponse>, DIDCommServiceError>(None)
            }
        })
    };

    let mut router = Router::new()
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
        )?;
    for type_url in routes {
        router = router.route(*type_url, make_capture())?;
    }

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

/// Connect both profiles to the mediator and wait for them to settle.
/// Bob's listener comes up first so his pickup queue is ready when
/// Alice pushes; both routers register handlers for `routes`.
async fn connect_alice_and_bob(
    mediator: &MockMediator,
    routes: &[&'static str],
) -> (
    DIDCommService,
    DIDCommService,
    String,
    String,
    mpsc::UnboundedReceiver<Message>,
) {
    let alice = mediator.make_profile("alice").expect("alice profile");
    let bob = mediator.make_profile("bob").expect("bob profile");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    let (bob_inbound_tx, bob_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (bob_service, _bob_shutdown) = start_profile_service(bob, routes, bob_inbound_tx)
        .await
        .expect("bob service");

    let (alice_inbound_tx, _alice_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (alice_service, _alice_shutdown) = start_profile_service(alice, routes, alice_inbound_tx)
        .await
        .expect("alice service");

    bob_service
        .wait_connected("bob", Duration::from_secs(15))
        .await
        .expect("bob connect");
    alice_service
        .wait_connected("alice", Duration::from_secs(15))
        .await
        .expect("alice connect");

    (
        alice_service,
        bob_service,
        alice_did,
        bob_did,
        bob_inbound_rx,
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn alice_sends_to_bob_via_mediator() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let (alice_service, bob_service, alice_did, bob_did, mut bob_rx) =
        connect_alice_and_bob(&mediator, &[TEST_MESSAGE_TYPE]).await;

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

    let received = tokio::time::timeout(Duration::from_secs(15), bob_rx.recv())
        .await
        .expect("bob received within 15s")
        .expect("inbound channel still open");

    assert_eq!(received.typ, TEST_MESSAGE_TYPE);
    assert_eq!(
        received.body.get("hello").and_then(|v| v.as_str()),
        Some("from-alice")
    );

    let _ = (alice_service, bob_service);
    drop(mediator);
}

/// Drives a real openvtc-core `RelationshipRequestBody` through the
/// mediator and asserts that Bob can deserialise the payload back into
/// the same protocol type. Same connect / wait / send / receive shape
/// as the basic round-trip, but the message body is the production
/// `relationships::RelationshipRequestBody` instead of opaque JSON —
/// so a future serde change on either side trips this test.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn relationship_request_round_trip() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let (alice_service, bob_service, alice_did, bob_did, mut bob_rx) =
        connect_alice_and_bob(&mediator, &[RELATIONSHIP_REQUEST]).await;

    // Use the openvtc-core protocol body shape so a serde regression on
    // either field name (`reason`, `did`, `name`) is caught here too.
    let body = RelationshipRequestBody {
        reason: Some("integration test".to_string()),
        did: alice_did.clone(),
        name: Some("Alice".to_string()),
    };
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        RELATIONSHIP_REQUEST.to_string(),
        serde_json::to_value(&body).expect("serialise body"),
    )
    .from(alice_did)
    .to(bob_did.clone())
    .finalize();

    alice_service
        .send_message_with_retry("alice", msg, &bob_did, 3, Duration::from_secs(2))
        .await
        .expect("alice send");

    let received = tokio::time::timeout(Duration::from_secs(15), bob_rx.recv())
        .await
        .expect("bob received within 15s")
        .expect("inbound channel still open");

    assert_eq!(received.typ, RELATIONSHIP_REQUEST);
    let parsed: RelationshipRequestBody =
        serde_json::from_value(received.body.clone()).expect("deserialise body");
    assert_eq!(parsed.reason.as_deref(), Some("integration test"));
    assert_eq!(parsed.name.as_deref(), Some("Alice"));
    assert!(parsed.did.starts_with("did:peer:"));

    let _ = (alice_service, bob_service);
    drop(mediator);
}
