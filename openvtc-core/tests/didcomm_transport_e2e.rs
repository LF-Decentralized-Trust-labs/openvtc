//! Integration coverage for the production DIDComm transport module
//! ([`openvtc_core::didcomm`]) over a real mediator.
//!
//! **This test could not exist before the module moved into `openvtc-core`.** It
//! lived at `openvtc/src/state_handler/didcomm.rs`, and `openvtc` is a
//! binary-only crate (`[[bin]]`, no `src/lib.rs`), so nothing could import it.
//! That is why the module that owns every socket in the TUI had no coverage
//! beyond two pure unit groups — a regex and an id function — while its actual
//! failure mode is `duplicate-channel` and duelling reconnect loops, which
//! produce neither a compile error nor a failing unit test.
//!
//! So this asserts the three things the delivery-layer swap (#189) is about to
//! rewrite, against the real mediator rather than a mock:
//!
//! 1. `build_router` routes an OpenVTC protocol message to the event channel —
//!    the catch-all regex working on a real wire, not just against `Regex::new`.
//! 2. `send_message_via` actually delivers through the mediator.
//! 3. A listener built by `relationship_listener_config_from_secrets` connects.
//!
//! Deliberately uses the `..._from_secrets` constructor: it is the one listener
//! builder that takes no `Config`, so the transport path is exercised without
//! standing up an encrypted on-disk config. The `Config`-taking builders
//! (`build_listener_configs`, `persona_listener_config_for`) differ only in where
//! the DID, mediator and secrets come from.
//!
//! `#[ignore]` like its siblings — booting the mediator is slow. CI's coverage
//! job runs `--include-ignored`.

mod common;

use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use common::{MockMediator, init_test_tracing};
use openvtc_core::didcomm::{
    DIDCommEvent, Messaging, add_listener, relationship_listener_config_from_secrets,
    send_message_via,
};
use tokio::sync::mpsc;
use uuid::Uuid;

/// An OpenVTC protocol type the production catch-all pattern must route.
const OPENVTC_TYPE: &str = "https://linuxfoundation.org/openvtc/test/1.0/ping";

/// Stand up one profile's production `Messaging` runtime and install its listener.
async fn start_production_service(
    profile: common::TestProfile,
    remote_did: &str,
    event_tx: mpsc::Sender<DIDCommEvent>,
) -> (Messaging, String) {
    let listener = relationship_listener_config_from_secrets(
        &profile.did,
        remote_did,
        &profile.mediator_did,
        profile.secrets.clone(),
    );
    let listener_id = listener.id.clone();
    let service = Messaging::start(event_tx);
    add_listener(&service, &listener)
        .await
        .expect("production listener spec installs");
    (service, listener_id)
}

/// The end-to-end path the swap will replace: production listener → production
/// send → mediator → production router → event channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator (~1s)"]
async fn an_openvtc_message_routes_through_the_production_transport() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob = mediator.profile("bob").expect("bob");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    // Receiver first: a listener that is not yet polling would miss the frame.
    let (bob_tx, mut bob_rx) = mpsc::channel::<DIDCommEvent>(16);
    let (bob_service, bob_listener) = start_production_service(bob, &alice_did, bob_tx).await;
    bob_service
        .wait_connected(&bob_listener, Duration::from_secs(20))
        .await
        .expect("bob listener connects");

    let (alice_tx, _alice_rx) = mpsc::channel::<DIDCommEvent>(16);
    let (alice_service, alice_listener) = start_production_service(alice, &bob_did, alice_tx).await;
    alice_service
        .wait_connected(&alice_listener, Duration::from_secs(20))
        .await
        .expect("alice listener connects");

    let message = Message::build(
        Uuid::new_v4().to_string(),
        OPENVTC_TYPE.to_string(),
        serde_json::json!({ "hello": "transport" }),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .finalize();

    send_message_via(&alice_service, &message, &alice_listener, &bob_did)
        .await
        .expect("production send delivers");

    let event = tokio::time::timeout(Duration::from_secs(20), bob_rx.recv())
        .await
        .expect("bob receives within 20s")
        .expect("event channel still open");

    match event {
        DIDCommEvent::InboundMessage {
            message,
            from,
            transport,
        } => {
            assert_eq!(
                message.typ, OPENVTC_TYPE,
                "the catch-all pattern routed this type"
            );
            // The reported transport is the one that actually carried the
            // frame, not a guess. This leg is DIDComm; the activity log used to
            // hardcode that label and so was wrong for every TSP frame.
            assert_eq!(
                transport,
                openvtc_core::didcomm::InboundTransport::DidComm,
                "a DIDComm round trip reports DIDComm"
            );
            assert_eq!(
                from.as_deref(),
                Some(alice_did.as_str()),
                "the sender survives the round trip"
            );
            assert_eq!(
                message.body.get("hello").and_then(|v| v.as_str()),
                Some("transport"),
                "the body survives pack/unpack"
            );
        }
        other => panic!("expected InboundMessage, got {other:?}"),
    }
}

/// A type the catch-all must *not* route reaches no handler, so nothing lands on
/// the event channel. The unit test asserts this against the regex; this asserts
/// it against a real delivered message, which is the claim that actually matters
/// — a routing gate that leaks would hand unvetted traffic to dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator (~1s)"]
async fn an_unrelated_message_type_reaches_no_handler() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob = mediator.profile("bob").expect("bob");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    let (bob_tx, mut bob_rx) = mpsc::channel::<DIDCommEvent>(16);
    let (bob_service, bob_listener) = start_production_service(bob, &alice_did, bob_tx).await;
    bob_service
        .wait_connected(&bob_listener, Duration::from_secs(20))
        .await
        .expect("bob listener connects");

    let (alice_tx, _alice_rx) = mpsc::channel::<DIDCommEvent>(16);
    let (alice_service, alice_listener) = start_production_service(alice, &bob_did, alice_tx).await;
    alice_service
        .wait_connected(&alice_listener, Duration::from_secs(20))
        .await
        .expect("alice listener connects");

    let message = Message::build(
        Uuid::new_v4().to_string(),
        "https://example.com/not-openvtc/1.0/whatever".to_string(),
        serde_json::json!({}),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .finalize();

    send_message_via(&alice_service, &message, &alice_listener, &bob_did)
        .await
        .expect("send delivers");

    assert!(
        tokio::time::timeout(Duration::from_millis(2500), bob_rx.recv())
            .await
            .is_err(),
        "an unrelated type must not reach the event channel"
    );
}

/// The supervisor must leave a **healthy** transport alone.
///
/// A rebuild tears the websocket down and builds a new one, so a supervisor that
/// fired on a connected transport — or on every tick — would churn the socket and
/// race the mediator's one-per-DID rule, manufacturing the `duplicate-channel`
/// fault it exists to recover from (#132).
///
/// The unit tests in `supervisor_policy_tests` pin the timing thresholds. This
/// asserts the loop actually honours them against a real mediator: across several
/// supervisor ticks, a connected listener neither reports a disconnect transition
/// nor leaves `Connected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator and waits out several supervisor ticks"]
async fn the_supervisor_does_not_churn_a_healthy_transport() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob_did = mediator.profile("bob").expect("bob").did;

    let (tx, _rx) = mpsc::channel::<DIDCommEvent>(16);
    let (service, listener_id) = start_production_service(alice, &bob_did, tx).await;
    service
        .wait_connected(&listener_id, Duration::from_secs(20))
        .await
        .expect("listener connects");

    // Watch for transitions from here: a rebuild would surface as a disconnect.
    let mut status = service.subscribe();

    // Comfortably more than one supervisor tick (10s), so a loop that rebuilds
    // unconditionally is caught.
    tokio::time::sleep(Duration::from_secs(25)).await;

    while let Ok(event) = status.try_recv() {
        if let openvtc_core::didcomm::ListenerStatus::Disconnected { listener_id, .. } = event {
            panic!("a healthy transport was disconnected — the supervisor churned {listener_id}");
        }
    }
    assert_eq!(
        service.listener_state(&listener_id),
        Some(openvtc_core::didcomm::ConnState::Connected),
        "the listener is still connected after several supervisor ticks"
    );
}
