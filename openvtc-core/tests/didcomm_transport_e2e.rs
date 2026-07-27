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
    DIDCommEvent, add_listener, build_router, relationship_listener_config_from_secrets,
    send_message_via,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// An OpenVTC protocol type the production catch-all pattern must route.
const OPENVTC_TYPE: &str = "https://linuxfoundation.org/openvtc/test/1.0/ping";

/// Start a `DIDCommService` for one profile using the **production** router and
/// the production `Config`-free listener builder.
async fn start_production_service(
    profile: common::TestProfile,
    remote_did: &str,
    event_tx: mpsc::Sender<DIDCommEvent>,
) -> (
    affinidi_messaging_didcomm_service::DIDCommService,
    String,
    CancellationToken,
) {
    let listener = relationship_listener_config_from_secrets(
        &profile.did,
        remote_did,
        &profile.mediator_did,
        profile.secrets.clone(),
    );
    let listener_id = listener.id.clone();
    let router = build_router(event_tx).expect("production router builds");
    let shutdown = CancellationToken::new();
    // Start empty and install through the production `add_listener` seam, so the
    // test drives the same path the runtime does rather than reaching past it
    // into the framework's own config type.
    let service = affinidi_messaging_didcomm_service::DIDCommService::start(
        affinidi_messaging_didcomm_service::DIDCommServiceConfig { listeners: vec![] },
        router,
        shutdown.clone(),
    )
    .await
    .expect("service starts");
    add_listener(&service, &listener)
        .await
        .expect("production listener spec installs");
    (service, listener_id, shutdown)
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
    let (bob_service, bob_listener, _bob_shutdown) =
        start_production_service(bob, &alice_did, bob_tx).await;
    bob_service
        .wait_connected(&bob_listener, Duration::from_secs(15))
        .await
        .expect("bob listener connects");

    let (alice_tx, _alice_rx) = mpsc::channel::<DIDCommEvent>(16);
    let (alice_service, alice_listener, _alice_shutdown) =
        start_production_service(alice, &bob_did, alice_tx).await;
    alice_service
        .wait_connected(&alice_listener, Duration::from_secs(15))
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
        DIDCommEvent::InboundMessage { message, from } => {
            assert_eq!(
                message.typ, OPENVTC_TYPE,
                "the catch-all pattern routed this type"
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
    let (bob_service, bob_listener, _bob_shutdown) =
        start_production_service(bob, &alice_did, bob_tx).await;
    bob_service
        .wait_connected(&bob_listener, Duration::from_secs(15))
        .await
        .expect("bob listener connects");

    let (alice_tx, _alice_rx) = mpsc::channel::<DIDCommEvent>(16);
    let (alice_service, alice_listener, _alice_shutdown) =
        start_production_service(alice, &bob_did, alice_tx).await;
    alice_service
        .wait_connected(&alice_listener, Duration::from_secs(15))
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
