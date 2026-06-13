//! Shared integration-test scaffolding.
//!
//! Wraps [`affinidi-messaging-test-mediator`]'s `TestMediator::with_users`
//! helper so each integration test gets the same mediator-plus-two-DIDs
//! setup without repeating the boilerplate. The fixture handles port
//! pre-bind, the mediator's `did:peer` (with `dm`/`#auth`/`#ws`
//! services), the JWT signing keypair, ALLOW_ALL ACL registration, and
//! — crucially — mints user DIDs whose service URI is the mediator's
//! DID rather than its HTTP URL. That last part is what makes
//! routing/2.0 forwards short-circuit to local delivery instead of
//! being enqueued to FORWARD_Q for external HTTP forwarding.
//!
//! Tests that boot the mediator are slow (~1s) so they're marked
//! `#[ignore]` by default. Run via:
//!
//!     cargo test -p openvtc-core -- --ignored
//!
//! CI's coverage job runs `--include-ignored` so the integration suite
//! still contributes to the report.

#![allow(dead_code)]

use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, HandlerContext,
    ListenerConfig, RestartPolicy, RetryConfig, Router, handler_fn, ignore_handler,
    trust_ping_handler,
};
use affinidi_messaging_test_mediator::{TestMediator, TestMediatorHandle, TestMediatorUser};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

/// A DIDComm profile generated for use by integration tests.
pub struct TestProfile {
    pub alias: String,
    pub did: String,
    pub secrets: Vec<Secret>,
    pub mediator_did: String,
}

/// In-process test mediator with two pre-registered DIDComm profiles
/// (Alice + Bob). Holds the [`TestMediatorHandle`] so the mediator
/// stays up for the lifetime of the test; tearing down on drop is
/// handled by the underlying handle.
pub struct MockMediator {
    pub handle: TestMediatorHandle,
    pub mediator_did: String,
    pub mediator_url: String,
    pub alice: TestProfile,
    pub bob: TestProfile,
}

impl MockMediator {
    /// Spawn the test mediator and register Alice + Bob as ALLOW_ALL
    /// local accounts via [`TestMediator::with_users`].
    pub async fn start() -> Result<Self> {
        let (handle, users) = TestMediator::with_users(["alice", "bob"]).await?;
        let mediator_did = handle.did().to_string();
        let mediator_url = handle.endpoint().to_string();

        let mut iter = users.into_iter();
        let alice = into_profile(iter.next().expect("alice"), &mediator_did);
        let bob = into_profile(iter.next().expect("bob"), &mediator_did);

        Ok(Self {
            handle,
            mediator_did,
            mediator_url,
            alice,
            bob,
        })
    }

    /// Convenience: clone the named profile (one of `"alice"` /
    /// `"bob"`). Tests typically destructure `mediator.alice` /
    /// `.bob` directly; this is for cases where the alias is dynamic.
    pub fn profile(&self, alias: &str) -> Option<TestProfile> {
        match alias {
            "alice" => Some(clone_profile(&self.alice)),
            "bob" => Some(clone_profile(&self.bob)),
            _ => None,
        }
    }
}

fn into_profile(user: TestMediatorUser, mediator_did: &str) -> TestProfile {
    TestProfile {
        alias: user.alias,
        did: user.did,
        secrets: user.secrets,
        mediator_did: mediator_did.to_string(),
    }
}

fn clone_profile(p: &TestProfile) -> TestProfile {
    TestProfile {
        alias: p.alias.clone(),
        did: p.did.clone(),
        secrets: p.secrets.clone(),
        mediator_did: p.mediator_did.clone(),
    }
}

/// Install a tracing subscriber so the mediator's logs surface in
/// `cargo test -- --nocapture`. Idempotent — subsequent calls are
/// no-ops once a global subscriber is installed.
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

/// Build a `DIDCommService` for `profile` with a router that captures
/// any inbound message in `routes` into `inbound_tx`. Returns the
/// running service plus the cancellation token guarding its background
/// tasks.
pub async fn start_profile_service(
    profile: TestProfile,
    routes: &[&'static str],
    inbound_tx: mpsc::UnboundedSender<Message>,
) -> std::result::Result<
    (DIDCommService, CancellationToken),
    Box<dyn std::error::Error + Send + Sync>,
> {
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
        router = router.route(type_url, make_capture())?;
    }

    let shutdown = CancellationToken::new();
    let service = DIDCommService::start(config, router, shutdown.clone()).await?;
    Ok((service, shutdown))
}
