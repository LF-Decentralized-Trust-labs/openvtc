//! Shared integration-test scaffolding.
//!
//! The expensive pieces — namely an in-process DIDComm mediator — live
//! here so each test crate doesn't have to re-derive its own setup
//! pattern. Tests that need the mediator call [`MockMediator::start`]
//! and use the returned [`MockMediator`] for the lifetime of the test;
//! it tears down on drop.
//!
//! Tests that boot the mediator are slow (low seconds) so they're
//! marked `#[ignore]` by default — run via:
//!
//!     cargo test -p openvtc-core -- --ignored
//!
//! (CI's `coverage` job runs `--include-ignored` so the integration
//! suite still contributes to the coverage report.)

#![allow(dead_code)]

use std::sync::Arc;

use affinidi_messaging_mediator::builder::{MediatorBuilder, MediatorHandle};
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

/// In-process DIDComm mediator running on an ephemeral loopback port.
/// Holds the [`MediatorHandle`] so the mediator stays up for the
/// lifetime of the test, and triggers shutdown on drop.
pub struct MockMediator {
    pub handle: MediatorHandle,
    /// HTTP base URL, e.g. `http://127.0.0.1:55812/mediator/v1/`.
    pub http_url: String,
    /// WebSocket URL, e.g. `ws://127.0.0.1:55812/mediator/v1/ws`.
    pub ws_url: String,
    /// Mediator's DID — tests addressing this mediator need this string
    /// in their DIDComm envelopes.
    pub mediator_did: String,
    /// Admin DID configured at startup. Some tests need the admin
    /// credential to provision profiles.
    pub admin_did: String,
    /// Background secrets-resolver task handle. Kept so it doesn't drop
    /// (and therefore doesn't get cancelled) until the mediator does.
    _secrets_task: Option<JoinHandle<()>>,
}

impl MockMediator {
    /// Spawn a mediator with a generated `did:peer` identity, in-memory
    /// store, ephemeral loopback listener, and a generated admin DID.
    /// Resolves once the listener is bound and ready to accept traffic.
    pub async fn start() -> Result<Self> {
        // 1. Generate the mediator's own DIDComm identity. did:peer is
        //    self-contained (no external resolution needed) which is
        //    exactly what we want for an in-process test fixture.
        let (mediator_did, mediator_secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )?;

        // 2. Generate the admin DID. The mediator gates `/admin/*`
        //    endpoints on this DID, but the integration tests below don't
        //    exercise admin operations — we just need it set so
        //    MediatorBuilder::start() validation passes.
        let (admin_did, _admin_secrets) =
            DID::generate_did_peer(vec![(PeerKeyRole::Verification, KeyType::Ed25519)], None)?;

        // 3. Stand up a secrets resolver and load the mediator's keys
        //    into it so the mediator can sign / decrypt its own traffic.
        let (resolver, secrets_task) = ThreadedSecretsResolver::new(None).await;
        resolver.insert_vec(&mediator_secrets).await;

        // 4. Build and start. `memory_store()` keeps state in RAM so
        //    teardown is just dropping the handle. `listen_addr` defaults
        //    to `127.0.0.1:0` (ephemeral) so parallel test invocations
        //    don't collide.
        let shutdown = CancellationToken::new();
        let handle = MediatorBuilder::new(Arc::new(resolver))
            .memory_store()
            .mediator_did(&mediator_did)
            .admin_did(&admin_did)
            .install_signal_handlers(false)
            .start(shutdown)
            .await?;

        let http_url = handle.http_endpoint.to_string();
        let ws_url = handle.ws_endpoint.to_string();
        let mediator_did = handle.mediator_did.clone();
        let admin_did = handle.admin_did.clone();

        Ok(Self {
            handle,
            http_url,
            ws_url,
            mediator_did,
            admin_did,
            _secrets_task: secrets_task,
        })
    }
}

impl Drop for MockMediator {
    fn drop(&mut self) {
        // Cancellation is async-safe even from sync `drop`; the server
        // task observes the token and unwinds in the background.
        self.handle.shutdown();
    }
}
