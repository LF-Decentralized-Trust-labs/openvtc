//! Shared integration-test scaffolding.
//!
//! Wraps [`affinidi-messaging-test-mediator`]'s `TestMediator` so each
//! integration test gets the same mediator-plus-two-DIDs setup without
//! repeating the boilerplate. The fixture handles port pre-bind, the
//! mediator's `did:peer` (with `dm`/`#auth`/`#ws` services), the JWT
//! signing keypair, and permissive global ACLs.
//!
//! ## Why we register accounts post-boot instead of using `local_dids`
//!
//! End-user DIDs must use the **mediator's DID** (not its HTTP URL) as
//! their DIDComm service endpoint. The mediator's routing/2.0 logic in
//! `service_endpoint_for_remote` only short-circuits to local delivery
//! when the next-hop URI string equals the mediator's DID; an HTTP URL
//! — even one pointing back at the same mediator — is treated as
//! "remote" and enqueued to `FORWARD_Q` for external HTTP forwarding.
//! The forwarding processor then either drops the message (if disabled)
//! or attempts to POST it back to itself (if enabled), which doesn't
//! resolve the round-trip.
//!
//! The mediator's DID is content-addressed off keys generated *during*
//! `TestMediator::spawn`, so it isn't known when `local_dids(...)` is
//! supplied at builder time. We therefore:
//!
//!   1. Construct our own `MemoryStore` and pass it in via `.store(...)`.
//!   2. Spawn the mediator without any `local_dids`.
//!   3. Capture `handle.did()`, generate Alice + Bob with that DID as
//!      their service URI.
//!   4. Register them as `ALLOW_ALL` accounts directly through the
//!      shared store — same code the test-mediator's own
//!      `register_local_dids` runs internally.
//!
//! Tests that boot the mediator are slow (~1s) so they're marked
//! `#[ignore]` by default. Run via:
//!
//!     cargo test -p openvtc-core -- --ignored
//!
//! CI's coverage job runs `--include-ignored` so the integration suite
//! still contributes to the report.

#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use affinidi_messaging_mediator::store::MemoryStore;
use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use affinidi_messaging_test_mediator::{TestMediator, TestMediatorHandle};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use sha256::digest;

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
    /// local accounts. See module docs for why this dance can't use the
    /// `TestMediatorBuilder::local_dids` shortcut.
    pub async fn start() -> Result<Self> {
        // Pre-bind so the mediator binds the same port the OS just gave
        // us. The drop window before `TestMediator::spawn` re-binds is
        // microseconds; collisions on 127.0.0.1 are practically nil.
        let pre_bound = TcpListener::bind("127.0.0.1:0")?;
        let listen_addr: SocketAddr = pre_bound.local_addr()?;
        drop(pre_bound);

        // We need a handle on the store so we can register accounts
        // post-boot. Cloning an `Arc<dyn MediatorStore>` keeps both the
        // mediator and the harness pointing at the same `MemoryStore`.
        let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

        let handle = TestMediator::builder()
            .listen_addr(listen_addr)
            .store(store.clone())
            .spawn()
            .await?;

        let mediator_did = handle.did().to_string();
        let mediator_url = handle.endpoint().to_string();

        // Generate users now that the mediator's DID is known; using
        // the DID (not the URL) as their service URI is what trips the
        // mediator's "this is local" short-circuit in routing/2.0.
        let alice = generate_user("alice", &mediator_did, &mediator_did)?;
        let bob = generate_user("bob", &mediator_did, &mediator_did)?;

        // Register both as ALLOW_ALL accounts directly. The
        // `from_string_ruleset` helper builds the same bitmask the
        // test-mediator's internal `register_local_dids` uses for
        // builder-supplied `local_dids`.
        let acls = MediatorACLSet::from_string_ruleset("ALLOW_ALL")
            .map_err(|e| format!("ALLOW_ALL ACL build: {e}"))?;
        for did in [&alice.did, &bob.did] {
            let did_hash = digest(did);
            if !store.account_exists(&did_hash).await? {
                store.account_add(&did_hash, &acls, None).await?;
            }
        }

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

/// Generate a fresh `did:peer` DIDComm profile. `service_uri` lands in
/// the `dm` service entry — pass the mediator's DID so the mediator's
/// routing logic recognises forwards as locally bound.
fn generate_user(alias: &str, service_uri: &str, mediator_did: &str) -> Result<TestProfile> {
    let (did, secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(service_uri.to_string()),
    )?;
    Ok(TestProfile {
        alias: alias.to_string(),
        did,
        secrets,
        mediator_did: mediator_did.to_string(),
    })
}

fn clone_profile(p: &TestProfile) -> TestProfile {
    TestProfile {
        alias: p.alias.clone(),
        did: p.did.clone(),
        secrets: p.secrets.clone(),
        mediator_did: p.mediator_did.clone(),
    }
}
