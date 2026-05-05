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

use affinidi_messaging_test_mediator::{TestMediator, TestMediatorHandle, TestMediatorUser};
use affinidi_tdk::secrets_resolver::secrets::Secret;

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
