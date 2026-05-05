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

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use affinidi_did_common::one_or_many::OneOrMany;
use affinidi_did_common::{
    DID as DIDCommon, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint,
    PeerServiceEndpointLong,
};
use affinidi_messaging_mediator::builder::{MediatorBuilder, MediatorHandle};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

/// A DIDComm profile generated for use by integration tests. The
/// `did:peer` is freshly minted for each call, the secrets are
/// in-memory only, and the `mediator_did` matches the
/// [`MockMediator`] this profile was registered with — so tests can
/// build [`TDKProfile`](affinidi_tdk_common::profiles::TDKProfile)
/// instances pointing at the right mediator.
pub struct TestProfile {
    pub alias: String,
    pub did: String,
    pub secrets: Vec<Secret>,
    pub mediator_did: String,
}

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
        // The DIDComm SDK resolves a profile's mediator DID to the
        // mediator's HTTP endpoint via the service entry baked into
        // the mediator's did:peer document. That URL has to be known
        // *before* the DID is generated, so we pre-bind to an
        // ephemeral port, drop the listener, and reuse the same port
        // for the actual server. The drop/reuse window is microseconds
        // and 127.0.0.1 — collisions in CI are practically impossible.
        let pre_bound = TcpListener::bind("127.0.0.1:0")?;
        let listen_addr: SocketAddr = pre_bound.local_addr()?;
        drop(pre_bound);

        // The mediator's did:peer must publish two services:
        //   * `dm`             — DIDComm messaging endpoint (used by
        //                         transports/websockets and HTTP).
        //   * `#auth`          — DID-based authentication endpoint (used
        //                         by the SDK's challenge-response flow).
        // Both point at the same base URI; the SDK appends `/authenticate`,
        // `/authenticate/challenge`, `/authenticate/refresh` for the auth
        // path. The TDK 0.6 single-service `generate_did_peer` shortcut
        // doesn't expose this, so we drop into `affinidi-did-common`
        // directly. (TDK 0.7+ has `generate_did_peer_with_services` for
        // the same job.)
        let didcomm_uri = format!("http://{}/mediator/v1", listen_addr);
        let (mediator_did, mediator_secrets) = generate_mediator_did_peer(&didcomm_uri)?;

        // Admin DID gates `/admin/*` endpoints; integration tests don't
        // exercise admin ops so any did:peer suffices.
        let (admin_did, _admin_secrets) =
            DID::generate_did_peer(vec![(PeerKeyRole::Verification, KeyType::Ed25519)], None)?;

        // Stand up a secrets resolver and load the mediator's own keys
        // so it can sign / decrypt its own traffic.
        let (resolver, secrets_task) = ThreadedSecretsResolver::new(None).await;
        resolver.insert_vec(&mediator_secrets).await;

        // Headless mediator config ships zero-byte JWT keys, which
        // makes the auth path 500 with `InvalidEddsaKey` the moment a
        // client tries to authenticate. Generate a real Ed25519 pair
        // and inject it into the security config before start.
        let mut builder = MediatorBuilder::new(Arc::new(resolver))
            .memory_store()
            .mediator_did(&mediator_did)
            .admin_did(&admin_did)
            .listen_addr(listen_addr)
            .install_signal_handlers(false);
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())?;
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())?;
        let pubkey_der = {
            use ring::signature::KeyPair;
            pair.public_key().as_ref().to_vec()
        };
        builder.config_mut().security.jwt_encoding_key =
            jsonwebtoken::EncodingKey::from_ed_der(pkcs8.as_ref());
        builder.config_mut().security.jwt_decoding_key =
            jsonwebtoken::DecodingKey::from_ed_der(&pubkey_der);

        // Default `ExplicitDeny` mode flips the per-account ACL `local`
        // bit off, which makes every fresh DID trip the websocket
        // handler's "DID isn't local" 403. `ExplicitAllow` flips the
        // default the other way: any DID is considered local unless
        // it's explicitly denied. Matches what `mediator-setup`
        // produces for development deployments.
        // Mirror what the SDK's "allow_all" ACL preset produces: open
        // mediator with permissive defaults so any DID can connect,
        // send, receive, and exchange forwarded messages.
        use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
        builder.config_mut().security.mediator_acl_mode = AccessListModeType::ExplicitAllow;
        let acls = &mut builder.config_mut().security.global_acl_default;
        // Per-account access-list mode: ExplicitDeny means "allow
        // everyone except DIDs explicitly denied". With an empty list
        // that's effectively allow-all, matching the preset.
        let _ = acls.set_access_list_mode(AccessListModeType::ExplicitDeny, true, true);
        acls.set_local(true);
        let _ = acls.set_send_messages(true, true, true);
        let _ = acls.set_receive_messages(true, true, true);
        let _ = acls.set_send_forwarded(true, true, true);
        let _ = acls.set_receive_forwarded(true, true, true);
        let _ = acls.set_create_invites(true, true, true);
        let _ = acls.set_anon_receive(true, true, true);
        acls.set_self_manage_list(true);
        acls.set_self_manage_send_queue_limit(true);

        let shutdown = CancellationToken::new();
        let handle = builder.start(shutdown).await?;

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

    /// Mint a fresh DIDComm profile registered against this mediator.
    /// Returns a [`TestProfile`] whose `did`, `secrets`, and
    /// `mediator_did` are wired together — drop them straight into
    /// `TDKProfile::new` to drive a real DIDCommService against the
    /// in-process mediator.
    ///
    /// The mediator boots with `AccessListModeType::ExplicitDeny`
    /// (default), so any DID can register without admin involvement.
    pub fn make_profile(&self, alias: &str) -> Result<TestProfile> {
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )?;
        Ok(TestProfile {
            alias: alias.to_string(),
            did,
            secrets,
            mediator_did: self.mediator_did.clone(),
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

/// Build a multi-service did:peer for the mediator. Generates fresh
/// Ed25519 (verification) + X25519 (encryption) keys, registers both
/// `dm` and `#auth` service entries pointing at `base_uri`, and
/// returns the DID string + secrets with their `id` fields rewritten
/// to the published verification-method URLs (`<did>#key-N`).
fn generate_mediator_did_peer(base_uri: &str) -> Result<(String, Vec<Secret>)> {
    // Generate the keys via TDK so we get `Secret` instances with the
    // private key material attached (we need them for the secrets
    // resolver). TDK exposes `Secret::generate_*`; use the lower-level
    // path that the affinidi did-peer example follows.
    let mut v_secret = Secret::generate_ed25519(None, None);
    let mut e_secret =
        Secret::generate_x25519(None, None).map_err(|e| format!("generate x25519: {e:?}"))?;

    let v_multibase = v_secret
        .get_public_keymultibase()
        .map_err(|e| format!("v multibase: {e:?}"))?;
    let e_multibase = e_secret
        .get_public_keymultibase()
        .map_err(|e| format!("e multibase: {e:?}"))?;

    let peer_keys = vec![
        PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_multibase),
    ];

    // Use the plain `Uri` endpoint form (not the Long-with-routing
    // variant) — the resolved service endpoint goes through
    // `Endpoint::get_uri`, which on the Map (Long) branch happens to
    // round-trip through `serde_json::Value::to_string` and re-emits
    // the URI surrounded by JSON quotes. That stringly-typed value
    // then fails reqwest's `Url::parse` with RelativeUrlWithoutBase.
    // The Uri branch returns `url.to_string()` cleanly.
    // ws:// URI derived from the http URI by swapping scheme + adding
    // the mediator's /ws path. The SDK's WebSocket transport scans the
    // DID document for a service whose endpoint scheme is `ws`.
    let ws_uri = base_uri
        .replacen("http://", "ws://", 1)
        .replacen("https://", "wss://", 1)
        + "/ws";

    let long_endpoint = |uri: String| {
        PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri,
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        }))
    };

    let services = vec![
        // DIDComm messaging endpoint. The SDK's HTTP/WS discovery scans
        // services for a Long-form endpoint with `accept: didcomm/v2`,
        // so this entry must be Long form.
        PeerService {
            type_: "dm".into(),
            endpoint: long_endpoint(base_uri.to_string()),
            id: None,
        },
        // Authentication service. The SDK appends `/challenge`,
        // `/refresh` etc. to this URI. The mediator publishes those
        // routes under `/mediator/v1/authenticate/...`, so the service
        // URI must include the `/authenticate` segment.
        //
        // affinidi-did-authentication searches the DID document for a
        // service whose id ends in `#auth`. PeerService::id is
        // appended verbatim to the DID with no separator, so the
        // leading `#` has to be in the value.
        //
        // Use the simple Uri form: did-authentication's `get_uri`
        // helper round-trips Long-form endpoints through
        // `serde_json::Value::to_string`, which leaves JSON quotes
        // wrapping the URL and breaks reqwest's URL parser.
        PeerService {
            type_: "Authentication".into(),
            endpoint: PeerServiceEndpoint::Uri(format!("{base_uri}/authenticate")),
            id: Some("#auth".into()),
        },
        // WebSocket service. Same Long-form requirement as `dm` — the
        // SDK reads the URI from the JSON map and checks for the
        // `ws://` (or `wss://`) scheme.
        PeerService {
            type_: "WebSocket".into(),
            endpoint: long_endpoint(ws_uri),
            id: Some("#ws".into()),
        },
    ];

    let (did_peer, _created) = DIDCommon::generate_peer(&peer_keys, Some(&services))
        .map_err(|e| format!("generate_peer: {e:?}"))?;
    let did_str = did_peer.to_string();

    // Rewrite the secrets' ids to match the DID's verification methods
    // (did:peer 2 numbers them sequentially: V→#key-1, E→#key-2).
    v_secret.id = format!("{did_str}#key-1");
    e_secret.id = format!("{did_str}#key-2");

    Ok((did_str, vec![v_secret, e_secret]))
}
