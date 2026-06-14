//! End-to-end State-A bootstrap exchange against a real in-process VTA.
//!
//! Drives the VTA-side of OpenVTC bootstrap against `vta_service`'s
//! `MockVta::start_provisionable()` — a real, listening VTA on a loopback
//! port with a self-resolving `did:key` identity (VTI#406/#427). Because the
//! mock can't be resolved *back* to its loopback URL, provisioning is driven
//! **URL-direct** (the seam OpenVTC's own bootstrap takes when `OPENVTC_VTA_URL`
//! is set): `provision_admin_rotated_via_rest` talks REST to `base_url()` with
//! the configured `vta_did()`, never re-resolving the DID.
//!
//! Scenarios:
//!
//!   * `admin_rotation_provisions_against_mock_vta` — the State-A admin
//!     rotation: an ephemeral setup `did:key` (authorized in the ACL, the
//!     `pnm acl create` step) drives `provision_admin_rotated_via_rest`, which
//!     returns a freshly-minted long-term admin DID + key (not the setup pair).
//!   * `bootstrap_creates_top_context_and_lists_webvh_server` — the rest of the
//!     State-A VTA surface: an authenticated client creates the account's
//!     top-level context and sees a seeded webvh hosting server in the
//!     catalogue (the prerequisite a later persona `did:webvh` mint resolves).
//!
//! The DIDComm join-request submission + lifecycle resolution that follow
//! bootstrap are pure-mediator and covered in `join_lifecycle_e2e.rs`. The
//! persona `did:webvh` mint itself (`create_key` → `create_did_webvh`) is not
//! yet exercised here — `MockVta` has no webvh hosting backend, so the publish
//! 500s; tracked as VTI#431 (and the ACL ergonomics as VTI#429).
//!
//! All `#[ignore]`'d: spinning up the provisionable VTA + the provision
//! round-trip is slow. CI's coverage job runs them via `--include-ignored`.
//!
//! NOTE: depends on the `vta-service` git dev-dependency (the VTA server crate
//! is not on crates.io); its git source is allow-listed in `deny.toml`.

use vta_sdk::client::{CreateContextRequest, VtaClient};
use vta_sdk::provision_client::{
    EphemeralSetupKey, ProvisionAsk, provision_admin_rotated_via_rest,
};
use vta_service::acl::{AclEntry, Role};
use vta_service::test_support::MockVta;

/// Authorize `did` as super-admin in the mock's ACL — the `pnm acl create`
/// step the real bootstrap performs before the setup DID can provision. (An
/// ergonomic `MockVta` helper for this is requested in VTI#429; until then we
/// seed the entry through the public keyspace API, mirroring vta-service's own
/// `url_direct_admin_rotation_round_trips_against_rest_only_mock` test.)
async fn authorize_super_admin(mock: &MockVta, did: &str) {
    let entry = AclEntry::new(did, Role::Admin, "openvtc-e2e").with_contexts(vec![]);
    mock.ctx
        .acl_ks
        .insert(format!("acl:{did}"), &entry)
        .await
        .expect("seed super-admin acl");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA + URL-direct admin-rotation round-trip"]
async fn admin_rotation_provisions_against_mock_vta() {
    let mock = MockVta::start_provisionable().await;
    assert!(
        mock.vta_did().starts_with("did:key:z6Mk"),
        "provisionable mock must expose a real, self-resolving did:key"
    );

    let setup = EphemeralSetupKey::generate().expect("generate setup key");
    authorize_super_admin(&mock, &setup.did).await;

    // URL-direct: REST to base_url() with the configured vta_did, no DID→URL
    // resolution — the seam OpenVTC's bootstrap takes when OPENVTC_VTA_URL is set.
    let reply = provision_admin_rotated_via_rest(
        mock.base_url(),
        mock.vta_did(),
        setup.did.clone(),
        setup.private_key_multibase().to_string(),
        ProvisionAsk::vta_admin_rotated("ctx1"),
    )
    .await
    .expect("URL-direct admin rotation round-trips against MockVta");

    assert!(
        reply.admin_did.starts_with("did:key:"),
        "rotated admin must be a did:key, got {}",
        reply.admin_did
    );
    assert_ne!(
        reply.admin_did, setup.did,
        "rotation must mint a fresh admin DID, not echo the ephemeral setup DID"
    );
    assert!(
        !reply.admin_private_key_mb.is_empty(),
        "the rotated admin must carry its private key"
    );

    mock.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA"]
async fn bootstrap_creates_top_context_and_lists_webvh_server() {
    let mock = MockVta::start_provisionable().await;

    // Authenticated client. `mint_token` with an empty contexts vec is
    // super-admin (top-level context creation is super-admin only); it bypasses
    // the DIDComm-packed live handshake the REST-only mock can't unpack.
    let token = mock
        .ctx
        .mint_token("did:key:z6MkOpenVtcAdmin", "admin", vec![])
        .await;
    let client = VtaClient::new(mock.base_url());
    client.set_token_async(token).await;

    // State-A: create the account's top-level context.
    let ctx = client
        .create_context(CreateContextRequest {
            id: "openvtc-acct".to_string(),
            name: "OpenVTC Account".to_string(),
            description: None,
            parent: None,
        })
        .await
        .expect("create top-level context");
    assert_eq!(ctx.id, "openvtc-acct");

    // A webvh hosting server must be in the catalogue for a later persona
    // did:webvh mint to find one to publish to.
    mock.seed_webvh_server("prod", "did:webvh:host.example.com")
        .await;
    let servers = client
        .list_webvh_servers()
        .await
        .expect("list webvh servers");
    assert!(
        servers
            .servers
            .iter()
            .any(|s| s.id == "prod" && s.did == "did:webvh:host.example.com"),
        "seeded webvh server must appear in the catalogue, got {:?}",
        servers.servers
    );

    mock.shutdown().await;
}
