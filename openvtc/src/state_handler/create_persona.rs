//! Standalone persona-DID minting.
//!
//! Mints a fresh, self-contained persona `did:webvh` into the account (D6)
//! *without* a join — the use case is handing the DID to a VTC so it can issue a
//! Verifiable Invitation Credential (VIC) bound to it; a later join then redeems
//! that VIC on the clean join-as-subject path (the VIC subject is one of our own
//! personas, so no subject-linkage proof is needed).
//!
//! This is the join flow's mint sub-sequence (`join_flow::run_join_sequence`)
//! minus the community/submit parts: pick a WebVH server, mint the DID via the
//! VTA, then persist through the shared [`ConfigExtension::mint_persona_into`].
//! The minted persona is an orphan (no community) until a join reuses it, and
//! shows in the VTA panel's Context Identities list.

use affinidi_tdk::TDK;
use anyhow::Result;
use vta_sdk::{client::VtaClient, protocols::did_management::create::WebvhPathMode};

use openvtc_core::config::{Config, KeyBackend, account::PersonaId};

use crate::state_handler::setup_sequence::{SetupState, config::ConfigExtension, vta};

/// Mint a standalone persona DID into `config` and persist it, returning its id
/// and `did:webvh`. `progress` receives a human-readable line per network step
/// (so the overlay can show what's happening). Requires the always-on admin VTA
/// session and a configured account context; errors otherwise.
///
/// Mirrors the join flow's persona mint, including using the account's VTA
/// mediator (the minted DID advertises it) and following
/// [`ConfigExtension::mint_persona_into`]'s behaviour of setting
/// `public.friendly_name` to the persona label.
pub(crate) async fn mint_standalone_persona(
    admin_vta: &VtaClient,
    tdk: &TDK,
    config: &mut Config,
    profile: &str,
    label: String,
    mut progress: impl FnMut(&str),
) -> Result<(PersonaId, String)> {
    let top_context_id = config.account.top_context_id.clone();
    if top_context_id.is_empty() {
        anyhow::bail!("No account context yet — finish setup before creating a persona.");
    }

    // Pick the first WebVH server (serverless mint is a deliberate follow-up,
    // matching the join flow).
    progress("Finding a DID hosting server…");
    let server_id = vta::list_webvh_servers(admin_vta)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No WebVH server available from the VTA (serverless mint not yet supported)."
            )
        })?
        .id;

    // Mint the persona did:webvh via the server (server-generated keys).
    progress(&format!("Creating persona DID via {server_id}…"));
    let (keys, did, document, _mnemonic) = vta::create_did_via_server(
        admin_vta,
        tdk,
        &top_context_id,
        &server_id,
        WebvhPathMode::AutoAssign,
    )
    .await?;

    // The persona's mediator is the account's VTA mediator: the DID minted via
    // the VTA's webvh server advertises that mediator, so the persona listener
    // must use the same one (mirrors the join flow).
    let custom_mediator = match &config.key_backend {
        KeyBackend::Vta { mediator_did, .. } => mediator_did.clone(),
        _ => None,
    };

    // Persist via the shared mint path. `mint_persona_into` reads the persona
    // keys, DID, document, mediator, and username from a `SetupState`, so build a
    // scratch one carrying just those — no community/sub-context is involved.
    let setup = SetupState {
        did_keys: Some(keys),
        custom_mediator,
        username: label,
        webvh_address: crate::state_handler::setup_sequence::WebVHAddress {
            did: did.clone(),
            document,
            ..Default::default()
        },
        ..Default::default()
    };

    progress("Saving persona…");
    let persona_id = Config::mint_persona_into(config, &setup, tdk, profile).await?;
    Ok((persona_id, did))
}
