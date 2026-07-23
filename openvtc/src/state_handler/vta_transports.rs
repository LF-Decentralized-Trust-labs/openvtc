//! Off-loop probe of the transports a VTA advertises.
//!
//! The VTA panel used to show a bare `VTA URL`, which says nothing about *how*
//! the CLI is talking to the VTA — the URL stays populated on the DIDComm path
//! too, where it is only the REST fallback. What the operator needs is the pair
//! "what does this VTA offer" / "which one are we on".
//!
//! The second half is free (see
//! [`VtaTransports::in_use`](crate::state_handler::main_page::content::VtaTransports::in_use)).
//! The first needs the VTA's DID document resolved, so it runs here as a
//! background job on its own dispatch domain and is applied to the panel state
//! on the loop thread, preserving the single-mutator invariant.
//!
//! The endpoint extraction is **not** hand-rolled: `vta_sdk`'s
//! `provision_client::resolve_vta` already reads the `#vta-rest` and
//! `DIDCommMessaging` services out of the document, and the setup flow calls the
//! same function — so the panel and the bootstrap diagnostics can never disagree
//! about what a VTA advertises.

use crate::state_handler::main_page::content::AdvertisedTransports;

/// Probe `vta_did` for its advertised transports.
///
/// Never fails: a resolve error comes back as an `AdvertisedTransports` with
/// [`error`](AdvertisedTransports::error) set and both endpoints `None`, so the
/// panel can say "could not check" instead of rendering an unreachable VTA as
/// one that offers nothing (VTI R6.4).
pub(crate) async fn probe(vta_did: String) -> AdvertisedTransports {
    match vta_sdk::provision_client::resolve_vta(&vta_did).await {
        Ok(resolved) => AdvertisedTransports {
            mediator_did: resolved.mediator_did,
            rest_url: resolved.rest_url,
            error: None,
        },
        Err(e) => {
            tracing::debug!("VTA transport probe for {vta_did} failed: {e}");
            AdvertisedTransports {
                mediator_did: None,
                rest_url: None,
                error: Some(e.to_string()),
            }
        }
    }
}
