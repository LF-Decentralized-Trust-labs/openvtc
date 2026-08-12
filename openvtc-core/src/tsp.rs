/*!
 * The TSP send leg for VTC-facing ceremonies (#185 item 2f).
 *
 * ## Why this is send-only
 *
 * Inbound TSP is **already arriving**. `DidCommTransport` owns the one mediator
 * websocket and surfaces both protocols off it, unpacking each TSP frame with
 * `atm.tsp().unpack` — which authenticates the sender VID — and tagging it
 * `Protocol::TSP`. So receiving needed no new transport, only routing: see
 * `didcomm::tsp_frame_to_message`, where those frames used to be dropped.
 *
 * What was missing is the other direction. `ATM::forward_and_send_message` — the
 * send half of [`crate::pack_and_send`] — builds a DIDComm `routing/2.0` forward
 * unconditionally, so it cannot carry a Trust Task document as TSP. This module
 * is that one missing call and nothing more.
 *
 * Send-only is also why there is **no second websocket**. The mediator permits
 * one channel per DID and evicts a second as `duplicate-channel`; a TSP send is
 * an HTTP post through the mediator, holding no socket of its own, so it cannot
 * duel with the DIDComm one. Same shape as the VTA leg
 * (`enable_tsp_trust_tasks`) and for the same reason.
 *
 * ## Why this is not a `MessageTransport`
 *
 * The delivery layer would take one — `MessagingService` holds any number of
 * transports over a single outbox, which is what `OutboxEntry::via` exists for —
 * and an earlier draft of this change registered a TSP leg that way.
 *
 * It was the wrong fit *here*. The ceremony sends do not go through the delivery
 * layer at all: [`crate::pack_and_send`] posts straight through the ATM, so a
 * TSP leg on the outbox would have given TSP joins durability that DIDComm joins
 * do not have, and would have meant threading a `Messaging` handle down into
 * `join_flow.rs`. Matching the transport this change is *about* — same call
 * shape, same failure semantics, only the wire differs — keeps the swap
 * reviewable and the two paths comparable.
 *
 * Putting the ceremony sends behind the outbox is worth doing, but for **both**
 * transports at once and as its own change; doing it here would have hidden a
 * durability change inside a transport change.
 */

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use serde_json::Value;

use crate::errors::OpenVTCError;

/// Seal a Trust Task `document` to `to_did` and route it through that peer's
/// advertised TSP mediator.
///
/// The TSP counterpart of [`crate::pack_and_send`], and deliberately the same
/// signature shape so the two are directly comparable at a call site.
///
/// `tsp_mediator_did` is the peer's **advertised** `#tsp` mediator — the hop the
/// routing layer is sealed to — not ours. That is the addressing information the
/// peer published for exactly this purpose (`discover_tsp_mediator`), and using
/// ours instead would only work while the two happen to coincide.
///
/// Unlike the DIDComm path the caller does **not** pack: `send_routed` seals the
/// payload end-to-end to `route.last()` and wraps that in a routing layer sealed
/// to `route[0]`, so the document goes in as plaintext JSON.
///
/// # Errors
///
/// Returns [`OpenVTCError`] if the document will not serialise, or if the
/// mediator did not accept the frame. The message names the peer, the routing
/// hop, **and the mediator the frame was actually posted to** (R6.4), so an
/// operator can tell a wrong advertised mediator from a refused send from an
/// unreachable hop.
///
/// Naming all three is not belt-and-braces. `send_routed` posts to the
/// *profile's* mediator — `route[0]` is sealed into the frame, not dialled — so
/// a rejection quoting only the advertised mediator sends an operator to inspect
/// a host that never received the request. That happened: a mediator built
/// without its `tsp` feature answered `400 w.m.message.deserialize` (it fed the
/// CESR frame to the DIDComm JSON parser), under an error naming the peer's
/// perfectly healthy TSP mediator.
pub async fn send_trust_task(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    document: &Value,
    to_did: &str,
    tsp_mediator_did: &str,
) -> Result<(), OpenVTCError> {
    let payload = serde_json::to_vec(document)
        .map_err(|e| OpenVTCError::Config(format!("serialise Trust Task document for TSP: {e}")))?;
    let route = [tsp_mediator_did.to_string(), to_did.to_string()];

    atm.tsp()
        .send_routed(profile, &route, &payload)
        .await
        .map_err(|e| {
            // Best-effort: a profile that cannot name its own mediator is not a
            // reason to lose the send error we actually have to report.
            let our_mediator = profile
                .dids()
                .map(|(_, mediator)| mediator.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            OpenVTCError::Config(format!(
                "TSP send to {to_did} (routed via its advertised mediator \
                 {tsp_mediator_did}, posted through our own mediator \
                 {our_mediator}): {e}"
            ))
        })
}

#[cfg(test)]
mod tests {

    /// The hop order is the part that is easy to get backwards and impossible to
    /// see in a signature: `route[0]` is the mediator the routing layer is sealed
    /// to, `route.last()` the final recipient the payload is sealed to. Reversed,
    /// the mediator would receive a frame it cannot forward.
    #[test]
    fn route_is_mediator_then_recipient() {
        let to = "did:webvh:example:vtc";
        let mediator = "did:webvh:example:mediator";
        let route = [mediator.to_string(), to.to_string()];

        assert_eq!(route[0], mediator, "route[0] must be the routing hop");
        assert_eq!(
            route.last().map(String::as_str),
            Some(to),
            "route.last() must be the final recipient"
        );
    }
}
