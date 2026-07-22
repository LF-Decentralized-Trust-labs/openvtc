//! Off-loop batch resolution of agent names.
//!
//! The runtime loop collects the DIDs whose names are uncached or stale
//! ([`Config::agent_name_refresh_targets`](openvtc_core::config::Config::agent_name_refresh_targets))
//! and hands the whole list to [`resolve_batch`] as a single background job. One
//! job (not one per DID) because the background-dispatch busy-guard is
//! per-domain: per-DID jobs on the shared `AgentName` domain would serialise.
//!
//! Inside the job the DIDs resolve concurrently but **bounded** — a sliding
//! window of at most [`CONCURRENCY`] in flight — so a large account does not
//! open an unbounded fan of connections at the resolver (VTI R1.4). The job does
//! I/O only; its `(did, name)` results are applied to the config on the loop
//! thread by `background_dispatch::apply_outcome`, preserving the single-mutator
//! invariant.

// The resolver type, re-exported by the TDK facade so this crate needs no
// direct dependency on the cache SDK.
use affinidi_tdk::did_resolver::DIDCacheClient;
use tokio::task::JoinSet;

/// Maximum concurrent DID resolutions inside one batch job.
const CONCURRENCY: usize = 4;

/// Resolve each DID to a verified agent name (or `None`), bounded to
/// [`CONCURRENCY`] in flight. The result pairs each input DID with its verified
/// name; order is not preserved (the caller keys by DID).
pub(crate) async fn resolve_batch(
    resolver: DIDCacheClient,
    dids: Vec<String>,
) -> Vec<(String, Option<String>)> {
    let mut out = Vec::with_capacity(dids.len());
    let mut pending = dids.into_iter();
    let mut in_flight: JoinSet<(String, Option<String>)> = JoinSet::new();

    let spawn_one = |set: &mut JoinSet<(String, Option<String>)>, did: String| {
        let resolver = resolver.clone();
        set.spawn(async move {
            let name = openvtc_core::agent_name::resolve_verified_name(&resolver, &did).await;
            (did, name)
        });
    };

    // Prime the window, then keep it full: each completion spawns the next DID.
    for _ in 0..CONCURRENCY {
        if let Some(did) = pending.next() {
            spawn_one(&mut in_flight, did);
        }
    }
    while let Some(joined) = in_flight.join_next().await {
        // A resolution task does not panic (its body is fallible-by-Option), so
        // a JoinError would be a cancellation; drop it and keep going.
        if let Ok(pair) = joined {
            out.push(pair);
        }
        if let Some(did) = pending.next() {
            spawn_one(&mut in_flight, did);
        }
    }
    out
}
