//! Keeps this install visible to the rest of the account, and notices the
//! others.
//!
//! Runs as one long-lived background task (D13). It never touches `State` —
//! it sends [`PresenceReport`]s down a channel that the state-handler loop owns,
//! preserving the single-mutator rule, and it never blocks startup: the first
//! registration happens inside the task, so a VTA that is slow, offline, or does
//! not implement the device slice costs nothing but a log line.
//!
//! # Why it re-lists rather than only registering once
//!
//! A sibling that starts *after* us would otherwise be invisible until the next
//! launch — and the case that matters is precisely someone opening a second
//! instance while the first is running. Listing on each heartbeat costs one
//! extra trust task per interval and turns the mediator's mutual-eviction loop
//! from a mystery into a sentence.

use openvtc_core::devices::{self, DeviceRecord};
use std::collections::BTreeSet;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};
use vta_sdk::client::VtaClient;

/// What the presence task tells the loop.
#[derive(Clone, Debug)]
pub enum PresenceReport {
    /// This install's own binding, once claimed. Lets the loop name us and
    /// gives the sibling filter something to exclude.
    Registered {
        /// The VTA's id for our binding.
        device_id: String,
    },
    /// Siblings that were not live last time we looked.
    ///
    /// Only the *newly* seen ones, because the loop logs what it receives and a
    /// warning repeated every five minutes is one the user learns to ignore.
    NewSiblings(Vec<DeviceRecord>),
    /// Registration or listing failed. Non-fatal, but worth one line so the
    /// absence of sibling warnings is not mistaken for an absence of siblings.
    Unavailable(String),
}

/// Register this install, then heartbeat and watch for siblings until cancelled.
///
/// Returns when `tx` closes — i.e. when the state handler exits.
pub async fn run(client: VtaClient, profile: String, tx: UnboundedSender<PresenceReport>) {
    let self_id = match devices::register(&client, &profile).await {
        Ok(record) => {
            info!(device_id = %record.device_id, "registered this install with the VTA");
            if tx
                .send(PresenceReport::Registered {
                    device_id: record.device_id.clone(),
                })
                .is_err()
            {
                return;
            }
            Some(record.device_id)
        }
        Err(e) => {
            // Not fatal: a VTA without the device slice, or one briefly
            // unreachable, must not degrade anything the user came here for.
            warn!("device registration unavailable: {e}");
            let _ = tx.send(PresenceReport::Unavailable(e.to_string()));
            None
        }
    };

    // Siblings already reported, so a steady state stays quiet. Keyed by
    // device id rather than by the whole record, because `lastSeenAt` changes
    // on every heartbeat and would otherwise re-announce the same machine.
    let mut announced: BTreeSet<String> = BTreeSet::new();

    loop {
        match devices::list(&client).await {
            Ok(all) => {
                let live = devices::live_siblings(&all, self_id.as_deref(), chrono::Utc::now());
                let fresh = newly_appeared(&mut announced, &live);
                if !fresh.is_empty() && tx.send(PresenceReport::NewSiblings(fresh)).is_err() {
                    return;
                }
            }
            Err(e) => debug!("device listing unavailable: {e}"),
        }

        tokio::time::sleep(devices::HEARTBEAT_INTERVAL).await;
        if tx.is_closed() {
            return;
        }
        if let Err(e) = devices::heartbeat(&client).await {
            // A missed beat is recoverable — the liveness window tolerates one
            // — so this is debug, not a warning the user needs to see.
            debug!("device heartbeat failed: {e}");
        }
    }
}

/// Which of `live` have not been announced yet, updating `announced` to match.
///
/// Two properties, and both matter to whether the warning is worth having:
///
/// - A sibling seen again is **not** re-reported. `lastSeenAt` changes on every
///   heartbeat, so comparing whole records would re-announce the same machine
///   every interval, and a warning shown every five minutes is one the user
///   learns to scroll past.
/// - A sibling that goes away is **forgotten**, so closing and reopening that
///   instance announces it again. That is a fresh collision, not a duplicate.
fn newly_appeared(announced: &mut BTreeSet<String>, live: &[DeviceRecord]) -> Vec<DeviceRecord> {
    let fresh: Vec<DeviceRecord> = live
        .iter()
        .filter(|d| !announced.contains(&d.device_id))
        .cloned()
        .collect();

    // Rebuilt from what is live now, so departures drop out.
    *announced = live.iter().map(|d| d.device_id.clone()).collect();
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> DeviceRecord {
        DeviceRecord {
            device_id: id.to_string(),
            display_name: format!("OpenVTC on {id}"),
            platform: None,
            registered_at: None,
            last_seen_at: Some(chrono::Utc::now().to_rfc3339()),
            disabled_at: None,
            wiped_at: None,
        }
    }

    #[test]
    fn a_new_sibling_is_announced_once() {
        let mut announced = BTreeSet::new();
        let live = vec![record("laptop")];

        let first = newly_appeared(&mut announced, &live);
        assert_eq!(first.len(), 1, "first sighting must be announced");

        let second = newly_appeared(&mut announced, &live);
        assert!(
            second.is_empty(),
            "a steady state must stay quiet — a warning every interval is one \
             the user learns to ignore"
        );
    }

    /// `lastSeenAt` changes on every heartbeat. Keying on the whole record
    /// would re-announce the same machine forever.
    #[test]
    fn a_refreshed_timestamp_is_not_a_new_sibling() {
        let mut announced = BTreeSet::new();
        let _ = newly_appeared(&mut announced, &[record("laptop")]);

        let mut later = record("laptop");
        later.last_seen_at = Some((chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339());
        assert!(newly_appeared(&mut announced, &[later]).is_empty());
    }

    #[test]
    fn a_sibling_that_leaves_and_returns_is_announced_again() {
        let mut announced = BTreeSet::new();
        let _ = newly_appeared(&mut announced, &[record("laptop")]);

        // Closed: no longer live.
        assert!(newly_appeared(&mut announced, &[]).is_empty());

        // Reopened — a fresh collision, and worth saying so.
        let again = newly_appeared(&mut announced, &[record("laptop")]);
        assert_eq!(again.len(), 1);
    }

    #[test]
    fn only_the_new_one_is_announced_when_another_joins() {
        let mut announced = BTreeSet::new();
        let _ = newly_appeared(&mut announced, &[record("laptop")]);

        let fresh = newly_appeared(&mut announced, &[record("laptop"), record("desktop")]);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].device_id, "desktop");
    }

    #[test]
    fn no_siblings_announces_nothing() {
        let mut announced = BTreeSet::new();
        assert!(newly_appeared(&mut announced, &[]).is_empty());
        assert!(announced.is_empty());
    }
}
