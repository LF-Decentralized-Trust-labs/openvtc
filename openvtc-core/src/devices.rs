//! Which installs are using this account, and which of them are live.
//!
//! # Why this exists
//!
//! OpenVTC's only concurrency guard is a local PID lock file keyed on the
//! config directory and profile name. It catches one case — the same profile
//! started twice from the same config path — and nothing else. Two config
//! paths, two profile names sharing a persona, or two machines are all
//! invisible to it.
//!
//! That matters more than it sounds, because the failure is already real: the
//! mediator's ceiling is **one websocket per DID**, and it enforces that by
//! *evicting* the established connection. Two installs presenting the same
//! persona therefore take turns evicting each other and both reconnect-loop,
//! which presents as a network fault rather than as "you have this open twice".
//!
//! This module does not stop that. It makes it **visible**, which is the part
//! that can be built today with no VTA change: a `DeviceBinding` is *"the
//! device-facing half of an `AclEntry`"*, each install already has its own, and
//! the binding carries `lastSeenAt`. Register on connect, heartbeat on a timer,
//! and the account can be asked who else is here.
//!
//! # Everything here is best-effort
//!
//! Device registration is diagnostic, not functional. A VTA that does not
//! support the device slice, or a call that times out, must never stop OpenVTC
//! starting — the user's account works regardless of whether we can enumerate
//! its devices. Every entry point returns a `Result` the caller is expected to
//! log and move past.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;

/// How often a running instance refreshes its `lastSeenAt`.
///
/// Five minutes is a deliberate compromise: frequent enough that a sibling is
/// noticed within a useful window, rare enough that it is not a meaningful
/// share of the trust-task traffic on a busy account.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300);

/// How recently a device must have been seen to count as live.
///
/// Three heartbeat intervals. Tolerates one missed beat plus clock skew between
/// the two machines without declaring a running sibling dead — a false "nobody
/// else is here" is the worse error, because it is the one that lets a user walk
/// into the eviction loop believing they are alone.
pub const LIVENESS_WINDOW: Duration = Duration::from_secs(900);

/// One registered install of an application against this account.
///
/// Deserialized tolerantly from the `device/list` payload: the VTA owns this
/// shape, several fields are optional on legacy rows, and an unrecognised
/// addition must not fail the listing. Only what OpenVTC actually shows is
/// modelled.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    /// The VTA's identifier for this binding.
    pub device_id: String,
    /// Human-readable name the device chose for itself.
    #[serde(default)]
    pub display_name: String,
    /// Operating system the device reported.
    #[serde(default)]
    pub platform: Option<String>,
    /// RFC 3339 — when the binding was claimed.
    #[serde(default)]
    pub registered_at: Option<String>,
    /// RFC 3339 — refreshed by every heartbeat and successful auth.
    #[serde(default)]
    pub last_seen_at: Option<String>,
    /// Set once the binding has been disabled; it can no longer authenticate.
    #[serde(default)]
    pub disabled_at: Option<String>,
    /// Set once a remote wipe has been issued for the device.
    #[serde(default)]
    pub wiped_at: Option<String>,
}

impl DeviceRecord {
    /// Whether this binding can still authenticate.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.disabled_at.is_none() && self.wiped_at.is_none()
    }

    /// When this device was last seen, if it reported a parseable timestamp.
    #[must_use]
    pub fn last_seen(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_seen_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }

    /// Whether this device has been seen within [`LIVENESS_WINDOW`] of `now`.
    ///
    /// A binding with no timestamp is **not** live: absence of evidence is
    /// treated as absence, because claiming a stale device is running would
    /// send the user chasing a machine that is switched off.
    #[must_use]
    pub fn is_live_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if !self.is_active() {
            return false;
        }
        let Some(seen) = self.last_seen() else {
            return false;
        };
        match (now - seen).to_std() {
            Ok(elapsed) => elapsed <= LIVENESS_WINDOW,
            // Negative: the device's clock is ahead of ours. Skew is not
            // staleness, so treat it as live rather than reporting a machine
            // that is plainly running as gone.
            Err(_) => true,
        }
    }

    /// Name for the UI, falling back to the id when the device gave none.
    #[must_use]
    pub fn label(&self) -> &str {
        if self.display_name.is_empty() {
            &self.device_id
        } else {
            &self.display_name
        }
    }
}

/// The `consumerKind` OpenVTC registers under.
///
/// `companion` / `desktop`, not `service` — OpenVTC is an interactive desktop
/// application, and the distinction is what lets an operator tell a person's
/// laptop from a daemon in `pnm device list`.
///
/// The wire form is camelCase (`formFactor`), verified against the VTA's own
/// `kind_to_wire` rather than the internal type, which is kebab-cased and never
/// crosses the wire (dev-guide R3.6).
fn consumer_kind() -> serde_json::Value {
    serde_json::json!({ "kind": "companion", "formFactor": "desktop" })
}

/// The name this install presents to the rest of the account.
///
/// Host plus profile, because both are needed to disambiguate: one machine can
/// run several profiles, and one profile name recurs across machines. This is
/// the string a user reads when told another install is live, so it has to be
/// the thing they would use to identify the machine.
#[must_use]
pub fn display_name(profile: &str) -> String {
    let host = sysinfo::System::host_name().unwrap_or_else(|| "unknown host".to_string());
    format!("OpenVTC on {host} ({profile})")
}

/// Claim or refresh this install's device binding.
///
/// Idempotent: the caller always acts on its own binding, so re-registering on
/// every launch simply refreshes the display name and platform.
///
/// # Errors
///
/// Any VTA failure. Callers log and continue — see the module docs.
pub async fn register(client: &VtaClient, profile: &str) -> Result<DeviceRecord, OpenVTCError> {
    let response = client
        .device_register(
            consumer_kind(),
            &display_name(profile),
            Some(std::env::consts::OS),
            None,
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("device registration failed: {e}")))?;

    parse_binding(&response)
        .ok_or_else(|| OpenVTCError::Vta("device registration returned no binding".to_string()))
}

/// Refresh this install's `lastSeenAt`.
///
/// # Errors
///
/// Any VTA failure.
pub async fn heartbeat(client: &VtaClient) -> Result<(), OpenVTCError> {
    client
        .device_heartbeat(Some(std::env::consts::OS))
        .await
        .map(|_| ())
        .map_err(|e| OpenVTCError::Vta(format!("device heartbeat failed: {e}")))
}

/// Every device registered against this account.
///
/// # Errors
///
/// Any VTA failure.
pub async fn list(client: &VtaClient) -> Result<Vec<DeviceRecord>, OpenVTCError> {
    let response = client
        .device_list(serde_json::json!({}))
        .await
        .map_err(|e| OpenVTCError::Vta(format!("device list failed: {e}")))?;

    let devices = response
        .get("devices")
        .and_then(|d| d.as_array())
        .ok_or_else(|| OpenVTCError::Vta("device list returned no `devices` array".to_string()))?;

    // One unparseable row must not lose the rest of the listing: this is a
    // diagnostic surface, and a partial answer beats none.
    let mut out = Vec::with_capacity(devices.len());
    for raw in devices {
        match serde_json::from_value::<DeviceRecord>(raw.clone()) {
            Ok(record) => out.push(record),
            Err(e) => debug!("skipping unparseable device row: {e}"),
        }
    }
    Ok(out)
}

/// Pull a `DeviceBinding` out of a register/heartbeat response, whether the VTA
/// returned it bare or wrapped in a `device` envelope.
fn parse_binding(response: &serde_json::Value) -> Option<DeviceRecord> {
    let candidate = response.get("device").unwrap_or(response);
    serde_json::from_value(candidate.clone()).ok()
}

/// Other installs currently using this account.
///
/// `self_device_id` is this install's binding, excluded from the result — it is
/// always live, and reporting it would make "another instance is running" fire
/// on every single launch.
#[must_use]
pub fn live_siblings(
    devices: &[DeviceRecord],
    self_device_id: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<DeviceRecord> {
    devices
        .iter()
        .filter(|d| Some(d.device_id.as_str()) != self_device_id)
        .filter(|d| d.is_live_at(now))
        .cloned()
        .collect()
}

/// One line naming the live siblings, for the activity log and the status bar.
#[must_use]
pub fn sibling_warning(siblings: &[DeviceRecord]) -> Option<String> {
    match siblings {
        [] => None,
        [one] => Some(format!(
            "This account is also open on {}. Both instances share one mediator \
             connection per persona, so messaging may be unstable until one is closed.",
            one.label()
        )),
        many => Some(format!(
            "This account is also open on {} other instances ({}). Messaging may be \
             unstable until they are closed.",
            many.len(),
            many.iter()
                .map(DeviceRecord::label)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};

    fn record(id: &str, last_seen: Option<chrono::DateTime<Utc>>) -> DeviceRecord {
        DeviceRecord {
            device_id: id.to_string(),
            display_name: format!("OpenVTC on {id}"),
            platform: Some("linux".to_string()),
            registered_at: None,
            last_seen_at: last_seen.map(|t| t.to_rfc3339()),
            disabled_at: None,
            wiped_at: None,
        }
    }

    #[test]
    fn a_recently_seen_device_is_live() {
        let now = Utc::now();
        let d = record("a", Some(now - ChronoDuration::minutes(2)));
        assert!(d.is_live_at(now));
    }

    #[test]
    fn a_stale_device_is_not_live() {
        let now = Utc::now();
        let d = record("a", Some(now - ChronoDuration::minutes(30)));
        assert!(!d.is_live_at(now));
    }

    /// One missed heartbeat must not declare a running instance dead — a false
    /// "nobody else is here" is the error that walks a user into the eviction
    /// loop believing they are alone.
    #[test]
    fn one_missed_heartbeat_is_still_live() {
        let now = Utc::now();
        let missed_one = now - ChronoDuration::from_std(HEARTBEAT_INTERVAL * 2).unwrap();
        assert!(record("a", Some(missed_one)).is_live_at(now));
    }

    /// The other machine's clock being ahead is skew, not staleness.
    #[test]
    fn a_device_whose_clock_is_ahead_is_live() {
        let now = Utc::now();
        let d = record("a", Some(now + ChronoDuration::minutes(3)));
        assert!(d.is_live_at(now), "clock skew must not read as stale");
    }

    /// No timestamp means no evidence, and no evidence is not presence.
    #[test]
    fn a_device_with_no_timestamp_is_not_live() {
        assert!(!record("a", None).is_live_at(Utc::now()));
    }

    #[test]
    fn a_disabled_or_wiped_device_is_never_live() {
        let now = Utc::now();
        let mut disabled = record("a", Some(now));
        disabled.disabled_at = Some(now.to_rfc3339());
        assert!(!disabled.is_live_at(now));

        let mut wiped = record("b", Some(now));
        wiped.wiped_at = Some(now.to_rfc3339());
        assert!(!wiped.is_live_at(now));
    }

    /// The regression that would make this feature unusable: warning about
    /// yourself on every launch.
    #[test]
    fn our_own_binding_is_never_a_sibling() {
        let now = Utc::now();
        let devices = vec![record("self", Some(now)), record("other", Some(now))];
        let siblings = live_siblings(&devices, Some("self"), now);
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0].device_id, "other");
    }

    #[test]
    fn stale_siblings_are_not_reported() {
        let now = Utc::now();
        let devices = vec![
            record("self", Some(now)),
            record("old-laptop", Some(now - ChronoDuration::days(3))),
        ];
        assert!(live_siblings(&devices, Some("self"), now).is_empty());
    }

    #[test]
    fn the_warning_names_the_other_instance() {
        let now = Utc::now();
        let siblings = vec![record("glenn-laptop", Some(now))];
        let warning = sibling_warning(&siblings).expect("a live sibling warns");
        assert!(warning.contains("OpenVTC on glenn-laptop"), "{warning}");
        assert!(warning.contains("mediator"), "{warning}");
    }

    #[test]
    fn no_siblings_means_no_warning() {
        assert!(sibling_warning(&[]).is_none());
    }

    #[test]
    fn several_siblings_are_counted_and_named() {
        let now = Utc::now();
        let siblings = vec![record("a", Some(now)), record("b", Some(now))];
        let warning = sibling_warning(&siblings).expect("warns");
        assert!(warning.contains('2'), "{warning}");
        assert!(
            warning.contains("OpenVTC on a") && warning.contains("OpenVTC on b"),
            "{warning}"
        );
    }

    /// The VTA owns this shape and legacy rows omit fields. A listing must
    /// survive both, and must not require fields OpenVTC does not use.
    #[test]
    fn a_sparse_binding_still_parses() {
        let raw = serde_json::json!({
            "deviceId": "dev-1",
            "displayName": "OpenVTC on host",
            "registeredAt": "2026-08-20T00:00:00Z",
            "somethingNewerVtasSend": true
        });
        let d: DeviceRecord = serde_json::from_value(raw).expect("tolerant parse");
        assert_eq!(d.device_id, "dev-1");
        assert!(d.last_seen_at.is_none());
        assert!(d.is_active());
    }

    #[test]
    fn a_binding_with_no_name_falls_back_to_its_id() {
        let d = DeviceRecord {
            device_id: "dev-1".to_string(),
            display_name: String::new(),
            platform: None,
            registered_at: None,
            last_seen_at: None,
            disabled_at: None,
            wiped_at: None,
        };
        assert_eq!(d.label(), "dev-1");
    }

    /// Verified against the VTA's own `kind_to_wire`: the wire form is
    /// camelCase, not the kebab-case of the internal type.
    #[test]
    fn the_consumer_kind_matches_the_vta_wire_form() {
        assert_eq!(
            consumer_kind(),
            serde_json::json!({ "kind": "companion", "formFactor": "desktop" })
        );
    }

    #[test]
    fn the_display_name_carries_host_and_profile() {
        let name = display_name("work");
        assert!(name.starts_with("OpenVTC on "), "{name}");
        assert!(name.ends_with("(work)"), "{name}");
    }
}
