//! Managing agent names on the account's own personas.
//!
//! The consumer side ([`openvtc_core::agent_name`]) *reads* agent names. This
//! module *writes* them: bind (`set`), release (`remove`), park (`disable`) and
//! resume (`enable`) a name on a persona the VTA hosts, plus `list` (the
//! authoritative registry, parked names included) and `check` (availability).
//!
//! Every verb is a VTA Trust Task (`spec/vta/webvh/agent-name/{op}/1.0`),
//! submitted through [`VtaClient::dispatch_trust_task`]. The VTA is the party
//! with authority over the account's webvh DIDs — it created them and holds
//! their update keys — so it resolves the DID's current document, edits
//! `alsoKnownAs`, signs a new version, and calls the hosting server. OpenVTC
//! only names the persona DID and the name; it never signs here.
//!
//! `remove` releases a name for anyone to reclaim; `disable` keeps it reserved
//! but stops it resolving. Both report `enabled: false`.

use anyhow::{Context, Result};
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::did_management::agent_name::{
    AgentNameCheckResultBody, AgentNameEntry, AgentNameListResultBody, AgentNameResultBody,
};
use vta_sdk::trust_tasks;

/// Trust-task round-trips can involve a webvh publish (sign + host write), so
/// allow more headroom than a plain read.
const AGENT_NAME_TT_TIMEOUT: u64 = 60;

/// The host a `did:webvh` is served from (`example.com`, or `example.com:8443`
/// for a custom port) — the authority half of any agent name on it. Derived via
/// `didwebvh-rs` per the repo's did:webvh rule; `None` if the DID does not
/// parse. Used only to build the scheme-less name (`host/@local`) for the local
/// display cache; the VTA derives the domain itself for the actual operations.
pub(crate) fn derive_host(did: &str) -> Option<String> {
    let url = didwebvh_rs::url::WebVHURL::parse_did_url(did).ok()?;
    Some(match url.port {
        Some(port) => format!("{}:{port}", url.domain),
        None => url.domain,
    })
}

/// Bind (or refresh) `name` on `did`. The resulting document claims the name;
/// it resolves once the host serves the new version.
pub(crate) async fn set_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_SET_1_0,
        did,
        Some(name),
    )
    .await
}

/// Release `name` from `did` — it stops resolving and is free for anyone to
/// reclaim. Destructive.
pub(crate) async fn remove_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_REMOVE_1_0,
        did,
        Some(name),
    )
    .await
}

/// Resume serving a parked `name` on `did`.
pub(crate) async fn enable_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_ENABLE_1_0,
        did,
        Some(name),
    )
    .await
}

/// Park `name` on `did` — it stops resolving but stays reserved to this DID.
pub(crate) async fn disable_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_DISABLE_1_0,
        did,
        Some(name),
    )
    .await
}

/// The DID's agent-name registry as the host holds it — parked names included.
pub(crate) async fn list_names(vta: &VtaClient, did: &str) -> Result<Vec<AgentNameEntry>> {
    let value = vta
        .dispatch_trust_task(
            trust_tasks::TASK_WEBVH_AGENT_NAME_LIST_1_0,
            serde_json::json!({ "did": did }),
            AGENT_NAME_TT_TIMEOUT,
        )
        .await
        .context("agent-name list task failed")?;
    let body: AgentNameListResultBody =
        serde_json::from_value(value).context("decoding agent-name list result")?;
    Ok(body.names)
}

/// Whether `name` is free to claim on `did`'s host. `available` is `false` for a
/// reserved name too — `reserved` distinguishes the two.
pub(crate) async fn check_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameCheckResultBody> {
    let value = vta
        .dispatch_trust_task(
            trust_tasks::TASK_WEBVH_AGENT_NAME_CHECK_1_0,
            serde_json::json!({ "did": did, "name": name }),
            AGENT_NAME_TT_TIMEOUT,
        )
        .await
        .context("agent-name check task failed")?;
    serde_json::from_value(value).context("decoding agent-name check result")
}

/// Shared submit for the four mutating verbs, which share the `{ did, name }`
/// body and `AgentNameResultBody` shape.
async fn dispatch(
    vta: &VtaClient,
    type_uri: &str,
    did: &str,
    name: Option<&str>,
) -> Result<AgentNameResultBody> {
    let mut payload = serde_json::json!({ "did": did });
    if let Some(name) = name {
        payload["name"] = serde_json::Value::String(name.to_string());
    }
    let value = vta
        .dispatch_trust_task(type_uri, payload, AGENT_NAME_TT_TIMEOUT)
        .await
        .with_context(|| format!("agent-name task {type_uri} failed"))?;
    serde_json::from_value(value).context("decoding agent-name result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_host_pulls_the_domain_from_a_webvh_did() {
        assert_eq!(
            derive_host("did:webvh:QmScid:example.com").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn derive_host_includes_a_custom_port() {
        // did:webvh encodes ports as %3A within the path segment.
        assert_eq!(
            derive_host("did:webvh:QmScid:example.com%3A8443").as_deref(),
            Some("example.com:8443")
        );
    }

    #[test]
    fn derive_host_rejects_a_non_webvh_did() {
        assert_eq!(derive_host("did:key:z6Mk"), None);
    }
}
