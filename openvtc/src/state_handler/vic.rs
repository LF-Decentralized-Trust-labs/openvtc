//! VIC (Verifiable Invitation Credential) vault management.
//!
//! Thin async helpers over the VTA credential-vault lifecycle tasks, backing the
//! VTA Service panel's invitation-credential manager: list / import / archive /
//! unarchive / soft-delete / restore / purge the VICs a holder holds
//! (`purpose = "invite"`). Everything goes through the always-on admin VTA
//! session's credential vault. The list is built from descriptors only — a
//! query result never carries the credential body, so nothing here fetches one.

use anyhow::Result;
use vta_sdk::client::VtaClient;

use crate::state_handler::main_page::content::VicSummary;

/// Reason string stamped on lifecycle mutations (shows in the VTA audit log).
const REASON: &str = "via OpenVTC";

/// List the holder's invitation credentials. With `include_inactive`, archived
/// and soft-deleted VICs are surfaced too (so the panel can offer restore /
/// purge); otherwise only active ones are returned. `purpose = "invite"`
/// satisfies the vault's ≥1-filter requirement; the include flags are modifiers.
pub(crate) async fn list_vics(
    admin_vta: &VtaClient,
    include_inactive: bool,
) -> Result<Vec<VicSummary>> {
    let mut filter = serde_json::json!({ "purpose": "invite" });
    if include_inactive {
        filter["includeArchived"] = serde_json::Value::Bool(true);
        filter["includeDeleted"] = serde_json::Value::Bool(true);
    }
    let listing = admin_vta.cred_vault_query(filter).await?;
    let creds = listing
        .get("credentials")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    Ok(creds.iter().map(VicSummary::from_descriptor).collect())
}

/// Import a pasted VIC into the vault: validate it is an InvitationCredential,
/// then store it via `cred_vault_receive`. The vault keys it under the VC's own
/// `id`.
pub(crate) async fn add_vic(admin_vta: &VtaClient, json: &str) -> Result<()> {
    let vic: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| anyhow::anyhow!("not valid JSON: {e}"))?;
    if !openvtc_core::join::is_invitation_credential(&vic) {
        anyhow::bail!("not an invitation credential (missing the `InvitationCredential` type tag)");
    }
    admin_vta.cred_vault_receive(vic, None).await?;
    Ok(())
}

/// Archive a VIC (hidden from query/presentation, restorable via unarchive).
pub(crate) async fn archive_vic(admin_vta: &VtaClient, id: &str) -> Result<()> {
    admin_vta.cred_vault_archive(id, Some(REASON)).await?;
    Ok(())
}

/// Return an archived VIC to active.
pub(crate) async fn unarchive_vic(admin_vta: &VtaClient, id: &str) -> Result<()> {
    admin_vta.cred_vault_unarchive(id, Some(REASON)).await?;
    Ok(())
}

/// Soft-delete a VIC (recoverable tombstone within the grace window).
pub(crate) async fn delete_vic(admin_vta: &VtaClient, id: &str) -> Result<()> {
    admin_vta
        .cred_vault_delete(id, /* force */ false, Some(REASON))
        .await?;
    Ok(())
}

/// Restore a soft-deleted VIC (only within the grace window).
pub(crate) async fn restore_vic(admin_vta: &VtaClient, id: &str) -> Result<()> {
    admin_vta.cred_vault_restore(id, Some(REASON)).await?;
    Ok(())
}

/// Irreversibly purge a VIC and its index rows.
pub(crate) async fn purge_vic(admin_vta: &VtaClient, id: &str) -> Result<()> {
    admin_vta.cred_vault_purge(id, Some(REASON)).await?;
    Ok(())
}
