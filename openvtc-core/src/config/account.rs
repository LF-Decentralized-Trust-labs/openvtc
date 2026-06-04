/*!
 * Multi-community account model (config v2).
 *
 * Replaces the single-persona / single-VTA singleton with an `Account` that
 * owns a collection of [`PersonaRecord`]s and a collection of
 * [`CommunityRecord`]s. See `docs/design/multi-community-support.md` and
 * `docs/design/t1-active-identity-api.md`.
 *
 * Scope note: this module defines the **persisted metadata** model, stored
 * encrypted in the `ProtectedConfig` tier and treated by `Config::load_step2`
 * as the source of truth for the active persona. The account admin credential
 * (a secret) stays in `SecuredConfig`/keyring; persona key material is
 * VTA-managed (`key_refs` are non-secret ids, D12). Runtime resolution lives in
 * [`crate::identity`] (`IdentityContext` / `IdentityRegistry`).
 */

use crate::config::KeyTypes;
use crate::relationships::Relationships;
use crate::vrc::Vrcs;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A VTC community is keyed by its DID (`did:webvh:...`).
pub type VtcDid = String;

/// Stable, rotation-safe identifier for a persona.
///
/// Decoupled from the persona's `did:webvh` (which can rotate) so that a
/// community's `persona_ref` survives DID rotation (fork resolution: stable
/// UUID).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersonaId(pub Uuid);

impl PersonaId {
    /// Mint a fresh persona id.
    pub fn new() -> Self {
        PersonaId(Uuid::new_v4())
    }
}

impl Default for PersonaId {
    fn default() -> Self {
        PersonaId::new()
    }
}

impl std::fmt::Display for PersonaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A non-secret reference to a VTA-managed key (D12).
///
/// Key material lives at the VTA and is fetched at runtime; only the opaque
/// `key_id`, its purpose, and creation time are persisted locally.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRef {
    /// Opaque VTA key identifier.
    pub key_id: String,
    /// What the key is used for.
    pub purpose: KeyTypes,
    /// When the key was created.
    pub created_at: DateTime<Utc>,
}

/// An account-level persona — a self-contained `did:webvh` identity that one or
/// more communities may present (D6: context-independent; D1: reusable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersonaRecord {
    /// Stable identifier (rotation-safe).
    pub persona_id: PersonaId,
    /// The persona's `did:webvh`.
    pub did: String,
    /// Non-secret references to this persona's VTA-managed keys.
    pub key_refs: Vec<KeyRef>,
    /// Mediator DID; defaults to the VTA mediator, optional override at mint (D7).
    pub mediator_did: Option<String>,
    /// The sub-context the persona was minted under — provenance only (D6).
    pub origin_context_id: String,
    /// When the persona was created.
    pub created_at: DateTime<Utc>,
    /// Optional human-friendly label.
    pub label: Option<String>,
}

/// Lifecycle state of a community membership (D8). Only [`Active`] is live; all
/// other states are read-only (D14).
///
/// [`Active`]: CommunityStatus::Active
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CommunityStatus {
    /// Join request submitted, awaiting the VTC's decision.
    Pending {
        /// The join request id from the submit receipt.
        request_id: Uuid,
    },
    /// Member in good standing (the only live state).
    Active,
    /// Member voluntarily left (`MEMBER_SELF_REMOVE`).
    Left,
    /// Join request denied by the VTC.
    Rejected,
    /// Member removed by the VTC (involuntary).
    Removed,
    /// Pending join unanswered past the 7-day client timeout (D16).
    Expired,
}

impl CommunityStatus {
    /// True only for [`Active`](CommunityStatus::Active) — the single live state.
    pub fn is_active(&self) -> bool {
        matches!(self, CommunityStatus::Active)
    }

    /// True for every non-[`Active`](CommunityStatus::Active) state (read-only, D14).
    pub fn is_read_only(&self) -> bool {
        !self.is_active()
    }

    /// True for terminal/inactive states eligible for archive or delete (R-C-8):
    /// `Left`, `Rejected`, `Removed`, `Expired`. (`Pending` is not — it is still
    /// in flight.)
    pub fn is_inactive(&self) -> bool {
        matches!(
            self,
            CommunityStatus::Left
                | CommunityStatus::Rejected
                | CommunityStatus::Removed
                | CommunityStatus::Expired
        )
    }

    /// True when the community should raise the actions-required indicator
    /// (R-C-3 / R-S-2): a `Pending` decision is awaited, or there is an
    /// unacknowledged `Rejected` / `Removed` / `Expired` outcome. (Acknowledgement
    /// of the terminal states is tracked separately and layered on top.)
    pub fn needs_attention(&self) -> bool {
        matches!(
            self,
            CommunityStatus::Pending { .. }
                | CommunityStatus::Rejected
                | CommunityStatus::Removed
                | CommunityStatus::Expired
        )
    }

    /// True when the membership needs a live DIDComm session: `Active` (to
    /// operate) and `Pending` (so the VTC's join reply is receivable, D16).
    pub fn requires_live_session(&self) -> bool {
        matches!(
            self,
            CommunityStatus::Active | CommunityStatus::Pending { .. }
        )
    }
}

/// A community membership — one per State-B join, referencing an account persona.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommunityRecord {
    /// The community's VTC DID.
    pub vtc_did: VtcDid,
    /// Display name resolved from the VTC DID document, if available.
    pub display_name: Option<String>,
    /// Sub-context id under the account's top context (`<top>/<slug>`, D9).
    pub sub_context_id: String,
    /// Which account persona is presented to this VTC (must resolve, R-P-1).
    pub persona_ref: PersonaId,
    /// Membership lifecycle state.
    pub status: CommunityStatus,
    /// User-starred favourite (sorts to top; R-C-4).
    #[serde(default)]
    pub favourite: bool,
    /// User-archived (hidden from the default list; R-C-8).
    #[serde(default)]
    pub archived: bool,
    /// Set when the membership first becomes `Active` (member-since; R-C-2).
    pub member_since: Option<DateTime<Utc>>,
    /// When the join request was submitted — anchors the 7-day timeout (D16).
    pub requested_at: Option<DateTime<Utc>>,
    /// DIDComm relationships scoped to this community.
    #[serde(default)]
    pub relationships: Relationships,
    /// VRCs we have issued within this community.
    #[serde(default)]
    pub vrcs_issued: Vrcs,
    /// VRCs we have received within this community.
    #[serde(default)]
    pub vrcs_received: Vrcs,
}

/// The account — the OpenVTC ↔ VTA relationship (State-A bootstrap) plus its
/// personas and community memberships.
///
/// The account **admin credential** is a secret and is NOT stored here — it
/// lives in `SecuredConfig`/keyring (D12). This struct is the `ProtectedConfig`
/// (encrypted) metadata tier.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    /// DID of the VTA this account is provisioned against.
    pub vta_did: String,
    /// Base URL of the VTA (empty for DIDComm-only VTAs).
    pub vta_url: String,
    /// The top-level context this account administers.
    pub top_context_id: String,
    /// Organisation DID this account is affiliated with (the former
    /// `public.lk_did` singleton). Account-level, not persona-scoped.
    #[serde(default)]
    pub org_did: String,
    /// Account personas, keyed by stable id.
    #[serde(default)]
    pub personas: HashMap<PersonaId, PersonaRecord>,
    /// Community memberships, keyed by VTC DID.
    #[serde(default)]
    pub communities: HashMap<VtcDid, CommunityRecord>,
}

impl Account {
    /// Resolve the persona presented to a given community, following
    /// `persona_ref`. Returns `None` if the community is unknown or its
    /// `persona_ref` dangles (a referential-integrity violation; see
    /// [`Self::dangling_refs`]).
    pub fn persona_for(&self, vtc: &VtcDid) -> Option<&PersonaRecord> {
        let community = self.communities.get(vtc)?;
        self.personas.get(&community.persona_ref)
    }

    /// True if any community references this persona.
    pub fn persona_referenced(&self, id: &PersonaId) -> bool {
        self.communities.values().any(|c| &c.persona_ref == id)
    }

    /// Whether a persona may be deleted (R-P-1): it must exist and not be
    /// referenced by any community.
    pub fn can_delete_persona(&self, id: &PersonaId) -> bool {
        self.personas.contains_key(id) && !self.persona_referenced(id)
    }

    /// Any `persona_ref`s that do not resolve to an existing persona — should
    /// always be empty (referential integrity, R-P-1).
    pub fn dangling_refs(&self) -> Vec<(&VtcDid, &PersonaId)> {
        self.communities
            .iter()
            .filter(|(_, c)| !self.personas.contains_key(&c.persona_ref))
            .map(|(vtc, c)| (vtc, &c.persona_ref))
            .collect()
    }

    /// Iterator over communities in the `Active` (live) state.
    pub fn active_communities(&self) -> impl Iterator<Item = &CommunityRecord> {
        self.communities.values().filter(|c| c.status.is_active())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona(label: &str) -> PersonaRecord {
        PersonaRecord {
            persona_id: PersonaId::new(),
            did: format!("did:webvh:example.com:{label}"),
            key_refs: vec![KeyRef {
                key_id: format!("key-{label}"),
                purpose: KeyTypes::PersonaSigning,
                created_at: Utc::now(),
            }],
            mediator_did: None,
            origin_context_id: format!("openvtc/{label}"),
            created_at: Utc::now(),
            label: Some(label.to_string()),
        }
    }

    fn community(vtc: &str, persona_ref: PersonaId, status: CommunityStatus) -> CommunityRecord {
        CommunityRecord {
            vtc_did: vtc.to_string(),
            display_name: Some(vtc.to_string()),
            sub_context_id: format!("openvtc/{vtc}"),
            persona_ref,
            status,
            favourite: false,
            archived: false,
            member_since: None,
            requested_at: None,
            relationships: Relationships::default(),
            vrcs_issued: Vrcs::default(),
            vrcs_received: Vrcs::default(),
        }
    }

    #[test]
    fn status_classification() {
        assert!(CommunityStatus::Active.is_active());
        assert!(!CommunityStatus::Active.is_read_only());
        assert!(!CommunityStatus::Active.needs_attention());

        for s in [
            CommunityStatus::Left,
            CommunityStatus::Rejected,
            CommunityStatus::Removed,
            CommunityStatus::Expired,
        ] {
            assert!(s.is_read_only(), "{s:?} should be read-only");
            assert!(s.is_inactive(), "{s:?} should be inactive (archive/delete)");
        }

        let pending = CommunityStatus::Pending {
            request_id: Uuid::new_v4(),
        };
        assert!(pending.is_read_only());
        assert!(!pending.is_inactive(), "pending is in-flight, not inactive");
        assert!(pending.needs_attention());
        assert!(CommunityStatus::Rejected.needs_attention());
        assert!(!CommunityStatus::Left.needs_attention());
    }

    #[test]
    fn persona_for_resolves_ref() {
        let mut acct = Account::default();
        let p = persona("alice");
        let pid = p.persona_id;
        acct.personas.insert(pid, p);
        acct.communities.insert(
            "vtc:a".into(),
            community("vtc:a", pid, CommunityStatus::Active),
        );

        let resolved = acct.persona_for(&"vtc:a".to_string()).expect("resolves");
        assert_eq!(resolved.persona_id, pid);
        assert!(acct.persona_for(&"vtc:missing".to_string()).is_none());
        assert!(acct.dangling_refs().is_empty());
    }

    #[test]
    fn referential_integrity_blocks_persona_delete() {
        let mut acct = Account::default();
        let p = persona("bob");
        let pid = p.persona_id;
        acct.personas.insert(pid, p);

        // Unreferenced: deletable.
        assert!(acct.can_delete_persona(&pid));

        // Now referenced by an active community: not deletable (R-P-1).
        acct.communities.insert(
            "vtc:b".into(),
            community("vtc:b", pid, CommunityStatus::Active),
        );
        assert!(acct.persona_referenced(&pid));
        assert!(!acct.can_delete_persona(&pid));

        // Unknown persona is never deletable.
        assert!(!acct.can_delete_persona(&PersonaId::new()));
    }

    #[test]
    fn active_communities_filters() {
        let mut acct = Account::default();
        let p = persona("carol");
        let pid = p.persona_id;
        acct.personas.insert(pid, p);
        acct.communities
            .insert("a".into(), community("a", pid, CommunityStatus::Active));
        acct.communities
            .insert("b".into(), community("b", pid, CommunityStatus::Left));
        acct.communities.insert(
            "c".into(),
            community(
                "c",
                pid,
                CommunityStatus::Pending {
                    request_id: Uuid::new_v4(),
                },
            ),
        );
        assert_eq!(acct.active_communities().count(), 1);
    }

    #[test]
    fn account_json_round_trip_preserves_shape() {
        let mut acct = Account {
            vta_did: "did:webvh:vta.example".into(),
            vta_url: "https://vta.example".into(),
            top_context_id: "openvtc".into(),
            ..Account::default()
        };
        let p = persona("dave");
        let pid = p.persona_id;
        let req = Uuid::new_v4();
        acct.personas.insert(pid, p);
        acct.communities.insert(
            "vtc:x".into(),
            community("vtc:x", pid, CommunityStatus::Pending { request_id: req }),
        );

        let json = serde_json::to_string(&acct).expect("serialize");
        let back: Account = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.vta_did, acct.vta_did);
        assert_eq!(back.top_context_id, "openvtc");
        assert_eq!(back.personas.len(), 1);
        let bp = back.personas.get(&pid).expect("persona survives");
        assert_eq!(bp.did, "did:webvh:example.com:dave");
        let bc = back.communities.get("vtc:x").expect("community survives");
        assert_eq!(bc.persona_ref, pid);
        assert_eq!(bc.status, CommunityStatus::Pending { request_id: req });
    }

    #[test]
    fn community_status_tag_is_stable() {
        // The serde tag is part of the on-disk format; pin it.
        let j = serde_json::to_string(&CommunityStatus::Active).unwrap();
        assert_eq!(j, r#"{"state":"active"}"#);
        let j = serde_json::to_string(&CommunityStatus::Expired).unwrap();
        assert_eq!(j, r#"{"state":"expired"}"#);
    }
}
