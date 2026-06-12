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

use crate::CredentialKind;
use crate::config::KeyTypes;
use crate::errors::OpenVTCError;
use crate::relationships::Relationships;
use crate::tasks::Tasks;
use crate::vrc::Vrcs;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

/// A VTC community is keyed by its DID (`did:webvh:...`).
pub type VtcDid = String;

/// Stable, rotation-safe identifier for a persona.
///
/// Decoupled from the persona's `did:webvh` (which can rotate) so that a
/// community's `persona_ref` survives DID rotation (fork resolution: stable
/// UUID).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// Cached resolved DID document (PERF #3: startup uses this instead of a
    /// fresh network resolve when present — did:webvh documents change rarely
    /// between launches, so a cached doc only goes stale if the persona rotated
    /// keys out-of-band). Persisted with the record; populated at mint/setup and
    /// whenever the persona is resolved. `None` for records minted before this
    /// field existed, in which case load falls back to a network resolve.
    #[serde(default)]
    pub did_document: Option<affinidi_tdk::did_common::Document>,
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

    /// The set of *statuses* that can raise the actions-required indicator
    /// (R-C-3 / R-S-2): `Pending` and the terminal `Rejected` / `Removed` /
    /// `Expired`. This is status-only; the acknowledgement-aware,
    /// per-membership predicate is [`CommunityRecord::needs_attention`], which
    /// layers the `acknowledged` flag on top.
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
#[serde(from = "CommunityRecordShadow")]
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
    /// Whether the user has acknowledged a terminal outcome
    /// (`Rejected`/`Removed`/`Expired`), clearing the actions-required badge
    /// (R-C-3 / R-S-2). Reset whenever the membership returns to a live state.
    #[serde(default)]
    pub acknowledged: bool,
    /// Set when the membership first becomes `Active` (member-since; R-C-2).
    pub member_since: Option<DateTime<Utc>>,
    /// When the join request was submitted — anchors the 7-day timeout (D16).
    pub requested_at: Option<DateTime<Utc>>,
    /// DIDComm relationships scoped to this community.
    #[serde(default)]
    pub relationships: Relationships,
    /// Reserved per-community inbox (protocol-workflow tasks). The eventual home
    /// for a physically per-community inbox; **not yet populated** — PR-1 scopes
    /// the main page by attribution (relationships/tasks carry an owning-persona
    /// tag and are filtered to the working community) while the collections stay
    /// in the global `ProtectedConfig` tier. Additive + serde(default)-tolerant
    /// so older configs load and a later physical-move migration can fill it.
    #[serde(default)]
    pub tasks: Tasks,
    /// VRCs we have issued within this community.
    #[serde(default)]
    pub vrcs_issued: Vrcs,
    /// VRCs we have received within this community.
    #[serde(default)]
    pub vrcs_received: Vrcs,
    /// Verifiable credentials this VTC has issued to us, keyed by
    /// [`CredentialKind`]. The membership credential (VMC) lands here on
    /// admission and activates the membership; the role endorsement (VEC)
    /// arrives alongside. Stored as the signed W3C VC JSON. Empty until the
    /// join is accepted and credentials arrive (R-B-8).
    ///
    /// Persisted as a JSON object keyed by [`CredentialKind::config_key`].
    /// Configs written before R19 used flat `membership_credential` /
    /// `role_credential` fields; [`CommunityRecordShadow`] folds those in on
    /// load so older configs keep working.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<CredentialKind, serde_json::Value>,
}

/// Deserialize-only shadow of [`CommunityRecord`] that folds pre-R19
/// `membership_credential` / `role_credential` fields into the typed
/// [`credentials`](CommunityRecord::credentials) registry, so older configs
/// keep loading (the project tolerates format evolution via shims, not
/// migrations). New configs deserialize straight through the `credentials`
/// object. Unknown credential keys (e.g. written by a newer version) are
/// dropped rather than failing the whole config load.
#[derive(Deserialize)]
struct CommunityRecordShadow {
    vtc_did: VtcDid,
    display_name: Option<String>,
    sub_context_id: String,
    persona_ref: PersonaId,
    status: CommunityStatus,
    #[serde(default)]
    favourite: bool,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    acknowledged: bool,
    member_since: Option<DateTime<Utc>>,
    requested_at: Option<DateTime<Utc>>,
    #[serde(default)]
    relationships: Relationships,
    #[serde(default)]
    tasks: Tasks,
    #[serde(default)]
    vrcs_issued: Vrcs,
    #[serde(default)]
    vrcs_received: Vrcs,
    // Keyed by `String`, not `CredentialKind`, on purpose: this is the
    // durability boundary. A strict `CredentialKind` key would make an
    // unrecognised kind (e.g. from a newer build) a fatal whole-config load
    // error; the `From` impl below instead drops unknown keys with a warning.
    #[serde(default)]
    credentials: BTreeMap<String, serde_json::Value>,
    // Legacy pre-R19 flat fields, folded into `credentials` below.
    #[serde(default)]
    membership_credential: Option<serde_json::Value>,
    #[serde(default)]
    role_credential: Option<serde_json::Value>,
}

impl From<CommunityRecordShadow> for CommunityRecord {
    fn from(shadow: CommunityRecordShadow) -> Self {
        // New-format `credentials` keys win; unknown keys are dropped (a newer
        // version may persist kinds this build doesn't know).
        let mut credentials: BTreeMap<CredentialKind, serde_json::Value> = BTreeMap::new();
        for (key, vc) in shadow.credentials {
            match CredentialKind::from_config_key(&key) {
                Some(kind) => {
                    credentials.insert(kind, vc);
                }
                None => tracing::warn!(
                    credential_kind = %key,
                    "dropping unknown stored credential kind",
                ),
            }
        }
        // Fold legacy flat fields in without clobbering a new-format value.
        if let Some(vmc) = shadow.membership_credential {
            credentials.entry(CredentialKind::Membership).or_insert(vmc);
        }
        if let Some(vec) = shadow.role_credential {
            credentials.entry(CredentialKind::Role).or_insert(vec);
        }
        CommunityRecord {
            vtc_did: shadow.vtc_did,
            display_name: shadow.display_name,
            sub_context_id: shadow.sub_context_id,
            persona_ref: shadow.persona_ref,
            status: shadow.status,
            favourite: shadow.favourite,
            archived: shadow.archived,
            acknowledged: shadow.acknowledged,
            member_since: shadow.member_since,
            requested_at: shadow.requested_at,
            relationships: shadow.relationships,
            tasks: shadow.tasks,
            vrcs_issued: shadow.vrcs_issued,
            vrcs_received: shadow.vrcs_received,
            credentials,
        }
    }
}

/// Client-side timeout for an unanswered `Pending` join (D16 / R-B-7): a join
/// request with no decision after this many days transitions to `Expired`.
pub const PENDING_TIMEOUT_DAYS: i64 = 7;

impl CommunityRecord {
    /// Build a fresh `Pending` join record (State-B join request, R-B-*).
    ///
    /// `request_id` correlates the VTC's asynchronous accept/reject decision
    /// (R-B-8); `requested_at` is stamped with `now` to anchor the 7-day timeout
    /// (D16). Starts unfavourited, unarchived, unacknowledged, with empty
    /// community-scoped relationship/VRC stores.
    pub fn new_pending(
        vtc_did: VtcDid,
        display_name: Option<String>,
        sub_context_id: String,
        persona_ref: PersonaId,
        request_id: Uuid,
        now: DateTime<Utc>,
    ) -> Self {
        CommunityRecord {
            vtc_did,
            display_name,
            sub_context_id,
            persona_ref,
            status: CommunityStatus::Pending { request_id },
            favourite: false,
            archived: false,
            acknowledged: false,
            member_since: None,
            requested_at: Some(now),
            relationships: Relationships::default(),
            tasks: Tasks::default(),
            vrcs_issued: Vrcs::default(),
            vrcs_received: Vrcs::default(),
            credentials: BTreeMap::new(),
        }
    }

    /// True for a membership that needs a live DIDComm session (Active or
    /// Pending) — so the VTC's asynchronous join reply is receivable (D16).
    pub fn is_live(&self) -> bool {
        self.status.requires_live_session()
    }

    /// Transition to `Active` on acceptance (R-B-8). Stamps `member_since` with
    /// `now` the first time the membership becomes active (R-C-2); leaves an
    /// existing timestamp untouched so a re-activation keeps the original date.
    /// Returning to a live state clears any prior acknowledgement (R-S-2).
    pub fn activate(&mut self, now: DateTime<Utc>) {
        if self.member_since.is_none() {
            self.member_since = Some(now);
        }
        self.status = CommunityStatus::Active;
        self.acknowledged = false;
    }

    /// Transition to `Rejected` — the VTC denied the join request (R-B-8). A
    /// fresh terminal outcome starts unacknowledged so it raises the
    /// actions-required badge until the user clears it (R-S-2).
    pub fn reject(&mut self) {
        self.status = CommunityStatus::Rejected;
        self.acknowledged = false;
    }

    /// Transition to `Removed` — the VTC removed an active member (R-B-8). Starts
    /// unacknowledged (R-S-2).
    pub fn remove(&mut self) {
        self.status = CommunityStatus::Removed;
        self.acknowledged = false;
    }

    /// Transition to `Left` — the member voluntarily left (R-L-1). `Left` never
    /// raises the actions-required badge (the user chose to leave).
    pub fn leave(&mut self) {
        self.status = CommunityStatus::Left;
        self.acknowledged = false;
    }

    /// Acknowledge a terminal outcome (`Rejected`/`Removed`/`Expired`), clearing
    /// the actions-required badge for this community (R-S-2). No effect on the
    /// `Pending` badge, which only clears when the request resolves.
    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
    }

    /// Whether this community raises the actions-required indicator (R-C-3):
    /// `Pending` always (a decision is awaited), or an **unacknowledged**
    /// terminal outcome `Rejected`/`Removed`/`Expired` (R-S-2). `Active` and
    /// `Left` never do.
    pub fn needs_attention(&self) -> bool {
        match self.status {
            CommunityStatus::Pending { .. } => true,
            CommunityStatus::Rejected | CommunityStatus::Removed | CommunityStatus::Expired => {
                !self.acknowledged
            }
            CommunityStatus::Active | CommunityStatus::Left => false,
        }
    }

    /// Toggle the favourite/star flag (R-C-4). Returns the new value.
    pub fn toggle_favourite(&mut self) -> bool {
        self.favourite = !self.favourite;
        self.favourite
    }

    /// Whether this membership may be archived or deleted (R-C-8): only an
    /// **inactive** one (`Left`/`Rejected`/`Removed`/`Expired`). An active or
    /// pending membership must be left first.
    pub fn can_archive_or_delete(&self) -> bool {
        self.status.is_inactive()
    }

    /// Expire a stale `Pending` join past the [`PENDING_TIMEOUT_DAYS`] client
    /// timeout (R-B-7 / D16). No-op unless the membership is currently `Pending`
    /// with a `requested_at` at least the timeout old. Returns `true` if it
    /// transitioned to `Expired`.
    pub fn expire_if_stale(&mut self, now: DateTime<Utc>) -> bool {
        if matches!(self.status, CommunityStatus::Pending { .. })
            && let Some(requested) = self.requested_at
            && now - requested >= TimeDelta::days(PENDING_TIMEOUT_DAYS)
        {
            self.status = CommunityStatus::Expired;
            self.acknowledged = false;
            return true;
        }
        false
    }
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

    /// The id of the account persona whose `did` equals `did`, if any. Maps an
    /// addressed persona DID (e.g. an inbound message's recipient) back to its
    /// [`PersonaId`] for D10 attribution tagging.
    pub fn persona_id_for_did(&self, did: &str) -> Option<PersonaId> {
        self.personas
            .iter()
            .find(|(_, p)| p.did == did)
            .map(|(id, _)| *id)
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

    /// A membership by VTC DID.
    pub fn community(&self, vtc: &VtcDid) -> Option<&CommunityRecord> {
        self.communities.get(vtc)
    }

    /// A mutable membership by VTC DID — for applying a lifecycle transition.
    pub fn community_mut(&mut self, vtc: &VtcDid) -> Option<&mut CommunityRecord> {
        self.communities.get_mut(vtc)
    }

    /// A *live* membership (Active or Pending) for this VTC, if any.
    ///
    /// State B uses this for join idempotency (R-B-9): a live membership is
    /// surfaced to the user instead of submitting a duplicate, while an inactive
    /// one (`Left`/`Rejected`/`Removed`/`Expired`) may be re-joined.
    pub fn live_community(&self, vtc: &VtcDid) -> Option<&CommunityRecord> {
        self.communities.get(vtc).filter(|c| c.is_live())
    }

    /// Sweep all `Pending` memberships, expiring any past the client timeout
    /// (R-B-7 / D16). Returns the VTC DIDs that transitioned to `Expired` so the
    /// caller can persist and raise the actions-required indicator (R-S-2).
    pub fn expire_stale_pending(&mut self, now: DateTime<Utc>) -> Vec<VtcDid> {
        let mut expired = Vec::new();
        for (vtc, community) in self.communities.iter_mut() {
            if community.expire_if_stale(now) {
                expired.push(vtc.clone());
            }
        }
        expired
    }

    /// Number of communities currently raising the actions-required indicator
    /// (R-C-3): see [`CommunityRecord::needs_attention`]. Archived communities
    /// are excluded — archiving hides a membership from the default list, so it
    /// no longer nags.
    pub fn actions_required_count(&self) -> usize {
        self.communities
            .values()
            .filter(|c| !c.archived && c.needs_attention())
            .count()
    }

    /// Communities for the overview page in display order (R-C-4): favourites
    /// first, then by display name (case-insensitive; unnamed last), then VTC
    /// DID as a stable tiebreak. Archived communities are excluded unless
    /// `include_archived` (R-C-8).
    pub fn communities_for_display(&self, include_archived: bool) -> Vec<&CommunityRecord> {
        let mut list: Vec<&CommunityRecord> = self
            .communities
            .values()
            .filter(|c| include_archived || !c.archived)
            .collect();
        list.sort_by(|a, b| {
            // Favourites first.
            b.favourite
                .cmp(&a.favourite)
                // Then by display name, case-insensitive; the unnamed sort last.
                .then_with(|| match (&a.display_name, &b.display_name) {
                    (Some(an), Some(bn)) => an.to_lowercase().cmp(&bn.to_lowercase()),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                })
                // Finally the VTC DID for a stable, deterministic order.
                .then_with(|| a.vtc_did.cmp(&b.vtc_did))
        });
        list
    }

    /// The community to use as the default working context (D10 / R-C-6/7) when
    /// the user hasn't explicitly selected one: the first **Active** community in
    /// display order (favourites first, then by name, then VTC DID). Returns
    /// `None` when there is no active community (the "no active community" state).
    /// Deterministic so the working context is stable across launches.
    pub fn default_working_community(&self) -> Option<VtcDid> {
        self.communities_for_display(false)
            .into_iter()
            .find(|c| c.status.is_active())
            .map(|c| c.vtc_did.clone())
    }

    /// Archive an inactive community (R-C-8): retain its data but hide it from
    /// the default list. Errors if the community is unknown or still
    /// active/pending (it must be left first).
    pub fn archive_community(&mut self, vtc: &VtcDid) -> Result<(), OpenVTCError> {
        let community = self
            .communities
            .get_mut(vtc)
            .ok_or_else(|| OpenVTCError::Config(format!("Unknown community: {vtc}")))?;
        if !community.can_archive_or_delete() {
            return Err(OpenVTCError::Config(format!(
                "Cannot archive an active/pending community ({vtc}); leave it first"
            )));
        }
        community.archived = true;
        Ok(())
    }

    /// Delete an inactive community's local record (R-C-8), returning the removed
    /// record. Errors if the community is unknown or still active/pending. The
    /// presented persona is retained even if now unreferenced (R-P-2); explicit
    /// persona deletion is a separate action.
    pub fn delete_community(&mut self, vtc: &VtcDid) -> Result<CommunityRecord, OpenVTCError> {
        match self.communities.get(vtc) {
            None => Err(OpenVTCError::Config(format!("Unknown community: {vtc}"))),
            Some(c) if !c.can_archive_or_delete() => Err(OpenVTCError::Config(format!(
                "Cannot delete an active/pending community ({vtc}); leave it first"
            ))),
            Some(_) => Ok(self
                .communities
                .remove(vtc)
                .expect("presence checked above")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona(label: &str) -> PersonaRecord {
        PersonaRecord {
            persona_id: PersonaId::new(),
            did: format!("did:webvh:example.com:{label}"),
            did_document: None,
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
            acknowledged: false,
            member_since: None,
            requested_at: None,
            relationships: Relationships::default(),
            tasks: Tasks::default(),
            vrcs_issued: Vrcs::default(),
            vrcs_received: Vrcs::default(),
            credentials: BTreeMap::new(),
        }
    }

    #[test]
    fn persona_id_for_did_maps_addressed_did_to_persona() {
        let pa = persona("alice");
        let pb = persona("bob");
        let (pid_a, did_a) = (pa.persona_id, pa.did.clone());
        let mut acct = Account::default();
        acct.personas.insert(pa.persona_id, pa);
        acct.personas.insert(pb.persona_id, pb);
        assert_eq!(acct.persona_id_for_did(&did_a), Some(pid_a));
        assert_eq!(acct.persona_id_for_did("did:web:nobody"), None);
    }

    #[test]
    fn default_working_community_prefers_favourite_active_and_skips_inactive() {
        let p = persona("p");
        let mut acct = Account::default();
        // No communities → no working context.
        assert_eq!(acct.default_working_community(), None);

        // An inactive (Left) community is never the working context.
        let left = community("did:web:left", p.persona_id, CommunityStatus::Left);
        acct.communities.insert(left.vtc_did.clone(), left);
        assert_eq!(acct.default_working_community(), None);

        // A plain active community becomes the default.
        let act = community("did:web:active", p.persona_id, CommunityStatus::Active);
        acct.communities.insert(act.vtc_did.clone(), act);
        assert_eq!(
            acct.default_working_community().as_deref(),
            Some("did:web:active")
        );

        // A favourited active community wins (sorts first in display order).
        let mut fav = community("did:web:fav", p.persona_id, CommunityStatus::Active);
        fav.favourite = true;
        acct.communities.insert(fav.vtc_did.clone(), fav);
        acct.personas.insert(p.persona_id, p);
        assert_eq!(
            acct.default_working_community().as_deref(),
            Some("did:web:fav")
        );
    }

    #[test]
    fn community_record_tasks_survive_json_round_trip() {
        use crate::tasks::TaskType;
        use std::sync::Arc;

        let pid = PersonaId::new();
        let mut comm = community("did:web:vtc-rt", pid, CommunityStatus::Active);
        comm.tasks.new_task(
            &Arc::new("task-rt".to_string()),
            TaskType::RelationshipRequestRejected,
        );
        let json = serde_json::to_string(&comm).expect("serialize");
        let back: CommunityRecord = serde_json::from_str(&json).expect("deserialize");
        assert!(
            back.tasks
                .get_by_id(&Arc::new("task-rt".to_string()))
                .is_some(),
            "per-community task should survive the round trip"
        );
    }

    /// Pre-R19 configs stored credentials as flat `membership_credential` /
    /// `role_credential` fields. They must still load, folded into the typed
    /// `credentials` registry (config round-trip — no migration).
    #[test]
    fn legacy_flat_credential_fields_load_into_registry() {
        let legacy = serde_json::json!({
            "vtc_did": "did:webvh:vtc.example",
            "display_name": "Example VTC",
            "sub_context_id": "openvtc/example",
            "persona_ref": PersonaId::new().0,
            "status": { "state": "active" },
            "member_since": null,
            "requested_at": null,
            "membership_credential": { "type": ["MembershipCredential"], "id": "vmc-1" },
            "role_credential": { "type": ["EndorsementCredential"], "id": "vec-1" },
        });
        let rec: CommunityRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(
            rec.credentials
                .get(&CredentialKind::Membership)
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str()),
            Some("vmc-1"),
        );
        assert_eq!(
            rec.credentials
                .get(&CredentialKind::Role)
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str()),
            Some("vec-1"),
        );
    }

    /// The new `credentials` object round-trips, serializes under stable
    /// `config_key` names, and tolerates an unknown key (dropped, not fatal).
    #[test]
    fn typed_credentials_round_trip_and_tolerate_unknown() {
        let mut rec = community(
            "did:webvh:vtc.example",
            PersonaId::new(),
            CommunityStatus::Active,
        );
        rec.credentials.insert(
            CredentialKind::Membership,
            serde_json::json!({ "id": "vmc-1" }),
        );

        let json = serde_json::to_value(&rec).unwrap();
        assert!(
            json["credentials"]["Membership"]["id"] == "vmc-1",
            "credentials must persist under the config_key name: {json}",
        );

        let back: CommunityRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back.credentials, rec.credentials);

        // An unrecognised kind (e.g. from a newer build) is dropped, not fatal.
        let with_unknown = serde_json::json!({
            "vtc_did": "did:webvh:vtc.example",
            "display_name": null,
            "sub_context_id": "openvtc/x",
            "persona_ref": PersonaId::new().0,
            "status": { "state": "active" },
            "member_since": null,
            "requested_at": null,
            "credentials": { "FutureKind": { "id": "x" } },
        });
        let rec: CommunityRecord = serde_json::from_value(with_unknown).unwrap();
        assert!(rec.credentials.is_empty());
    }

    #[test]
    fn new_pending_builds_a_live_pending_record() {
        let now = Utc::now();
        let pid = PersonaId::new();
        let req = Uuid::new_v4();
        let rec = CommunityRecord::new_pending(
            "did:webvh:vtc.example".to_string(),
            Some("Example VTC".to_string()),
            "openvtc/example".to_string(),
            pid,
            req,
            now,
        );
        assert!(matches!(rec.status, CommunityStatus::Pending { request_id } if request_id == req));
        assert_eq!(rec.persona_ref, pid);
        assert_eq!(rec.requested_at, Some(now));
        assert_eq!(rec.member_since, None);
        assert!(rec.is_live());
        assert!(rec.needs_attention());
        assert!(!rec.favourite && !rec.archived && !rec.acknowledged);

        // Idempotency (R-B-9): a pending join is a live membership, so a re-join
        // attempt finds it via `live_community`.
        let mut acct = Account::default();
        acct.communities.insert(rec.vtc_did.clone(), rec.clone());
        assert!(acct.live_community(&rec.vtc_did).is_some());
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

    fn pending() -> CommunityStatus {
        CommunityStatus::Pending {
            request_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn activate_stamps_member_since_once() {
        let pid = PersonaId::new();
        let mut c = community("v", pid, pending());
        let t0 = Utc::now();
        c.activate(t0);
        assert_eq!(c.status, CommunityStatus::Active);
        assert_eq!(c.member_since, Some(t0));

        // Re-activating keeps the original member-since date.
        c.activate(t0 + TimeDelta::days(5));
        assert_eq!(c.member_since, Some(t0), "member_since must not be reset");
    }

    #[test]
    fn terminal_transitions_set_status() {
        let pid = PersonaId::new();

        let mut r = community("v", pid, pending());
        r.reject();
        assert_eq!(r.status, CommunityStatus::Rejected);

        let mut rm = community("v", pid, CommunityStatus::Active);
        rm.remove();
        assert_eq!(rm.status, CommunityStatus::Removed);

        let mut l = community("v", pid, CommunityStatus::Active);
        l.leave();
        assert_eq!(l.status, CommunityStatus::Left);
    }

    #[test]
    fn expire_if_stale_only_fires_for_old_pending() {
        let pid = PersonaId::new();
        let now = Utc::now();

        // Fresh pending (just under the timeout): not expired.
        let mut fresh = community("v", pid, pending());
        fresh.requested_at = Some(now - TimeDelta::days(PENDING_TIMEOUT_DAYS - 1));
        assert!(!fresh.expire_if_stale(now));
        assert!(matches!(fresh.status, CommunityStatus::Pending { .. }));

        // Stale pending (at the timeout): expires.
        let mut stale = community("v", pid, pending());
        stale.requested_at = Some(now - TimeDelta::days(PENDING_TIMEOUT_DAYS));
        assert!(stale.expire_if_stale(now));
        assert_eq!(stale.status, CommunityStatus::Expired);

        // Active is never expired, however old.
        let mut active = community("v", pid, CommunityStatus::Active);
        active.requested_at = Some(now - TimeDelta::days(365));
        assert!(!active.expire_if_stale(now));
        assert_eq!(active.status, CommunityStatus::Active);

        // Pending with no requested_at can't be judged stale.
        let mut no_ts = community("v", pid, pending());
        no_ts.requested_at = None;
        assert!(!no_ts.expire_if_stale(now));
    }

    #[test]
    fn live_community_filters_inactive() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.communities.insert(
            "active".into(),
            community("active", pid, CommunityStatus::Active),
        );
        acct.communities
            .insert("left".into(), community("left", pid, CommunityStatus::Left));
        acct.communities
            .insert("pend".into(), community("pend", pid, pending()));

        assert!(acct.live_community(&"active".to_string()).is_some());
        assert!(acct.live_community(&"pend".to_string()).is_some());
        assert!(
            acct.live_community(&"left".to_string()).is_none(),
            "Left is not a live membership"
        );
        assert!(acct.live_community(&"missing".to_string()).is_none());
    }

    #[test]
    fn favourite_toggle_and_archive_delete_guard() {
        let pid = PersonaId::new();
        let mut c = community("v", pid, CommunityStatus::Active);
        assert!(!c.favourite);
        assert!(c.toggle_favourite());
        assert!(c.favourite);
        assert!(!c.toggle_favourite());

        // Active/pending cannot be archived/deleted; inactive can.
        assert!(!community("v", pid, CommunityStatus::Active).can_archive_or_delete());
        assert!(!community("v", pid, pending()).can_archive_or_delete());
        for s in [
            CommunityStatus::Left,
            CommunityStatus::Rejected,
            CommunityStatus::Removed,
            CommunityStatus::Expired,
        ] {
            assert!(community("v", pid, s).can_archive_or_delete());
        }
    }

    #[test]
    fn communities_for_display_orders_and_filters() {
        let mut acct = Account::default();
        let pid = PersonaId::new();

        let mut zebra = community("did:z", pid, CommunityStatus::Active);
        zebra.display_name = Some("Zebra".into());
        let mut acme = community("did:a", pid, CommunityStatus::Active);
        acme.display_name = Some("acme".into()); // lowercase: case-insensitive sort
        let mut fav = community("did:f", pid, CommunityStatus::Active);
        fav.display_name = Some("Middle".into());
        fav.favourite = true;
        let mut archived = community("did:x", pid, CommunityStatus::Left);
        archived.display_name = Some("Aardvark".into());
        archived.archived = true;

        for c in [zebra, acme, fav, archived] {
            acct.communities.insert(c.vtc_did.clone(), c);
        }

        // Default: archived excluded; favourite first, then name (ci).
        let names: Vec<&str> = acct
            .communities_for_display(false)
            .iter()
            .map(|c| c.display_name.as_deref().unwrap())
            .collect();
        assert_eq!(names, vec!["Middle", "acme", "Zebra"]);

        // With archived included, "Aardvark" appears (still after the favourite).
        let with_archived: Vec<&str> = acct
            .communities_for_display(true)
            .iter()
            .map(|c| c.display_name.as_deref().unwrap())
            .collect();
        assert_eq!(with_archived, vec!["Middle", "Aardvark", "acme", "Zebra"]);
    }

    #[test]
    fn archive_and_delete_respect_guards() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.communities.insert(
            "active".into(),
            community("active", pid, CommunityStatus::Active),
        );
        acct.communities
            .insert("left".into(), community("left", pid, CommunityStatus::Left));

        // Active cannot be archived or deleted.
        assert!(acct.archive_community(&"active".to_string()).is_err());
        assert!(acct.delete_community(&"active".to_string()).is_err());
        // Unknown errors too.
        assert!(acct.archive_community(&"missing".to_string()).is_err());

        // Inactive archives, then deletes.
        acct.archive_community(&"left".to_string()).unwrap();
        assert!(acct.communities["left"].archived);
        let removed = acct.delete_community(&"left".to_string()).unwrap();
        assert_eq!(removed.vtc_did, "left");
        assert!(!acct.communities.contains_key("left"));
    }

    #[test]
    fn expire_stale_pending_sweeps_and_reports() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        let now = Utc::now();

        let mut stale = community("stale", pid, pending());
        stale.requested_at = Some(now - TimeDelta::days(10));
        acct.communities.insert("stale".into(), stale);

        let mut fresh = community("fresh", pid, pending());
        fresh.requested_at = Some(now - TimeDelta::days(1));
        acct.communities.insert("fresh".into(), fresh);

        acct.communities.insert(
            "active".into(),
            community("active", pid, CommunityStatus::Active),
        );

        let expired = acct.expire_stale_pending(now);
        assert_eq!(expired, vec!["stale".to_string()]);
        assert_eq!(acct.communities["stale"].status, CommunityStatus::Expired);
        assert!(matches!(
            acct.communities["fresh"].status,
            CommunityStatus::Pending { .. }
        ));
        assert_eq!(acct.communities["active"].status, CommunityStatus::Active);
    }

    #[test]
    fn needs_attention_covers_pending_and_unacked_terminals() {
        let pid = PersonaId::new();
        assert!(community("v", pid, pending()).needs_attention());
        assert!(!community("v", pid, CommunityStatus::Active).needs_attention());
        assert!(
            !community("v", pid, CommunityStatus::Left).needs_attention(),
            "Left is voluntary — never an action"
        );
        for s in [
            CommunityStatus::Rejected,
            CommunityStatus::Removed,
            CommunityStatus::Expired,
        ] {
            let mut c = community("v", pid, s.clone());
            assert!(c.needs_attention(), "{s:?} should nag until acknowledged");
            c.acknowledge();
            assert!(!c.needs_attention(), "{s:?} clears once acknowledged");
        }
    }

    #[test]
    fn fresh_terminal_outcome_resets_acknowledgement() {
        let pid = PersonaId::new();
        // Acknowledge a Rejected, re-activate, then get Removed: the new terminal
        // outcome must nag again — acknowledgement does not carry across
        // transitions.
        let mut c = community("v", pid, CommunityStatus::Rejected);
        c.acknowledge();
        assert!(!c.needs_attention());
        c.activate(Utc::now());
        assert!(!c.acknowledged, "returning to a live state clears the ack");
        assert!(!c.needs_attention(), "Active never nags");
        c.remove();
        assert!(
            c.needs_attention(),
            "a fresh Removed must nag despite the earlier ack"
        );
    }

    #[test]
    fn actions_required_count_excludes_acknowledged_and_archived() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.communities
            .insert("pending".into(), community("pending", pid, pending()));
        acct.communities.insert(
            "active".into(),
            community("active", pid, CommunityStatus::Active),
        );

        // Unacknowledged Rejected → counts.
        let mut rejected = community("rejected", pid, CommunityStatus::Rejected);

        // Acknowledged Removed → does not count.
        let mut acked = community("acked", pid, CommunityStatus::Removed);
        acked.acknowledge();
        acct.communities.insert("acked".into(), acked);

        // Archived (unacknowledged) Expired → hidden, so does not count.
        let mut archived = community("archived", pid, CommunityStatus::Expired);
        archived.archived = true;
        acct.communities.insert("archived".into(), archived);

        acct.communities.insert("rejected".into(), rejected.clone());
        // pending + rejected.
        assert_eq!(acct.actions_required_count(), 2);

        // Acknowledging the rejection drops the count to just the pending.
        rejected.acknowledge();
        acct.communities.insert("rejected".into(), rejected);
        assert_eq!(acct.actions_required_count(), 1);
    }
}
