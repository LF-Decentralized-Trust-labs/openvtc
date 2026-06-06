/*!
 * Active-identity resolution over the config v2 [`Account`] model.
 *
 * A community presents a persona; many communities may present the **same**
 * persona (D1 reuse). Because the DIDComm layer keys connections by DID and a
 * reused persona must share one connection, the **session key is the persona**,
 * not the community (see `docs/design/t1-active-identity-api.md`).
 *
 * This is the metadata-only routing layer: it resolves communities → personas
 * and groups them by the persona session that serves them. The runtime-heavy
 * `IdentityContext` (resolved DID Document, ATM messaging profile, key/secret
 * loading) is layered on during config load in a later T1 commit; this module
 * gives the session manager the persona-keyed routing it needs without runtime
 * state.
 */

use crate::config::account::{Account, CommunityRecord, PersonaId, PersonaRecord, VtcDid};
use affinidi_tdk::{did_common::Document, messaging::profiles::ATMProfile};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A resolved community membership paired with the persona it presents.
///
/// Borrows from the owning [`Account`]; cheap to construct.
#[derive(Clone, Copy, Debug)]
pub struct IdentityRef<'a> {
    /// The community membership.
    pub community: &'a CommunityRecord,
    /// The persona presented to this community.
    pub persona: &'a PersonaRecord,
}

impl<'a> IdentityRef<'a> {
    /// The persona's `did:webvh`.
    pub fn persona_did(&self) -> &'a str {
        &self.persona.did
    }

    /// The DIDComm session key for this membership — the **persona** id.
    /// Memberships sharing a persona share one session.
    pub fn session_key(&self) -> PersonaId {
        self.persona.persona_id
    }

    /// The persona's mediator DID, if set.
    pub fn mediator_did(&self) -> Option<&'a str> {
        self.persona.mediator_did.as_deref()
    }
}

/// Read-only index over an [`Account`] that resolves communities to the persona
/// identity they present and groups them by persona session.
#[derive(Clone, Copy, Debug)]
pub struct IdentityRegistry<'a> {
    account: &'a Account,
}

impl<'a> IdentityRegistry<'a> {
    /// Build a registry view over an account. Cheap (borrows).
    pub fn new(account: &'a Account) -> Self {
        Self { account }
    }

    /// Resolve a community to its identity (community + presented persona).
    /// Returns `None` if the community is unknown or its `persona_ref` dangles.
    pub fn get(&self, vtc: &VtcDid) -> Option<IdentityRef<'a>> {
        let community = self.account.communities.get(vtc)?;
        let persona = self.account.personas.get(&community.persona_ref)?;
        Some(IdentityRef { community, persona })
    }

    /// Iterator over all resolvable memberships (skips any with a dangling
    /// `persona_ref`, which [`Account::dangling_refs`] reports separately).
    pub fn all(&self) -> impl Iterator<Item = IdentityRef<'a>> {
        self.account.communities.values().filter_map(move |c| {
            self.account
                .personas
                .get(&c.persona_ref)
                .map(|persona| IdentityRef {
                    community: c,
                    persona,
                })
        })
    }

    /// Memberships in the `Active` (live) state.
    pub fn active(&self) -> impl Iterator<Item = IdentityRef<'a>> {
        self.all().filter(|r| r.community.status.is_active())
    }

    /// Persona sessions that must be live, mapped to the communities they serve.
    ///
    /// A persona needs a session if any of its communities is `Active` or
    /// `Pending` ([`CommunityStatus::requires_live_session`]). A reused persona
    /// appears once, serving several communities — one shared connection.
    ///
    /// [`CommunityStatus::requires_live_session`]: crate::config::account::CommunityStatus::requires_live_session
    pub fn sessions(&self) -> HashMap<PersonaId, Vec<&'a VtcDid>> {
        let mut map: HashMap<PersonaId, Vec<&'a VtcDid>> = HashMap::new();
        for c in self.account.communities.values() {
            if c.status.requires_live_session()
                && self.account.personas.contains_key(&c.persona_ref)
            {
                map.entry(c.persona_ref).or_default().push(&c.vtc_did);
            }
        }
        map
    }

    /// The set of persona ids that should currently have a live session.
    pub fn active_session_keys(&self) -> HashSet<PersonaId> {
        self.sessions().into_keys().collect()
    }
}

/// A fully-resolved, runtime-ready identity: a persona plus its resolved DID
/// document and registered ATM messaging profile.
///
/// Built at config load (and at setup) and held on [`crate::config::Config`].
/// This is what consumers use to *act* as a persona — sign, send, and receive.
/// It replaces the singleton `Config.persona_did` (`PersonaDID`) as the runtime
/// identity as consumers migrate onto it.
#[derive(Clone, Debug)]
pub struct IdentityContext {
    /// Stable id of the persona this context resolves.
    pub persona_id: PersonaId,
    /// The persona's `did:webvh`.
    pub did: String,
    /// Resolved DID document.
    pub document: Document,
    /// Registered ATM messaging profile for this persona (not connected here;
    /// the DIDComm session manager owns connections).
    pub profile: Arc<ATMProfile>,
    /// The persona's mediator DID, if any.
    pub mediator_did: Option<String>,
}

impl IdentityContext {
    /// The persona's `did:webvh`.
    pub fn persona_did(&self) -> &str {
        &self.did
    }

    /// The resolved DID document.
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// The persona's ATM messaging profile.
    pub fn profile(&self) -> &Arc<ATMProfile> {
        &self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::account::{CommunityStatus, KeyRef, PersonaRecord};
    use chrono::Utc;
    use uuid::Uuid;

    fn persona() -> PersonaRecord {
        PersonaRecord {
            persona_id: PersonaId::new(),
            did: "did:webvh:example:p".into(),
            did_document: None,
            key_refs: Vec::<KeyRef>::new(),
            mediator_did: Some("did:webvh:mediator".into()),
            origin_context_id: "openvtc/p".into(),
            created_at: Utc::now(),
            label: None,
        }
    }

    fn community(vtc: &str, persona_ref: PersonaId, status: CommunityStatus) -> CommunityRecord {
        CommunityRecord {
            vtc_did: vtc.into(),
            display_name: None,
            sub_context_id: format!("openvtc/{vtc}"),
            persona_ref,
            status,
            favourite: false,
            archived: false,
            acknowledged: false,
            member_since: None,
            requested_at: None,
            relationships: Default::default(),
            vrcs_issued: Default::default(),
            vrcs_received: Default::default(),
        }
    }

    #[test]
    fn resolves_and_exposes_session_key() {
        let mut acct = Account::default();
        let p = persona();
        let pid = p.persona_id;
        acct.personas.insert(pid, p);
        acct.communities
            .insert("a".into(), community("a", pid, CommunityStatus::Active));

        let reg = IdentityRegistry::new(&acct);
        let id = reg.get(&"a".to_string()).expect("resolves");
        assert_eq!(id.session_key(), pid);
        assert_eq!(id.persona_did(), "did:webvh:example:p");
        assert_eq!(id.mediator_did(), Some("did:webvh:mediator"));
    }

    #[test]
    fn reused_persona_shares_one_session() {
        let mut acct = Account::default();
        let p = persona();
        let pid = p.persona_id;
        acct.personas.insert(pid, p);
        // Two Active communities present the SAME persona.
        acct.communities
            .insert("a".into(), community("a", pid, CommunityStatus::Active));
        acct.communities
            .insert("b".into(), community("b", pid, CommunityStatus::Active));

        let reg = IdentityRegistry::new(&acct);
        let sessions = reg.sessions();
        assert_eq!(sessions.len(), 1, "one shared persona session");
        assert_eq!(sessions[&pid].len(), 2, "serving both communities");
        assert_eq!(reg.active_session_keys().len(), 1);
    }

    #[test]
    fn pending_needs_session_inactive_does_not() {
        let mut acct = Account::default();
        let p1 = persona();
        let p2 = persona();
        let (id1, id2) = (p1.persona_id, p2.persona_id);
        acct.personas.insert(id1, p1);
        acct.personas.insert(id2, p2);
        // p1 → Pending (needs session); p2 → Left (does not).
        acct.communities.insert(
            "pending".into(),
            community(
                "pending",
                id1,
                CommunityStatus::Pending {
                    request_id: Uuid::new_v4(),
                },
            ),
        );
        acct.communities
            .insert("left".into(), community("left", id2, CommunityStatus::Left));

        let reg = IdentityRegistry::new(&acct);
        let keys = reg.active_session_keys();
        assert!(keys.contains(&id1), "pending persona needs a session");
        assert!(!keys.contains(&id2), "left persona needs no session");
        assert_eq!(reg.active().count(), 0, "no Active communities here");
    }

    #[test]
    fn dangling_ref_is_skipped() {
        let mut acct = Account::default();
        // Community references a persona that doesn't exist.
        acct.communities.insert(
            "x".into(),
            community("x", PersonaId::new(), CommunityStatus::Active),
        );
        let reg = IdentityRegistry::new(&acct);
        assert!(reg.get(&"x".to_string()).is_none());
        assert_eq!(reg.all().count(), 0);
        assert!(reg.sessions().is_empty());
    }
}
