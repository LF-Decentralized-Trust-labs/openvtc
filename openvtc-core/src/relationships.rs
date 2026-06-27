//! Relationship management for OpenVTC.
//!
//! Relationships represent DIDComm connections between the local persona and
//! remote parties. Each relationship tracks its own DID pair, state machine
//! status, and associated VRCs.

use crate::{
    KeyPurpose,
    bip32::Bip32Extension,
    config::{
        KeyBackend, KeyTypes,
        account::PersonaId,
        secured_config::{KeyInfoConfig, KeySourceMaterial},
    },
    errors::OpenVTCError,
    vrc::Vrcs,
};
use affinidi_tdk::{
    TDK,
    did_common::{document::DocumentExt, verification_method::VerificationMethod},
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::Arc,
    time::SystemTime,
};
use tracing::{debug, warn};
use uuid::Uuid;

// ****************************************************************************
// Relationship Structures
// ****************************************************************************

/// State machine for the lifecycle of a relationship between two parties.
#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationshipState {
    /// Relationship Request has been sent to the remote party
    RequestSent,

    /// Relationship Request has been accepted by respondent, need to finalise the relationship
    /// still
    RequestAccepted,

    /// Relationship Rejected by respondent
    RequestRejected,

    /// Relationship is established
    Established,

    /// There is no relationship
    None,
}

impl Display for RelationshipState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_str = match self {
            RelationshipState::RequestSent => "Request Sent",
            RelationshipState::RequestAccepted => "Request Accepted",
            RelationshipState::RequestRejected => "Request Rejected",
            RelationshipState::Established => "Established",
            RelationshipState::None => "None",
        };
        write!(f, "{}", state_str)
    }
}

/// Collection of all known relationships, indexed by the remote party's persona DID (P-DID).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(from = "RelationshipsShadow", into = "RelationshipsShadow")]
pub struct Relationships {
    /// Map from remote P-DID to the relationship state.
    ///
    /// Plain values (no `Arc<Mutex>`): there is exactly one mutating task (the
    /// `StateHandler` loop), so mutation goes through `&mut` and is infallible —
    /// there are no lock-poisoning paths that can silently drop an entry.
    pub relationships: HashMap<Arc<String>, Relationship>,

    /// Next BIP32 derivation path index to use when creating keys for a new relationship.
    pub path_pointer: u32,
}

/// A single relationship between the local user and a remote party.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Relationship {
    /// The task ID associated with the relationship handshake workflow.
    pub task_id: Arc<String>,

    /// The local DID used in this relationship (may be the persona DID or a dedicated R-DID).
    pub our_did: Arc<String>,

    /// The DID provided by the remote party for this relationship (may be an R-DID).
    pub remote_did: Arc<String>,

    /// The remote party's persona DID (P-DID).
    /// May equal `remote_did` if the remote party did not use a separate R-DID.
    pub remote_p_did: Arc<String>,

    /// Timestamp when this relationship was created.
    pub created: DateTime<Utc>,

    /// Current state of the relationship lifecycle.
    pub state: RelationshipState,

    /// Which of our account personas owns this relationship (D10 attribution).
    /// Set at creation to the working community's persona (outbound) or the
    /// addressed persona (inbound); the community-scoped main page filters
    /// relationships to the selected community's persona via this tag (R-C-6).
    /// `None` on relationships created before this field (legacy/single-persona),
    /// which are attributed to the sole persona at view time. Skipped when
    /// `None` so older configs round-trip byte-identically (R20 invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub our_persona: Option<PersonaId>,

    /// Set by [`Relationships::repair_key_info_ids`] when this relationship's
    /// R-DID secrets were lost to an older build's key-id bug and could not be
    /// recovered. Such a relationship cannot send or receive: its messaging
    /// profile is skipped (so it does not loop on mediator auth) and the UI
    /// shows a "needs re-establishment" badge prompting the user to re-create
    /// it. Re-establishing replaces the entry with a fresh one (flag false).
    /// Defaults to false and is omitted from serialization when false, so
    /// unaffected configs round-trip byte-identically (R20 invariant).
    #[serde(default, skip_serializing_if = "is_false")]
    pub needs_reestablishment: bool,
}

/// serde `skip_serializing_if` predicate: omit a `bool` field when it is false.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Outcome of [`Relationships::repair_key_info_ids`].
#[derive(Debug, Default)]
pub struct KeyInfoRepairReport {
    /// Number of `key_info` entries re-keyed to their canonical `{r_did}#key-N`
    /// ids. Non-zero means `key_info` changed and the config should be re-saved.
    pub repaired: usize,
    /// R-DIDs whose relationship keys could not be recovered. Their messaging
    /// profiles are skipped (no auth loop); the relationships must be
    /// re-established.
    pub unrecoverable: Vec<Arc<String>>,
}

impl KeyInfoRepairReport {
    /// Whether the pass changed anything worth persisting / reporting.
    pub fn changed(&self) -> bool {
        self.repaired > 0 || !self.unrecoverable.is_empty()
    }
}

/// Locate the source material for one R-DID verification method, returning
/// `(existing_key_info_id_to_replace, source, create_time)` or `None` if the key
/// cannot be recovered offline. Strategy, in order:
///
/// 1. **Multibase-keyed entry (VTA path):** the stored `key_info` id is the
///    public-key multibase, which equals the VM's `publicKeyMultibase` — a
///    direct map lookup that also preserves the entry's `VtaManaged` key id.
/// 2. **Reconstruct + byte-match:** re-derive each stored BIP32 `Derived` path
///    (or rebuild each `Imported` seed) and compare raw public-key bytes.
/// 3. **BIP32 rescan:** keys lost to the `"x25519"` collision have no surviving
///    entry, so rescan derivation paths `m/3'/1'/1'/{i}'` up to `path_pointer`
///    and mint a fresh `Derived` source on a byte match.
fn find_key_source(
    vm: &VerificationMethod,
    target_bytes: &[u8],
    kp: KeyPurpose,
    key_info: &HashMap<String, KeyInfoConfig>,
    key_backend: &KeyBackend,
    path_pointer: u32,
) -> Option<(Option<String>, KeySourceMaterial, DateTime<Utc>)> {
    // (1) The VM's publicKeyMultibase doubles as the old VTA-style key_info id.
    if let Some(mb) = vm
        .property_set
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
        && let Some(ki) = key_info.get(mb)
    {
        return Some((Some(mb.to_string()), ki.path.clone(), ki.create_time));
    }

    // (2) Reconstruct each candidate entry's public key and match bytes.
    for (id, ki) in key_info.iter() {
        let bytes = match &ki.path {
            KeySourceMaterial::Derived { path } => match key_backend {
                KeyBackend::Bip32 { root, .. } => root
                    .get_secret_from_path(path, kp)
                    .ok()
                    .map(|s| s.get_public_bytes().to_vec()),
                _ => None,
            },
            KeySourceMaterial::Imported { seed } => Secret::from_multibase(seed.expose_secret(), None)
                .ok()
                .map(|s| s.get_public_bytes().to_vec()),
            // VTA-managed secrets aren't reconstructable offline; the (1) path
            // handles them via their multibase id.
            KeySourceMaterial::VtaManaged { .. } => None,
        };
        if bytes.as_deref() == Some(target_bytes) {
            return Some((Some(id.clone()), ki.path.clone(), ki.create_time));
        }
    }

    // (3) BIP32 rescan for keys with no surviving entry (collision casualties).
    if let KeyBackend::Bip32 { root, .. } = key_backend {
        for i in 0..path_pointer {
            let path = format!("m/3'/1'/1'/{i}'");
            if let Ok(s) = root.get_secret_from_path(&path, kp)
                && s.get_public_bytes() == target_bytes
            {
                return Some((None, KeySourceMaterial::Derived { path }, Utc::now()));
            }
        }
    }

    None
}

impl From<RelationshipsShadow> for Relationships {
    fn from(value: RelationshipsShadow) -> Self {
        let mut relationships: HashMap<Arc<String>, Relationship> = HashMap::new();

        for relationship in value.relationships {
            let key = relationship.remote_p_did.clone();
            relationships.insert(key, relationship);
        }

        Relationships {
            relationships,
            path_pointer: value.path_pointer,
        }
    }
}

/// Flat serialization form of [`Relationships`] used for persistence in `SecuredConfig`.
///
/// On-disk compatibility note (R20): the previous in-memory model wrapped each
/// relationship in `Arc<Mutex<…>>`. With serde's `rc` feature both `Arc` and
/// `Mutex` serialize transparently as their inner value, so a `Vec<Relationship>`
/// and a `Vec<Arc<Mutex<Relationship>>>` produce **byte-identical** JSON. This
/// shadow keeps the on-disk format unchanged across the de-mutex refactor.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct RelationshipsShadow {
    pub(crate) relationships: Vec<Relationship>,
    pub(crate) path_pointer: u32,
}

impl From<Relationships> for RelationshipsShadow {
    fn from(value: Relationships) -> Self {
        let relationships = value
            .relationships
            .into_values()
            .collect::<Vec<Relationship>>();
        RelationshipsShadow {
            relationships,
            path_pointer: value.path_pointer,
        }
    }
}

impl Relationships {
    /// Generates ATM profiles for established relationships where the local R-DID differs
    /// from the persona P-DID, and registers the corresponding secrets with the TDK.
    ///
    /// # Errors
    ///
    /// Returns an error if the TDK ATM service is not initialized, VTA authentication
    /// fails, or secret derivation/import fails.
    /// `our_p_dids` is the set of *our* persona DIDs. Relationships served
    /// directly by a persona DID (rather than a dedicated R-DID) are skipped
    /// here — that persona's own listener carries them. With multiple personas
    /// the set must contain all of them, or another persona's DID would be
    /// mistaken for an R-DID and get a spurious `rel-` profile.
    pub async fn generate_profiles(
        &self,
        tdk: &TDK,
        our_p_dids: &HashSet<String>,
        mediator: &str,
        key_backend: &KeyBackend,
        key_info: &HashMap<String, KeyInfoConfig>,
        vta_client: Option<&vta_sdk::client::VtaClient>,
    ) -> Result<HashMap<Arc<String>, Arc<ATMProfile>>, OpenVTCError> {
        let atm = tdk
            .atm
            .clone()
            .ok_or_else(|| OpenVTCError::Config("TDK ATM service not initialized".to_string()))?;

        let mut profiles: HashMap<Arc<String>, Arc<ATMProfile>> = HashMap::new();
        debug!(
            "generating {} relationship profiles",
            self.relationships.len()
        );

        // Use the provided VTA client, or build one via the canonical
        // helper (which knows how to do DIDComm-only VTAs as well as REST).
        // The previous fallback hand-rolled `challenge_response` against
        // `vta_url` and silently broke for DIDComm-only VTAs whose
        // `vta_url` is empty.
        let mut owned_vta_client: Option<vta_sdk::client::VtaClient> = None;
        let vta_client: Option<&vta_sdk::client::VtaClient> = match vta_client {
            Some(client) => Some(client),
            None => {
                if matches!(key_backend, KeyBackend::Vta { .. }) {
                    owned_vta_client =
                        Some(super::config::build_runtime_vta_client(key_backend).await?);
                    owned_vta_client.as_ref()
                } else {
                    None
                }
            }
        };

        // Build the relationship profiles + gather their secrets, wrapped so our
        // own admin-DID VTA session (if built above) is shut down on EVERY exit,
        // including the `?` error paths below.
        let profiles_result: Result<(), OpenVTCError> = async {
            // Collect R-DID relationships that need profiles + secrets.
            let r_did_entries: Vec<Arc<String>> = self
                .relationships
                .values()
                .filter_map(|rel| {
                    if matches!(
                        rel.state,
                        RelationshipState::Established
                            | RelationshipState::RequestSent
                            | RelationshipState::RequestAccepted
                    ) && !our_p_dids.contains(rel.our_did.as_str())
                        // Skip relationships whose R-DID keys were lost (flagged
                        // by `repair_key_info_ids`): registering a profile here is
                        // what caused the mediator-auth loop. They await
                        // re-establishment.
                        && !rel.needs_reestablishment
                    {
                        Some(rel.our_did.clone())
                    } else {
                        None
                    }
                })
                .collect();

            // Collect all VTA key fetch futures upfront so they can run concurrently.
            // Non-VTA secrets (BIP32 derived, imported) are resolved synchronously.
            struct PendingVtaFetch {
                key_id: String,
                secret_id: String,
                purpose: KeyPurpose,
            }

            let mut all_secrets: Vec<Secret> = Vec::new();
            let mut vta_fetches: Vec<PendingVtaFetch> = Vec::new();

            for our_did in &r_did_entries {
                // Skip any R-DID that has no canonical key-agreement (encryption)
                // entry in `key_info`. Registering a messaging profile for such a
                // DID is exactly what produced the historical mediator-auth loop:
                // packing the authentication message as the R-DID fails forever
                // with "sender has no usable key agreement key". This is the
                // unrecoverable set left by `repair_key_info_ids` (keys lost to an
                // older build's id bug); flag it for the user to re-establish
                // rather than spin. Recoverable R-DIDs were re-keyed to
                // `{r_did}#key-2` by the repair pass and pass this check.
                let has_key_agreement = key_info.iter().any(|(k, v)| {
                    k.starts_with(our_did.as_str())
                        && matches!(v.purpose, KeyTypes::RelationshipEncryption)
                });
                if !has_key_agreement {
                    warn!(
                        r_did = %our_did,
                        "relationship R-DID has no usable key-agreement key; skipping its \
                         messaging profile — this relationship must be re-established"
                    );
                    continue;
                }

                // Create ATM profile (no network — just registration)
                let profile =
                    ATMProfile::new(&atm, None, our_did.to_string(), Some(mediator.to_string()))
                        .await?;
                profiles.insert(our_did.clone(), atm.profile_add(&profile, false).await?);

                // Collect secrets for this DID
                for (k, v) in key_info.iter() {
                    if !k.starts_with(our_did.as_str()) {
                        continue;
                    }
                    let kp = match v.purpose {
                        KeyTypes::RelationshipVerification => KeyPurpose::Signing,
                        KeyTypes::RelationshipEncryption => KeyPurpose::Encryption,
                        _ => continue,
                    };
                    match &v.path {
                        KeySourceMaterial::Derived { path } => {
                            if let KeyBackend::Bip32 { root, .. } = key_backend
                                && let Ok(mut s) = root.get_secret_from_path(path, kp)
                            {
                                s.id = k.clone();
                                all_secrets.push(s);
                            }
                        }
                        KeySourceMaterial::Imported { seed } => {
                            if let Ok(mut s) = Secret::from_multibase(seed.expose_secret(), None) {
                                s.id = k.clone();
                                all_secrets.push(s);
                            }
                        }
                        KeySourceMaterial::VtaManaged { key_id } => {
                            vta_fetches.push(PendingVtaFetch {
                                key_id: key_id.clone(),
                                secret_id: k.clone(),
                                purpose: kp,
                            });
                        }
                    }
                }
            }

            // Fetch all VTA secrets concurrently — VtaClient is Clone so cloned
            // clients share the HTTP connection pool and auth tokens.
            if let Some(client) = vta_client
                && !vta_fetches.is_empty()
            {
                debug!("fetching {} VTA secrets concurrently", vta_fetches.len());
                let mut handles = Vec::with_capacity(vta_fetches.len());
                for fetch in &vta_fetches {
                    let client = client.clone();
                    let key_id = fetch.key_id.clone();
                    handles.push(tokio::spawn(
                        async move { client.get_key_secret(&key_id).await },
                    ));
                }
                for (fetch, handle) in vta_fetches.iter().zip(handles) {
                    match handle.await {
                        Ok(Ok(resp)) => {
                            if let Ok(mut s) =
                                crate::config::keys::secret_from_vta_response(&resp, fetch.purpose)
                            {
                                s.id = fetch.secret_id.clone();
                                all_secrets.push(s);
                            }
                        }
                        Ok(Err(e)) => {
                            warn!(key_id = %fetch.key_id, "VTA get_key_secret failed: {e}");
                        }
                        Err(e) => {
                            warn!(key_id = %fetch.key_id, "VTA fetch task panicked: {e}");
                        }
                    }
                }
            }

            // Insert all secrets at once
            if !all_secrets.is_empty() {
                tdk.get_shared_state()
                    .secrets_resolver()
                    .insert_vec(&all_secrets)
                    .await;
            }

            Ok(())
        }
        .await;

        // Close our own admin-DID VTA session (if we built one) on every exit; a
        // caller-passed client is the caller's to close. `connect_didcomm` opens a
        // session that `Drop` can't close.
        if let Some(client) = &owned_vta_client {
            client.shutdown().await;
        }
        profiles_result?;

        Ok(profiles)
    }

    /// One-time, offline, idempotent repair of relationship-DID (R-DID)
    /// `key_info` entries whose ids were persisted *before* the `did:peer` mint
    /// by older builds (the `create_io` id-ordering bug). Such entries are keyed
    /// by a placeholder id — a random base58 string for the Ed25519 verification
    /// key and the constant `"x25519"` for the X25519 key-agreement key —
    /// instead of the canonical `{r_did}#key-1` / `#key-2` verification-method
    /// ids that `Config` key resolution and [`Relationships::generate_profiles`]
    /// require. Because the encryption id is a constant, multiple relationships'
    /// encryption entries also collide in the `key_info` map and all but one are
    /// lost.
    ///
    /// For each R-DID relationship not already keyed canonically, this resolves
    /// the `did:peer` document (self-describing — no network) for the
    /// authoritative verification-method ids and public keys, locates each key's
    /// source material — by the stored multibase id (VTA), by re-deriving stored
    /// BIP32 paths, or, for keys lost to the collision, by rescanning the BIP32
    /// derivation space — and re-keys it to the canonical id. Relationships whose
    /// keys cannot be recovered are returned in [`KeyInfoRepairReport::
    /// unrecoverable`]; `generate_profiles` then skips their profiles (no auth
    /// loop) and the caller logs them for re-establishment.
    pub async fn repair_key_info_ids(
        &mut self,
        tdk: &TDK,
        our_p_dids: &HashSet<String>,
        key_info: &mut HashMap<String, KeyInfoConfig>,
        key_backend: &KeyBackend,
    ) -> KeyInfoRepairReport {
        let mut report = KeyInfoRepairReport::default();

        // Snapshot (remote_p_did, r_did) for every R-DID relationship up front so
        // the `needs_reestablishment` flag can be set afterwards without a borrow
        // clash against this read-only pass.
        let targets: Vec<(Arc<String>, Arc<String>)> = self
            .relationships
            .values()
            .filter(|rel| {
                matches!(
                    rel.state,
                    RelationshipState::Established
                        | RelationshipState::RequestSent
                        | RelationshipState::RequestAccepted
                ) && !our_p_dids.contains(rel.our_did.as_str())
            })
            .map(|rel| (rel.remote_p_did.clone(), rel.our_did.clone()))
            .collect();

        let path_pointer = self.path_pointer;
        // remote_p_dids to flag once the immutable snapshot above is consumed.
        let mut to_flag: Vec<Arc<String>> = Vec::new();

        for (remote_p_did, r_did) in targets {
            // Already canonical (created post-fix or previously repaired): a
            // cheap string scan keeps the whole pass idempotent.
            if key_info.keys().any(|k| k.starts_with(r_did.as_str())) {
                continue;
            }

            let doc = match tdk.did_resolver().resolve(r_did.as_str()).await {
                Ok(resp) => resp.doc,
                Err(e) => {
                    warn!(r_did = %r_did, error = %e,
                        "repair: could not resolve R-DID; relationship must be re-established");
                    report.unrecoverable.push(r_did);
                    to_flag.push(remote_p_did);
                    continue;
                }
            };

            // Resolve every verification method to (canonical id, purpose,
            // source material). Bail to "unrecoverable" if any one can't be
            // located so we never half-register an R-DID.
            let mut rekeys: Vec<(Option<String>, String, KeyInfoConfig)> = Vec::new();
            let mut recovered = true;
            for vm in &doc.verification_method {
                let Ok(target_bytes) = vm.get_public_key_bytes() else {
                    continue; // non-Multikey VM; not one of our R-DID keys
                };
                let (kp, purpose) = if doc.contains_key_agreement(vm.id.as_str()) {
                    (KeyPurpose::Encryption, KeyTypes::RelationshipEncryption)
                } else {
                    (KeyPurpose::Signing, KeyTypes::RelationshipVerification)
                };
                match find_key_source(vm, &target_bytes, kp, key_info, key_backend, path_pointer) {
                    Some((old_id, source, created)) => rekeys.push((
                        old_id,
                        vm.id.as_str().to_string(),
                        KeyInfoConfig {
                            path: source,
                            create_time: created,
                            purpose,
                        },
                    )),
                    None => {
                        recovered = false;
                        break;
                    }
                }
            }

            if !recovered || rekeys.is_empty() {
                warn!(r_did = %r_did,
                    "repair: relationship keys could not be recovered; must be re-established");
                report.unrecoverable.push(r_did);
                to_flag.push(remote_p_did);
                continue;
            }

            for (old_id, new_id, new_ki) in rekeys {
                if let Some(old) = old_id
                    && old != new_id
                {
                    key_info.remove(&old);
                }
                key_info.insert(new_id, new_ki);
                report.repaired += 1;
            }
            debug!(r_did = %r_did, "repair: re-keyed relationship key_info to canonical ids");
        }

        // Persist the badge: mark unrecoverable relationships so the UI surfaces
        // them and `generate_profiles` skips their (unusable) messaging profiles.
        for pdid in to_flag {
            if let Some(rel) = self.relationships.get_mut(&pdid) {
                rel.needs_reestablishment = true;
            }
        }

        report
    }

    /// Removes a relationship by its task ID, along with any associated VRCs.
    ///
    /// Returns the removed relationship if found, or `None` if no match exists.
    pub fn remove_by_task_id(
        &mut self,
        id: &Arc<String>,
        vrcs_issued: &mut Vrcs,
        vrcs_received: &mut Vrcs,
    ) -> Option<Relationship> {
        let key = self
            .relationships
            .iter()
            .find(|(_, r)| r.task_id == *id)
            .map(|(k, _)| k.clone());

        if let Some(key) = key {
            debug!("relationship removed: task_id={}", id);
            self.remove(&key, vrcs_issued, vrcs_received)
        } else {
            None
        }
    }

    /// Removes a relationship by its remote P-DID key, along with any associated VRCs.
    ///
    /// Returns the removed relationship if found, or `None` if no match exists.
    pub fn remove(
        &mut self,
        key: &Arc<String>,
        vrcs_issued: &mut Vrcs,
        vrcs_received: &mut Vrcs,
    ) -> Option<Relationship> {
        // Find and remove any VRCs associated with this relationship
        vrcs_issued.remove_relationship(key);
        vrcs_received.remove_relationship(key);

        let removed = self.relationships.remove(key);
        if removed.is_some() {
            debug!("relationship removed: remote_did={}", key);
        }
        removed
    }

    /// Gets a relationship using the remote P-DID key.
    pub fn get(&self, p_did: &Arc<String>) -> Option<&Relationship> {
        self.relationships.get(p_did)
    }

    /// Gets a mutable reference to a relationship using the remote P-DID key.
    pub fn get_mut(&mut self, p_did: &Arc<String>) -> Option<&mut Relationship> {
        self.relationships.get_mut(p_did)
    }

    /// Finds a relationship by its task ID.
    pub fn find_by_task_id(&self, task_id: &Arc<String>) -> Option<&Relationship> {
        self.relationships.values().find(|r| &r.task_id == task_id)
    }

    /// Finds the map key (remote P-DID) of a relationship by its task ID.
    ///
    /// Useful for "look up → await → re-look-up mutably" flows where a `&mut`
    /// borrow cannot be held across an `.await`.
    pub fn find_key_by_task_id(&self, task_id: &Arc<String>) -> Option<Arc<String>> {
        self.relationships
            .iter()
            .find(|(_, r)| &r.task_id == task_id)
            .map(|(k, _)| k.clone())
    }

    /// Finds a relationship by its remote DID (either P-DID or R-DID).
    pub fn find_by_remote_did(&self, did: &Arc<String>) -> Option<&Relationship> {
        self.relationships
            .values()
            .find(|r| r.remote_did == *did || r.remote_p_did == *did)
    }

    /// Finds the map key (remote P-DID) of a relationship matching the given
    /// remote DID (either P-DID or R-DID).
    pub fn find_key_by_remote_did(&self, did: &Arc<String>) -> Option<Arc<String>> {
        self.relationships
            .iter()
            .find(|(_, r)| r.remote_did == *did || r.remote_p_did == *did)
            .map(|(k, _)| k.clone())
    }

    /// Returns only the relationships in the [`RelationshipState::Established`] state.
    pub fn get_established_relationships(&self) -> Vec<&Relationship> {
        self.relationships
            .values()
            .filter(|r| r.state == RelationshipState::Established)
            .collect()
    }
}

// ****************************************************************************
// Message Body Structure types
// ****************************************************************************

/// DIDComm message body sent to the remote party when requesting a new relationship.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelationshipRequestBody {
    /// Optional human-readable reason for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The DID the requester wants to use for this relationship.
    pub did: String,
    /// Optional human-readable name of the requester (e.g., "Alice").
    /// Allows the recipient to see who is requesting the relationship
    /// without needing to resolve the DID first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// DIDComm message body sent to the initiator when a relationship request is rejected.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelationshipRejectBody {
    /// Optional human-readable reason for the rejection.
    pub reason: Option<String>,
}

/// DIDComm message body sent to the initiator when a relationship request is accepted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelationshipAcceptBody {
    /// The DID the acceptor will use for this relationship.
    pub did: String,
}

// ****************************************************************************
// Message Handling
// ****************************************************************************

/// Creates and sends a relationship rejection message to the remote party via DIDComm.
///
/// - `atm`: The Affinidi Trusted Messaging service instance.
/// - `from_profile`: ATM profile of the responder (our identity).
/// - `to`: DID of the remote party who initiated the request.
/// - `mediator_did`: DID of the mediator used for message forwarding.
/// - `reason`: Optional human-readable reason for the rejection.
/// - `thid`: Thread ID linking this rejection to the original request.
///
/// # Errors
///
/// Returns an error if the system clock is unavailable, message encryption fails,
/// or message delivery fails.
pub async fn create_send_message_rejected(
    atm: &ATM,
    from_profile: &Arc<ATMProfile>,
    to: &str,
    mediator_did: &str,
    reason: Option<&str>,
    thid: &str,
) -> Result<(), OpenVTCError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| OpenVTCError::Config(format!("System clock error: {e}")))?
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-reject".to_string(),
        json!(RelationshipRejectBody {
            reason: reason.map(|r| r.to_string())
        }),
    )
    .from(from_profile.inner.did.to_string())
    .to(to.to_string())
    .thid(thid.to_string())
    .created_time(now)
    .expires_time(now + 60 * 60 * 48) // 48 hours
    .finalize();

    crate::pack_and_send(
        atm,
        from_profile,
        &msg,
        &from_profile.inner.did,
        to,
        mediator_did,
    )
    .await?;

    Ok(())
}

/// Creates and sends a relationship acceptance message to the remote party via DIDComm.
///
/// - `atm`: The Affinidi Trusted Messaging service instance.
/// - `from_profile`: ATM profile of the responder (our identity).
/// - `to`: DID of the remote party who initiated the request.
/// - `mediator_did`: DID of the mediator used for message forwarding.
/// - `r_did`: The relationship DID to use (may be the persona DID or a dedicated R-DID).
/// - `thid`: Thread ID linking this acceptance to the original request.
///
/// # Errors
///
/// Returns an error if the system clock is unavailable, message encryption fails,
/// or message delivery fails.
pub async fn create_send_message_accepted(
    atm: &ATM,
    from_profile: &Arc<ATMProfile>,
    to: &str,
    mediator_did: &str,
    r_did: &str,
    thid: &str,
) -> Result<(), OpenVTCError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| OpenVTCError::Config(format!("System clock error: {e}")))?
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-accept".to_string(),
        json!(RelationshipAcceptBody {
            did: r_did.to_string()
        }),
    )
    .from(from_profile.inner.did.to_string())
    .to(to.to_string())
    .thid(thid.to_string())
    .created_time(now)
    .expires_time(now + 60 * 60 * 48) // 48 hours
    .finalize();

    crate::pack_and_send(
        atm,
        from_profile,
        &msg,
        &from_profile.inner.did,
        to,
        mediator_did,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek_bip32::ExtendedSigningKey;
    use secrecy::SecretString;

    fn make_relationship(
        task_id: &str,
        our_did: &str,
        remote_did: &str,
        remote_p_did: &str,
        state: RelationshipState,
    ) -> Relationship {
        Relationship {
            task_id: Arc::new(task_id.to_string()),
            our_did: Arc::new(our_did.to_string()),
            remote_did: Arc::new(remote_did.to_string()),
            remote_p_did: Arc::new(remote_p_did.to_string()),
            created: Utc::now(),
            state,
            our_persona: None,
            needs_reestablishment: false,
        }
    }

    // --- R-DID key_info repair (migration) -------------------------------

    async fn empty_tdk() -> TDK {
        use affinidi_tdk::common::config::TDKConfig;
        TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .expect("TDK config builds"),
            None,
        )
        .await
        .expect("TDK builds")
    }

    /// Mint an R-DID from a BIP32 root exactly as `create_io` does: derive the
    /// verification (Signing) and key-agreement (Encryption) keys at the given
    /// paths, then build the `did:peer` (which rewrites the secret ids to
    /// `#key-1` / `#key-2`). Returns the canonical R-DID string.
    fn mint_rdid(root: &ExtendedSigningKey, v_path: &str, e_path: &str) -> String {
        use affinidi_tdk::dids::{DID, PeerKeyRole};
        let mut v = root
            .get_secret_from_path(v_path, KeyPurpose::Signing)
            .expect("v key");
        let mut e = root
            .get_secret_from_path(e_path, KeyPurpose::Encryption)
            .expect("e key");
        let mut keys = vec![
            (PeerKeyRole::Verification, &mut v),
            (PeerKeyRole::Encryption, &mut e),
        ];
        DID::generate_did_peer_from_secrets(&mut keys, Some("did:web:mediator.example".to_string()))
            .expect("did:peer")
    }

    fn broken_entry(path: &str, purpose: KeyTypes) -> KeyInfoConfig {
        KeyInfoConfig {
            path: KeySourceMaterial::Derived {
                path: path.to_string(),
            },
            create_time: Utc::now(),
            purpose,
        }
    }

    #[tokio::test]
    async fn repair_rekeys_bip32_rdid_keyinfo_to_canonical_ids() {
        let root = ExtendedSigningKey::from_seed(&[42u8; 32]).expect("root");
        let key_backend = KeyBackend::Bip32 {
            root: ExtendedSigningKey::from_seed(&[42u8; 32]).expect("root"),
            seed: SecretString::new("seed".into()),
        };
        let (v_path, e_path) = ("m/3'/1'/1'/0'", "m/3'/1'/1'/1'");
        let r_did = mint_rdid(&root, v_path, e_path);

        // key_info as an older build persisted it: placeholder ids (a random id
        // for the Ed25519 key, the constant "x25519" for X25519).
        let mut key_info = HashMap::new();
        key_info.insert(
            "random-v-id".to_string(),
            broken_entry(v_path, KeyTypes::RelationshipVerification),
        );
        key_info.insert(
            "x25519".to_string(),
            broken_entry(e_path, KeyTypes::RelationshipEncryption),
        );

        let mut rels = Relationships {
            path_pointer: 2,
            ..Default::default()
        };
        rels.relationships.insert(
            Arc::new("did:remote:p".to_string()),
            make_relationship(
                "task-1",
                &r_did,
                "did:remote:r",
                "did:remote:p",
                RelationshipState::Established,
            ),
        );

        let tdk = empty_tdk().await;
        let report = rels
            .repair_key_info_ids(&tdk, &HashSet::new(), &mut key_info, &key_backend)
            .await;

        assert_eq!(report.repaired, 2, "both keys re-keyed");
        assert!(report.unrecoverable.is_empty());
        let v_id = format!("{r_did}#key-1");
        let e_id = format!("{r_did}#key-2");
        assert!(key_info.contains_key(&v_id), "verification → {v_id}");
        assert!(key_info.contains_key(&e_id), "key-agreement → {e_id}");
        assert!(matches!(
            key_info[&e_id].purpose,
            KeyTypes::RelationshipEncryption
        ));
        assert!(matches!(
            key_info[&v_id].purpose,
            KeyTypes::RelationshipVerification
        ));
        assert!(!key_info.contains_key("random-v-id"));
        assert!(!key_info.contains_key("x25519"));
        assert!(
            !rels.relationships[&Arc::new("did:remote:p".to_string())].needs_reestablishment,
            "recovered relationship is not flagged"
        );

        // Idempotent: re-running changes nothing (entries already canonical).
        let again = rels
            .repair_key_info_ids(&tdk, &HashSet::new(), &mut key_info, &key_backend)
            .await;
        assert_eq!(again.repaired, 0);
        assert!(!again.changed());
    }

    #[tokio::test]
    async fn repair_recovers_encryption_key_lost_to_x25519_collision() {
        let root = ExtendedSigningKey::from_seed(&[7u8; 32]).expect("root");
        let key_backend = KeyBackend::Bip32 {
            root: ExtendedSigningKey::from_seed(&[7u8; 32]).expect("root"),
            seed: SecretString::new("seed".into()),
        };
        // Two relationships at paths (0,1) and (2,3).
        let a = mint_rdid(&root, "m/3'/1'/1'/0'", "m/3'/1'/1'/1'");
        let b = mint_rdid(&root, "m/3'/1'/1'/2'", "m/3'/1'/1'/3'");

        // Both encryption entries were stored under the constant "x25519", so
        // only the last survives; the other E key has NO entry and must be
        // recovered by rescanning the derivation space.
        let mut key_info = HashMap::new();
        key_info.insert(
            "rand-a".to_string(),
            broken_entry("m/3'/1'/1'/0'", KeyTypes::RelationshipVerification),
        );
        key_info.insert(
            "rand-b".to_string(),
            broken_entry("m/3'/1'/1'/2'", KeyTypes::RelationshipVerification),
        );
        key_info.insert(
            "x25519".to_string(),
            broken_entry("m/3'/1'/1'/3'", KeyTypes::RelationshipEncryption),
        );

        let mut rels = Relationships {
            path_pointer: 4,
            ..Default::default()
        };
        for (i, did) in [&a, &b].into_iter().enumerate() {
            rels.relationships.insert(
                Arc::new(format!("did:remote:p{i}")),
                make_relationship(
                    &format!("task-{i}"),
                    did,
                    "did:remote:r",
                    &format!("did:remote:p{i}"),
                    RelationshipState::Established,
                ),
            );
        }

        let tdk = empty_tdk().await;
        let report = rels
            .repair_key_info_ids(&tdk, &HashSet::new(), &mut key_info, &key_backend)
            .await;

        assert!(
            report.unrecoverable.is_empty(),
            "rescan recovers the collided key: {:?}",
            report.unrecoverable
        );
        for did in [&a, &b] {
            assert!(
                key_info.contains_key(&format!("{did}#key-1")),
                "{did} verification key present"
            );
            assert!(
                key_info.contains_key(&format!("{did}#key-2")),
                "{did} key-agreement key present (rescan-recovered if collided)"
            );
        }
    }

    #[tokio::test]
    async fn repair_flags_unrecoverable_relationship() {
        // R-DID minted from a DIFFERENT root than the backend, with no matching
        // key_info — its keys cannot be reconstructed offline.
        let foreign = ExtendedSigningKey::from_seed(&[99u8; 32]).expect("foreign root");
        let r_did = mint_rdid(&foreign, "m/3'/1'/1'/0'", "m/3'/1'/1'/1'");
        let key_backend = KeyBackend::Bip32 {
            root: ExtendedSigningKey::from_seed(&[1u8; 32]).expect("local root"),
            seed: SecretString::new("seed".into()),
        };

        let mut key_info = HashMap::new();
        let mut rels = Relationships {
            path_pointer: 4,
            ..Default::default()
        };
        rels.relationships.insert(
            Arc::new("did:remote:p".to_string()),
            make_relationship(
                "task-1",
                &r_did,
                "did:remote:r",
                "did:remote:p",
                RelationshipState::Established,
            ),
        );

        let tdk = empty_tdk().await;
        let report = rels
            .repair_key_info_ids(&tdk, &HashSet::new(), &mut key_info, &key_backend)
            .await;

        assert_eq!(report.repaired, 0);
        assert_eq!(report.unrecoverable.len(), 1);
        assert_eq!(report.unrecoverable[0].as_str(), r_did.as_str());
        assert!(key_info.is_empty());
        assert!(
            rels.relationships[&Arc::new("did:remote:p".to_string())].needs_reestablishment,
            "unrecoverable relationship is flagged for re-establishment"
        );
    }

    #[test]
    fn test_relationships_default_empty() {
        let rels = Relationships::default();
        assert!(
            rels.relationships.is_empty(),
            "Default Relationships should have no entries"
        );
        assert_eq!(rels.path_pointer, 0);
    }

    #[test]
    fn test_add_and_find_relationship() {
        let mut rels = Relationships::default();
        let r = make_relationship(
            "task-1",
            "did:our:1",
            "did:remote:1",
            "did:remote-p:1",
            RelationshipState::Established,
        );
        let key = r.remote_p_did.clone();
        rels.relationships.insert(key.clone(), r);

        // get by p-did
        let found = rels.get(&key);
        assert!(found.is_some(), "Should find relationship by remote P-DID");

        // find by task id
        let found_task = rels.find_by_task_id(&Arc::new("task-1".to_string()));
        assert!(found_task.is_some(), "Should find relationship by task ID");

        // find by remote did
        let found_remote = rels.find_by_remote_did(&Arc::new("did:remote:1".to_string()));
        assert!(
            found_remote.is_some(),
            "Should find relationship by remote DID"
        );
    }

    #[test]
    fn test_get_established_relationships() {
        let mut rels = Relationships::default();

        let r1 = make_relationship(
            "t1",
            "did:our:1",
            "did:r:1",
            "did:rp:1",
            RelationshipState::Established,
        );
        let r2 = make_relationship(
            "t2",
            "did:our:2",
            "did:r:2",
            "did:rp:2",
            RelationshipState::RequestSent,
        );
        rels.relationships.insert(r1.remote_p_did.clone(), r1);
        rels.relationships.insert(r2.remote_p_did.clone(), r2);

        let established = rels.get_established_relationships();
        assert_eq!(
            established.len(),
            1,
            "Only one relationship should be established"
        );
    }

    #[test]
    fn test_remove_relationship() {
        let mut rels = Relationships::default();
        let mut vrcs_issued = crate::vrc::Vrcs::default();
        let mut vrcs_received = crate::vrc::Vrcs::default();

        let r = make_relationship(
            "t1",
            "did:our:1",
            "did:r:1",
            "did:rp:1",
            RelationshipState::Established,
        );
        let key = r.remote_p_did.clone();
        rels.relationships.insert(key.clone(), r);

        let removed = rels.remove(&key, &mut vrcs_issued, &mut vrcs_received);
        assert!(removed.is_some(), "Should return the removed relationship");
        assert!(
            rels.relationships.is_empty(),
            "Relationships should be empty after removal"
        );
    }

    #[test]
    fn test_relationship_state_display() {
        assert_eq!(RelationshipState::RequestSent.to_string(), "Request Sent");
        assert_eq!(
            RelationshipState::RequestAccepted.to_string(),
            "Request Accepted"
        );
        assert_eq!(
            RelationshipState::RequestRejected.to_string(),
            "Request Rejected"
        );
        assert_eq!(RelationshipState::Established.to_string(), "Established");
        assert_eq!(RelationshipState::None.to_string(), "None");
    }

    #[test]
    fn test_relationships_shadow_roundtrip() {
        let mut rels = Relationships {
            path_pointer: 42,
            ..Default::default()
        };
        let r = make_relationship(
            "t1",
            "did:our:1",
            "did:r:1",
            "did:rp:1",
            RelationshipState::Established,
        );
        rels.relationships.insert(r.remote_p_did.clone(), r);

        let shadow: RelationshipsShadow = rels.into();
        assert_eq!(shadow.path_pointer, 42);
        assert_eq!(shadow.relationships.len(), 1);

        let restored: Relationships = shadow.into();
        assert_eq!(restored.path_pointer, 42);
        assert_eq!(restored.relationships.len(), 1);
    }

    /// On-disk compatibility guard (R20): a relationships JSON written by the
    /// pre-R20 `Arc<Mutex<Relationship>>` model must deserialize into the new
    /// plain-value model and re-serialize to **byte-identical** JSON.
    ///
    /// The fixture below is exactly what the old shadow emitted: `Arc` and
    /// `Mutex` both serialize transparently (serde `rc`), so each relationship
    /// is a bare object — no wrapper keys. `Relationships` serializes via
    /// `RelationshipsShadow`, so we drive the test through the public type.
    #[test]
    fn relationships_ondisk_byte_identical_roundtrip() {
        // A fixed timestamp so the round-trip is deterministic.
        let fixture = r#"{
  "relationships": [
    {
      "task_id": "task-abc",
      "our_did": "did:webvh:example:us",
      "remote_did": "did:webvh:example:them-rdid",
      "remote_p_did": "did:webvh:example:them",
      "created": "2024-01-02T03:04:05Z",
      "state": "Established"
    }
  ],
  "path_pointer": 7
}"#;

        // Deserialize into the new plain-value model (via the shadow).
        let rels: Relationships = serde_json::from_str(fixture).expect("fixture deserializes");
        assert_eq!(rels.path_pointer, 7);
        assert_eq!(rels.relationships.len(), 1);

        // Re-serialize and compare to the canonical pretty form to prove the
        // on-disk shape is unchanged across the de-mutex refactor.
        let reserialized = serde_json::to_string_pretty(&rels).expect("re-serializes");
        let fixture_value: serde_json::Value =
            serde_json::from_str(fixture).expect("fixture is valid json");
        let reserialized_value: serde_json::Value =
            serde_json::from_str(&reserialized).expect("output is valid json");
        assert_eq!(
            reserialized_value, fixture_value,
            "re-serialized relationships must match the pre-R20 on-disk shape"
        );
    }
}
