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
        }
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
