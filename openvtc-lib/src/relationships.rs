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
    collections::HashMap,
    fmt::Display,
    sync::{Arc, Mutex},
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
    pub relationships: HashMap<Arc<String>, Arc<Mutex<Relationship>>>,

    /*
    /// Mapping relationships by our R-DIDs
    pub r_map: HashMap<Arc<String>, Vec<HashSet<Arc<Relationship>>>>,
    */
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
}

impl From<RelationshipsShadow> for Relationships {
    fn from(value: RelationshipsShadow) -> Self {
        let mut relationships: HashMap<Arc<String>, Arc<Mutex<Relationship>>> = HashMap::new();
        //let mut r_map: HashMap<Arc<String>, Vec<HashSet<Arc<Relationship>>>> = HashMap::new();

        for relationship in value.relationships {
            let remote_did = match relationship.lock() {
                Ok(r) => r.remote_p_did.clone(),
                Err(e) => e.into_inner().remote_p_did.clone(),
            };
            relationships.insert(remote_did.clone(), relationship.clone());

            /*
                        r_map
                            .entry(relationship.our_did.clone())
                            .or_default()
                            .push(HashSet::from([relationship.clone()]));
            */
        }

        Relationships {
            relationships,
            //r_map,
            path_pointer: value.path_pointer,
        }
    }
}

/// Flat serialization form of [`Relationships`] used for persistence in `SecuredConfig`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct RelationshipsShadow {
    pub(crate) relationships: Vec<Arc<Mutex<Relationship>>>,
    pub(crate) path_pointer: u32,
}

impl From<Relationships> for RelationshipsShadow {
    fn from(value: Relationships) -> Self {
        let relationships = value
            .relationships
            .values()
            .cloned()
            .collect::<Vec<Arc<Mutex<Relationship>>>>();
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
    /// fails, a mutex is poisoned, or secret derivation/import fails.
    pub async fn generate_profiles(
        &self,
        tdk: &TDK,
        our_p_did: &Arc<String>,
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

        // Use provided VTA client, or create one as fallback for backward compat
        let owned_vta_client;
        let vta_client: Option<&vta_sdk::client::VtaClient> = match vta_client {
            Some(client) => Some(client),
            None => {
                if let KeyBackend::Vta {
                    credential_private_key,
                    credential_did,
                    vta_did,
                    vta_url,
                    ..
                } = key_backend
                {
                    let token_result = vta_sdk::session::challenge_response(
                        vta_url,
                        credential_did,
                        credential_private_key.expose_secret(),
                        vta_did,
                    )
                    .await
                    .map_err(|e| OpenVTCError::Config(format!("VTA authentication failed: {e}")))?;

                    owned_vta_client = {
                        let c = vta_sdk::client::VtaClient::new(vta_url);
                        c.set_token(token_result.access_token);
                        c
                    };
                    Some(&owned_vta_client)
                } else {
                    None
                }
            }
        };

        for relationship in self.relationships.values() {
            let (our_did, state) = {
                let lock = relationship.lock().map_err(|e| {
                    warn!("relationship mutex poisoned: {e}");
                    OpenVTCError::MutexPoisoned(format!("Relationship mutex poisoned: {e}"))
                })?;
                (lock.our_did.clone(), lock.state.clone())
            };
            if state == RelationshipState::Established && &our_did != our_p_did {
                // Create an ATMProfile for this relationship
                let profile =
                    ATMProfile::new(&atm, None, our_did.to_string(), Some(mediator.to_string()))
                        .await?;
                profiles.insert(our_did.clone(), atm.profile_add(&profile, false).await?);

                // Generate secrets for this DID
                let mut secrets: Vec<Secret> = Vec::new();
                for (k, v) in key_info.iter() {
                    if !k.starts_with(our_did.as_str()) {
                        continue;
                    }
                    let kp = match v.purpose {
                        KeyTypes::RelationshipVerification => KeyPurpose::Signing,
                        KeyTypes::RelationshipEncryption => KeyPurpose::Encryption,
                        _ => continue,
                    };
                    let secret = match &v.path {
                        KeySourceMaterial::Derived { path } => {
                            let KeyBackend::Bip32 { root, .. } = key_backend else {
                                continue;
                            };
                            root.get_secret_from_path(path, kp)
                                .map(|mut s| {
                                    s.id = k.clone();
                                    s
                                })
                                .map_err(|e| {
                                    warn!("secret derivation failed for key {}: {e}", k);
                                    e
                                })
                                .ok()
                        }
                        KeySourceMaterial::Imported { seed } => Secret::from_multibase(seed, None)
                            .map(|mut s| {
                                s.id = k.clone();
                                s
                            })
                            .map_err(|e| {
                                warn!("secret import failed for key {}: {e}", k);
                                e
                            })
                            .ok(),
                        KeySourceMaterial::VtaManaged { key_id } => {
                            if let Some(client) = vta_client {
                                match client.get_key_secret(key_id).await {
                                    Ok(resp) => crate::config::secret_from_vta_response(&resp, kp)
                                        .map(|mut s| {
                                            s.id = k.clone();
                                            s
                                        })
                                        .map_err(|e| {
                                            warn!("VTA secret retrieval failed for key {}: {e}", k);
                                            e
                                        })
                                        .ok(),
                                    Err(e) => {
                                        warn!("VTA get_key_secret failed for key {}: {e}", k);
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        }
                    };
                    if let Some(s) = secret {
                        secrets.push(s);
                    }
                }
                tdk.get_shared_state()
                    .secrets_resolver
                    .insert_vec(&secrets)
                    .await;
            }
        }

        Ok(profiles)
    }

    /// Removes a relationship by its task ID, along with any associated VRCs.
    ///
    /// # Errors
    ///
    /// Returns an error if the relationship mutex is poisoned.
    pub fn remove_by_task_id(
        &mut self,
        id: &Arc<String>,
        vrcs_issued: &mut Vrcs,
        vrcs_received: &mut Vrcs,
    ) -> Result<Option<Arc<Mutex<Relationship>>>, OpenVTCError> {
        let found = self
            .relationships
            .values()
            .find(|f| f.lock().map(|r| r.task_id == *id).unwrap_or(false))
            .cloned();

        if let Some(relationship) = found {
            let remote_did = relationship
                .lock()
                .map_err(|e| {
                    warn!("relationship mutex poisoned: {e}");
                    OpenVTCError::MutexPoisoned(format!("Relationship mutex poisoned: {e}"))
                })?
                .remote_did
                .clone();
            debug!("relationship removed: task_id={}", id);
            Ok(self.remove(&remote_did, vrcs_issued, vrcs_received))
        } else {
            Ok(None)
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
    ) -> Option<Arc<Mutex<Relationship>>> {
        // Find and remove any VRCs associated with this relationship
        vrcs_issued.remove_relationship(key);
        vrcs_received.remove_relationship(key);

        let removed = self.relationships.remove(key);
        if removed.is_some() {
            debug!("relationship removed: remote_did={}", key);
        }
        removed
    }

    /// Gets a relationship using the remote P-DID key
    pub fn get(&self, p_did: &Arc<String>) -> Option<Arc<Mutex<Relationship>>> {
        self.relationships.get(p_did).cloned()
    }

    /// Finds a relationship by its task ID.
    pub fn find_by_task_id(&self, task_id: &Arc<String>) -> Option<Arc<Mutex<Relationship>>> {
        self.relationships
            .values()
            .find(|f| f.lock().map(|r| &r.task_id == task_id).unwrap_or(false))
            .cloned()
    }

    /// Finds a relationship by its remote DID (either P-DID or R-DID).
    pub fn find_by_remote_did(&self, did: &Arc<String>) -> Option<Arc<Mutex<Relationship>>> {
        self.relationships
            .values()
            .find(|r| {
                r.lock()
                    .map(|lock| lock.remote_did == *did || lock.remote_p_did == *did)
                    .unwrap_or(false)
            })
            .cloned()
    }

    /// Returns only the relationships in the [`RelationshipState::Established`] state.
    pub fn get_established_relationships(&self) -> Vec<Arc<Mutex<Relationship>>> {
        self.relationships
            .values()
            .filter_map(|r| {
                let lock = r.lock().ok()?;
                if lock.state == RelationshipState::Established {
                    Some(r.clone())
                } else {
                    None
                }
            })
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
    pub reason: Option<String>,
    /// The DID the requester wants to use for this relationship.
    pub did: String,
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
    .expires_time(60 * 60 * 48) // 48 hours
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
    .expires_time(60 * 60 * 48) // 48 hours
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
        rels.relationships
            .insert(key.clone(), Arc::new(Mutex::new(r)));

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
        rels.relationships
            .insert(r1.remote_p_did.clone(), Arc::new(Mutex::new(r1)));
        rels.relationships
            .insert(r2.remote_p_did.clone(), Arc::new(Mutex::new(r2)));

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
        rels.relationships
            .insert(key.clone(), Arc::new(Mutex::new(r)));

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
        rels.relationships
            .insert(r.remote_p_did.clone(), Arc::new(Mutex::new(r)));

        let shadow: RelationshipsShadow = rels.into();
        assert_eq!(shadow.path_pointer, 42);
        assert_eq!(shadow.relationships.len(), 1);

        let restored: Relationships = shadow.into();
        assert_eq!(restored.path_pointer, 42);
        assert_eq!(restored.relationships.len(), 1);
    }
}
