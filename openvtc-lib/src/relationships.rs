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
    didcomm::{Message, PackEncryptedOptions},
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
use uuid::Uuid;

// ****************************************************************************
// Relationship Structures
// ****************************************************************************

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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(from = "RelationshipsShadow", into = "RelationshipsShadow")]
pub struct Relationships {
    /// Mapping relationships by the remote P-DID
    pub relationships: HashMap<Arc<String>, Arc<Mutex<Relationship>>>,

    /*
    /// Mapping relationships by our R-DIDs
    pub r_map: HashMap<Arc<String>, Vec<HashSet<Arc<Relationship>>>>,
    */
    /// latest BIP32 path pointer to use for new keys
    pub path_pointer: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Relationship {
    /// Task ID that this relationship may be attached to
    pub task_id: Arc<String>,

    /// What DID are we using in this relationship?
    pub our_did: Arc<String>,

    /// What is the DID of the remote party in this relationship?
    pub remote_did: Arc<String>,

    /// What is the remote end persona DID?
    /// NOTE: This may be the same as the remote did itself, or it may be a random r-did
    pub remote_p_did: Arc<String>,

    /// When was this relationship created?
    pub created: DateTime<Utc>,

    /// State machine status of this relationship
    pub state: RelationshipState,
}

impl From<RelationshipsShadow> for Relationships {
    fn from(value: RelationshipsShadow) -> Self {
        let mut relationships: HashMap<Arc<String>, Arc<Mutex<Relationship>>> = HashMap::new();
        //let mut r_map: HashMap<Arc<String>, Vec<HashSet<Arc<Relationship>>>> = HashMap::new();

        for relationship in value.relationships {
            let remote_did = relationship.lock().unwrap().remote_p_did.clone();
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

/// Used to serialize the more complex Relationships structure to SecuredConfig
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RelationshipsShadow {
    pub relationships: Vec<Arc<Mutex<Relationship>>>,
    pub path_pointer: u32,
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
    /// Generates ATM Profiles for established relationships where the local r-did is different
    /// than the local p-did
    pub async fn generate_profiles(
        &self,
        tdk: &TDK,
        our_p_did: &Arc<String>,
        mediator: &str,
        key_backend: &KeyBackend,
        key_info: &HashMap<String, KeyInfoConfig>,
    ) -> Result<HashMap<Arc<String>, Arc<ATMProfile>>, OpenVTCError> {
        let atm = tdk.atm.clone().unwrap();

        let mut profiles: HashMap<Arc<String>, Arc<ATMProfile>> = HashMap::new();

        // For VTA-managed keys, authenticate once upfront if needed
        let vta_client = if let KeyBackend::Vta {
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

            let mut client = vta_sdk::client::VtaClient::new(vta_url);
            client.set_token(token_result.access_token);
            Some(client)
        } else {
            None
        };

        for relationship in self.relationships.values() {
            let (our_did, state) = {
                let lock = relationship.lock().unwrap();
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
                            root.get_secret_from_path(path, kp).ok().map(|mut s| {
                                s.id = k.clone();
                                s
                            })
                        }
                        KeySourceMaterial::Imported { seed } => {
                            Secret::from_multibase(seed, None).ok().map(|mut s| {
                                s.id = k.clone();
                                s
                            })
                        }
                        KeySourceMaterial::VtaManaged { key_id } => {
                            if let Some(client) = &vta_client {
                                match client.get_key_secret(key_id).await {
                                    Ok(resp) => {
                                        crate::config::secret_from_vta_response(&resp, kp)
                                            .ok()
                                            .map(|mut s| {
                                                s.id = k.clone();
                                                s
                                            })
                                    }
                                    Err(_) => None,
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

    /// Removes a relationship by it's task_id
    pub fn remove_by_task_id(
        &mut self,
        id: &Arc<String>,
        vrcs_issued: &mut Vrcs,
        vrcs_recieved: &mut Vrcs,
    ) -> Option<Arc<Mutex<Relationship>>> {
        if let Some(relationship) = self
            .relationships
            .values()
            .find(|f| f.lock().unwrap().task_id == *id)
            .cloned()
        {
            self.remove(
                &relationship.lock().unwrap().remote_did,
                vrcs_issued,
                vrcs_recieved,
            )
        } else {
            None
        }
    }

    /// Removes a relationship by it's key, removes associated information tagged to the
    /// relationship such as VRCs
    /// Returns
    /// relationship removed if successful
    /// None if not found
    /// Error if something went wrong
    pub fn remove(
        &mut self,
        key: &Arc<String>,
        vrcs_issued: &mut Vrcs,
        vrcs_recieved: &mut Vrcs,
    ) -> Option<Arc<Mutex<Relationship>>> {
        // Find and remove any VRCs associated with this relationship
        vrcs_issued.remove_relationship(key);
        vrcs_recieved.remove_relationship(key);

        self.relationships.remove(key)
    }

    /// Gets a relationship using the remote P-DID key
    pub fn get(&self, p_did: &Arc<String>) -> Option<Arc<Mutex<Relationship>>> {
        self.relationships.get(p_did).cloned()
    }

    /// Finds a relationship by it's task ID
    pub fn find_by_task_id(&self, task_id: &Arc<String>) -> Option<Arc<Mutex<Relationship>>> {
        self.relationships
            .values()
            .find(|f| &f.lock().unwrap().task_id == task_id)
            .cloned()
    }

    /// Finds a relationship by it's remote DID (could be P-DID or R-DID)
    pub fn find_by_remote_did(&self, did: &Arc<String>) -> Option<Arc<Mutex<Relationship>>> {
        self.relationships
            .values()
            .find(|r| {
                let lock = r.lock().unwrap();
                lock.remote_did == *did || lock.remote_p_did == *did
            })
            .cloned()
    }

    /// Filters relationships and only returns those that are established
    pub fn get_established_relationships(&self) -> Vec<Arc<Mutex<Relationship>>> {
        self.relationships
            .values()
            .filter_map(|r| {
                let lock = r.lock().unwrap();
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

/// DIDComm message body sent to the remote party when requesting a relationship
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelationshipRequestBody {
    pub reason: Option<String>,
    pub did: String,
}

/// DIDComm message body sent to the initiator of a relationship request when the request is
/// rejected
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelationshipRejectBody {
    pub reason: Option<String>,
}

/// Body of a Relationship Rquest accept message
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelationshipAcceptBody {
    pub did: String,
}

// ****************************************************************************
// Message Handling
// ****************************************************************************

/// Creates and send the relationship rejection message to the remote party
/// atm: Affinidi Trusted Messaging instance
/// from_profile: ATM Profile of the responder
/// to: DID of who we will send this rejection message to
/// mediator_did: DID of the mediator to forward this message through
/// reason: Optional reason for rejecting the relationship request
/// thid: Thread ID for the DIDComm message
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
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
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

    // Pack the message
    let (msg, _) = msg
        .pack_encrypted(
            to,
            Some(&from_profile.inner.did),
            Some(&from_profile.inner.did),
            &atm.get_tdk().did_resolver,
            &atm.get_tdk().secrets_resolver,
            &PackEncryptedOptions {
                forward: false,
                ..Default::default()
            },
        )
        .await?;

    atm.forward_and_send_message(
        from_profile,
        false,
        &msg,
        None,
        mediator_did,
        to,
        None,
        None,
        false,
    )
    .await?;

    Ok(())
}

/// Creates and sends the relationship request accept message to the remote party
/// atm: Affinidi Trusted Messaging instance
/// from_profile: ATM Profile of the responder
/// to: DID of who we will send this rejection message to
/// mediator_did: DID of the mediator to forward this message through
/// r_did: The relationship DID to use for this relationship (May be the P-DID or R-DID)
/// thid: Thread ID for the DIDComm message
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
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
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

    // Pack the message
    // Pack the message
    let (msg, _) = msg
        .pack_encrypted(
            to,
            Some(&from_profile.inner.did),
            Some(&from_profile.inner.did),
            &atm.get_tdk().did_resolver,
            &atm.get_tdk().secrets_resolver,
            &PackEncryptedOptions {
                forward: false,
                ..Default::default()
            },
        )
        .await?;

    atm.forward_and_send_message(
        from_profile,
        false,
        &msg,
        None,
        mediator_did,
        to,
        None,
        None,
        false,
    )
    .await?;

    Ok(())
}
