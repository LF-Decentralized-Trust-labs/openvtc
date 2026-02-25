/*!
*   Verified Relationship Credentials (VRC)
*/

use crate::{MessageType, errors::OpenVTCError};
use affinidi_tdk::didcomm::Message;
use dtg_credentials::DTGCredential;
use serde::{Deserialize, Serialize};
use std::{
    collections::{
        HashMap,
        hash_map::{Keys, Values},
    },
    sync::Arc,
    time::SystemTime,
};
use uuid::Uuid;

/// Collection of VRCs
/// Often used side-by-side with a set for issued and 2nd set for received
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Vrcs {
    /// Hashmap of VRCs
    /// key = remote P-DID
    /// secondary key is the VRC-ID
    vrcs: HashMap<Arc<String>, HashMap<Arc<String>, Arc<DTGCredential>>>,
}

impl Vrcs {
    /// Get all VRC Values
    pub fn values(&self) -> Values<'_, Arc<String>, HashMap<Arc<String>, Arc<DTGCredential>>> {
        self.vrcs.values()
    }

    /// Get all the remote P-DID keys that exist with a VRC
    pub fn keys(&self) -> Keys<'_, Arc<String>, HashMap<Arc<String>, Arc<DTGCredential>>> {
        self.vrcs.keys()
    }

    /// Get all VRCs for a specific P-DID
    pub fn get(&self, id: &Arc<String>) -> Option<&HashMap<Arc<String>, Arc<DTGCredential>>> {
        self.vrcs.get(id)
    }

    /// Insert a new VRC for the given remote P-DID
    pub fn insert(&mut self, remote_p_did: &Arc<String>, vrc: Arc<DTGCredential>) {
        let hash = Arc::new(vrc.proof_value().unwrap().to_string());

        self.vrcs
            .entry(remote_p_did.clone())
            .and_modify(|hm| {
                hm.insert(hash.clone(), vrc.clone());
            })
            .or_insert({
                let mut hm = HashMap::new();
                hm.insert(hash, vrc);
                hm
            });
    }

    /// Removes a VRC using the VRC ID from the list of VRCs
    pub fn remove_vrc(&mut self, vrc_id: &Arc<String>) {
        for r in self.vrcs.values_mut() {
            r.retain(|vrc_id_key, _| vrc_id_key != vrc_id);
        }
    }

    /// Removes a relationship (which drops all the VRC's associated with it)
    /// returns true if a value was removed
    pub fn remove_relationship(&mut self, remote_p_did: &Arc<String>) -> bool {
        self.vrcs.remove(remote_p_did).is_some()
    }
}

pub trait DtgCredentialMessage {
    /// Create a DIDComm message for a DTGCredential
    /// NOTE: Only supports VRC due to the Message Type being set
    fn message(&self, from: &str, to: &str, thid: Option<&str>) -> Result<Message, OpenVTCError>;
}

impl DtgCredentialMessage for DTGCredential {
    fn message(&self, from: &str, to: &str, thid: Option<&str>) -> Result<Message, OpenVTCError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut builder = Message::build(
            Uuid::new_v4().to_string(),
            MessageType::VRCIssued.into(),
            serde_json::to_value(self)?,
        )
        .from(from.to_string())
        .to(to.to_string())
        .created_time(now)
        .expires_time(60 * 60 * 48); // 48 hours

        if let Some(thid_value) = thid {
            builder = builder.thid(thid_value.to_string());
        }

        Ok(builder.finalize())
    }
}

// ****************************************************************************
// VRC Request Structure
// ****************************************************************************

/// Structure of a request to someone to issue a VRC. Contains hints and information to help the
/// issuer create the VRC.
/// NOTE: It does not guarantee that the issuer will issue a VRC with the requested details.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VrcRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional: Include a reason for the VRC Request?
    pub reason: Option<String>,
}

impl VrcRequest {
    /// Creates a DIDComm message for the request
    pub fn create_message(
        &self,
        to: &Arc<String>,
        from: &Arc<String>,
    ) -> Result<Message, OpenVTCError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(Message::build(
            Uuid::new_v4().to_string(),
            "https://firstperson.network/vrc/1.0/request".to_string(),
            serde_json::to_value(self)?,
        )
        .from(from.to_string())
        .to(to.to_string())
        .created_time(now)
        .expires_time(60 * 60 * 48) // 48 hours
        .finalize())
    }
}

// ****************************************************************************
// VRC Request Reject Structure
// ****************************************************************************

/// VRC Request Rejected body
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VRCRequestReject {
    /// Optional: A reason for the rejection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl VRCRequestReject {
    /// Creates a DIDComm message for the rejection
    pub fn create_message(
        to: &Arc<String>,
        from: &Arc<String>,
        thid: &Arc<String>,
        reason: Option<String>,
    ) -> Result<Message, OpenVTCError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(Message::build(
            Uuid::new_v4().to_string(),
            "https://firstperson.network/vrc/1.0/rejected".to_string(),
            serde_json::to_value(VRCRequestReject { reason })?,
        )
        .from(from.to_string())
        .to(to.to_string())
        .thid(thid.to_string())
        .created_time(now)
        .expires_time(60 * 60 * 48) // 48 hours
        .finalize())
    }
}
