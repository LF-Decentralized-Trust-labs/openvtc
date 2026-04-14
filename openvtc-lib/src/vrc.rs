//! Verified Relationship Credentials (VRC).
//!
//! VRCs are credentials issued between parties in an established relationship.
//! This module provides storage (`Vrcs`), request/reject message builders
//! (`VrcRequest`, `VRCRequestReject`), and a trait for wrapping credentials
//! into DIDComm messages (`DtgCredentialMessage`).

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
use tracing::debug;
use uuid::Uuid;

/// Collection of VRCs, keyed by remote P-DID and then by VRC ID.
///
/// Typically two instances are maintained: one for issued VRCs and one for received VRCs.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Vrcs {
    /// Hashmap of VRCs
    /// key = remote P-DID
    /// secondary key is the VRC-ID
    vrcs: HashMap<Arc<String>, HashMap<Arc<String>, Arc<DTGCredential>>>,
}

impl Vrcs {
    /// Returns an iterator over all per-relationship VRC maps.
    pub fn values(&self) -> Values<'_, Arc<String>, HashMap<Arc<String>, Arc<DTGCredential>>> {
        self.vrcs.values()
    }

    /// Returns an iterator over all remote P-DID keys that have associated VRCs.
    pub fn keys(&self) -> Keys<'_, Arc<String>, HashMap<Arc<String>, Arc<DTGCredential>>> {
        self.vrcs.keys()
    }

    /// Returns all VRCs for the given remote P-DID, or `None` if no VRCs exist.
    pub fn get(&self, id: &Arc<String>) -> Option<&HashMap<Arc<String>, Arc<DTGCredential>>> {
        self.vrcs.get(id)
    }

    /// Insert a new VRC for the given remote P-DID.
    ///
    /// # Errors
    ///
    /// Returns `OpenVTCError::InvalidMessage` if the VRC has no proof value.
    pub fn insert(
        &mut self,
        remote_p_did: &Arc<String>,
        vrc: Arc<DTGCredential>,
    ) -> Result<(), OpenVTCError> {
        let hash = Arc::new(
            vrc.proof_value()
                .ok_or_else(|| OpenVTCError::InvalidMessage("VRC has no proof value".to_string()))?
                .to_string(),
        );

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

        Ok(())
    }

    /// Removes a VRC by its ID from all relationships.
    pub fn remove_vrc(&mut self, vrc_id: &Arc<String>) {
        debug!("removing VRC {}", vrc_id);
        for r in self.vrcs.values_mut() {
            r.retain(|vrc_id_key, _| vrc_id_key != vrc_id);
        }
    }

    /// Removes all VRCs for the given remote P-DID.
    ///
    /// Returns `true` if any VRCs were removed.
    pub fn remove_relationship(&mut self, remote_p_did: &Arc<String>) -> bool {
        let removed = self.vrcs.remove(remote_p_did).is_some();
        if removed {
            debug!("removing VRCs for relationship {}", remote_p_did);
        }
        removed
    }
}

/// Extension trait for wrapping a `DTGCredential` into a DIDComm message.
pub trait DtgCredentialMessage {
    /// Builds a DIDComm message containing this credential as the body.
    ///
    /// The message type is set to `VRCIssued`. An optional `thid` (thread ID)
    /// links the message to a prior VRC request conversation.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock is unavailable or the credential
    /// cannot be serialized to JSON.
    fn message(&self, from: &str, to: &str, thid: Option<&str>) -> Result<Message, OpenVTCError>;
}

impl DtgCredentialMessage for DTGCredential {
    fn message(&self, from: &str, to: &str, thid: Option<&str>) -> Result<Message, OpenVTCError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| OpenVTCError::Config(format!("System clock error: {e}")))?
            .as_secs();
        let mut builder = Message::build(
            Uuid::new_v4().to_string(),
            String::from(MessageType::VRCIssued),
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

/// A request asking a remote party to issue a VRC.
///
/// Contains optional hints to help the issuer create the VRC, but does not
/// guarantee the issuer will honor the requested details.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VrcRequest {
    /// Optional reason for the VRC request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl VrcRequest {
    /// Creates a DIDComm message for this VRC request.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock is unavailable or the request
    /// cannot be serialized to JSON.
    pub fn create_message(
        &self,
        to: &Arc<String>,
        from: &Arc<String>,
    ) -> Result<Message, OpenVTCError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| OpenVTCError::Config(format!("System clock error: {e}")))?
            .as_secs();
        Ok(Message::build(
            Uuid::new_v4().to_string(),
            crate::protocol_urls::VRC_REQUEST.to_string(),
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

/// DIDComm message body for rejecting a VRC request.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VRCRequestReject {
    /// Optional reason for the rejection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl VRCRequestReject {
    /// Creates a DIDComm rejection message for a VRC request.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock is unavailable or the body
    /// cannot be serialized to JSON.
    pub fn create_message(
        to: &Arc<String>,
        from: &Arc<String>,
        thid: &Arc<String>,
        reason: Option<String>,
    ) -> Result<Message, OpenVTCError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| OpenVTCError::Config(format!("System clock error: {e}")))?
            .as_secs();
        Ok(Message::build(
            Uuid::new_v4().to_string(),
            crate::protocol_urls::VRC_REJECTED.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrcs_default_empty() {
        let vrcs = Vrcs::default();
        assert_eq!(
            vrcs.keys().count(),
            0,
            "Default Vrcs should have no entries"
        );
        assert_eq!(vrcs.values().count(), 0);
    }

    #[test]
    fn test_vrcs_remove_relationship() {
        let mut vrcs = Vrcs::default();
        let key = Arc::new("did:remote:1".to_string());
        // remove on empty should return false
        assert!(!vrcs.remove_relationship(&key));
    }

    #[test]
    fn test_vrcs_get_missing_key() {
        let vrcs = Vrcs::default();
        let key = Arc::new("did:nonexistent".to_string());
        assert!(
            vrcs.get(&key).is_none(),
            "get on missing key should return None"
        );
    }

    #[test]
    fn test_vrc_request_default() {
        let req = VrcRequest::default();
        assert!(req.reason.is_none());
    }

    #[test]
    fn test_vrc_request_serde_roundtrip() {
        let req = VrcRequest {
            reason: Some("testing".to_string()),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let restored: VrcRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.reason.as_deref(), Some("testing"));
    }

    #[test]
    fn test_vrc_request_reject_serde_roundtrip() {
        let reject = VRCRequestReject {
            reason: Some("not trusted".to_string()),
        };
        let json = serde_json::to_string(&reject).expect("serialize");
        let restored: VRCRequestReject = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.reason.as_deref(), Some("not trusted"));
    }
}
