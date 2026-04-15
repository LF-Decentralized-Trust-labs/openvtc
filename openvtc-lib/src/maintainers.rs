//! Kernel maintainers list management and DIDComm messaging.
//!
//! Provides structures and helpers for exchanging lists of known kernel
//! maintainers between OpenVTC peers over DIDComm.

use std::{sync::Arc, time::SystemTime};

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::errors::OpenVTCError;

/// A known kernel maintainer identified by a human-readable alias and a DID.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Maintainer {
    /// Human-readable name or alias for this maintainer.
    pub alias: String,
    /// The maintainer's DID (e.g. `did:webvh:...`).
    pub did: String,
}

/// Creates and sends a kernel maintainers list response to a remote party via DIDComm.
///
/// - `atm`: The Affinidi Trusted Messaging service instance.
/// - `from_profile`: ATM profile of the sender (our identity).
/// - `to`: DID of the remote party to send the list to.
/// - `mediator_did`: DID of the mediator used for message forwarding.
/// - `list`: The list of `Maintainer` entries to include in the response body.
/// - `thid`: Thread ID linking this response to the original request.
///
/// # Errors
///
/// Returns an error if the system clock is unavailable, message encryption fails,
/// or message delivery fails.
pub async fn create_send_maintainers_list(
    atm: &ATM,
    from_profile: &Arc<ATMProfile>,
    to: &str,
    mediator_did: &str,
    list: &[Maintainer],
    thid: &str,
) -> Result<(), OpenVTCError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| OpenVTCError::Config(format!("System clock error: {e}")))?
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://kernel.org/maintainers/1.0/list/response".to_string(),
        json!(list),
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

    #[test]
    fn test_maintainer_creation() {
        let m = Maintainer {
            alias: "Alice".to_string(),
            did: "did:example:123".to_string(),
        };
        assert_eq!(m.alias, "Alice");
        assert_eq!(m.did, "did:example:123");
    }

    #[test]
    fn test_maintainer_clone() {
        let m = Maintainer {
            alias: "Bob".to_string(),
            did: "did:example:456".to_string(),
        };
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    #[test]
    fn test_maintainer_serde_roundtrip() {
        let m = Maintainer {
            alias: "Charlie".to_string(),
            did: "did:example:789".to_string(),
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let restored: Maintainer = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, restored);
    }

    #[test]
    fn test_maintainer_debug_format() {
        let m = Maintainer {
            alias: "Debug".to_string(),
            did: "did:example:dbg".to_string(),
        };
        let dbg = format!("{:?}", m);
        assert!(dbg.contains("Debug"), "Debug output should contain alias");
        assert!(
            dbg.contains("did:example:dbg"),
            "Debug output should contain DID"
        );
    }
}
