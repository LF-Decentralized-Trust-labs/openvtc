use std::{sync::Arc, time::SystemTime};

use affinidi_tdk::{
    didcomm::{Message, PackEncryptedOptions},
    messaging::{ATM, profiles::ATMProfile},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::errors::OpenVTCError;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Maintainer {
    pub alias: String,
    pub did: String,
}

/// Creates and send the Kernel Maintainers list message to the remote party
/// atm: Affinidi Trusted Messaging instance
/// from_profile: ATM Profile of the responder
/// to: DID of who we will send this rejection message to
/// mediator_did: DID of the mediator to forward this message through
/// list: Maintainers list
/// thid: Thread ID for the DIDComm message
pub async fn create_send_maintainers_list(
    atm: &ATM,
    from_profile: &Arc<ATMProfile>,
    to: &str,
    mediator_did: &str,
    list: &Vec<Maintainer>,
    thid: &str,
) -> Result<(), OpenVTCError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "https://kernel.org/maintainers/1.0/list/response".to_string(),
        json!(list),
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
