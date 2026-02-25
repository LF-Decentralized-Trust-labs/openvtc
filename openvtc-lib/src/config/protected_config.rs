/*! Configuration information that needs to be protected
*   but is not as critical as private key information which is stored in the OS Secure Store
*/

use std::{collections::HashMap, sync::Arc};

use crate::{
    config::secured_config::{unlock_code_decrypt, unlock_code_encrypt},
    errors::OpenVTCError,
    logs::{LogFamily, Logs},
    relationships::Relationships,
    tasks::Tasks,
    vrc::Vrcs,
};
use affinidi_tdk::TDK;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

/// A record for a single known Contact
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Contact {
    /// DID representing the contact
    pub did: Arc<String>,

    /// Optional alias for the DID
    pub alias: Option<String>,
}

// ****************************************************************************
// Contacts Collection
// ****************************************************************************

/// Contains all known contacts
/// Uses Reference Counters to avoid duplicating Contact instances
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(from = "ContactsShadow")]
pub struct Contacts {
    /// Contacts with key being DID
    pub contacts: HashMap<Arc<String>, Arc<Contact>>,

    /// Helps with finding a DID by it's alias
    #[serde(skip)]
    pub aliases: HashMap<String, Arc<Contact>>,
}
impl Contacts {
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Adds a new contact
    /// tdk: Trust Development Kit instance
    /// contact_did: DID of the contact to add
    /// alias: Optional alias for the contact
    /// check_did: Whether to check if the DID is valid
    pub async fn add_contact(
        &mut self,
        tdk: &TDK,
        contact_did: &str,
        alias: Option<String>,
        check_did: bool,
        logs: &mut Logs,
    ) -> Result<Arc<Contact>, OpenVTCError> {
        if check_did {
            match tdk.did_resolver().resolve(contact_did).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Couldn't resolve DID ({contact_did}). Reason: {e}");
                    return Err(OpenVTCError::Resolver(format!(
                        "Couldn't resolve DID ({}). Reason: {}",
                        contact_did, e
                    )));
                }
            }
        }

        let contact_did = Arc::new(contact_did.to_string());

        if let Some(alias) = &alias
            && self.aliases.contains_key(alias)
        {
            warn!("Duplicate alias ({alias}) detected! Existing alias must be removed first!");
            return Err(OpenVTCError::Contact(format!(
                "Duplicate alias ({alias}) detected! Existing alias must be removed first!"
            )));
        }

        let contact = Arc::new(Contact {
            did: contact_did.clone(),
            alias: alias.clone(),
        });

        self.contacts.insert(contact_did.clone(), contact.clone());

        if let Some(alias) = &alias {
            self.aliases.insert(alias.clone(), contact.clone());
        }

        logs.insert(
            LogFamily::Contact,
            format!(
                "Added contact ({}) alias({})",
                contact_did,
                alias.as_deref().unwrap_or("N/A")
            ),
        );

        Ok(contact)
    }

    /// Removes a contact (by DID or Alias)
    /// Returns Contact if contact was found and removed
    pub fn remove_contact(&mut self, logs: &mut Logs, id: &str) -> Option<Arc<Contact>> {
        if let Some(contact) = self.find_contact(id) {
            if let Some(alias) = &contact.alias {
                self.aliases.remove(alias);
            }

            let result = self.contacts.remove(&contact.did);

            if result.is_some() {
                logs.insert(
                    LogFamily::Contact,
                    format!(
                        "Removed contact ({}) alias({})",
                        contact.did,
                        contact.alias.as_deref().unwrap_or("N/A")
                    ),
                );
            }
            result
        } else {
            None
        }
    }

    /// Finds a contact by alias or DID
    /// will look for alias first, then DID
    pub fn find_contact(&self, id: &str) -> Option<Arc<Contact>> {
        if let Some(contact) = self.aliases.get(id) {
            Some(contact.clone())
        } else {
            #[allow(clippy::unnecessary_to_owned)] // Because using RC's
            self.contacts.get(&(id.to_string())).cloned()
        }
    }
}

/// Private Shadow struct to help with deserializing Contacts and recreating the aliases map
#[derive(Deserialize)]
struct ContactsShadow {
    contacts: HashMap<Arc<String>, Arc<Contact>>,
}

impl From<ContactsShadow> for Contacts {
    fn from(shadow: ContactsShadow) -> Self {
        let mut contacts = Contacts {
            contacts: shadow.contacts,
            aliases: HashMap::new(),
        };

        for contact in contacts.contacts.values() {
            if let Some(alias) = &contact.alias {
                contacts.aliases.insert(alias.clone(), contact.clone());
            }
        }

        contacts
    }
}

/// Primary structure used for storing protected [crate::config::Config] data that is sensitive but
/// not key data
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct ProtectedConfig {
    /// Known contacts and associated information
    pub contacts: Contacts,

    /// Relationships information
    #[serde(default)]
    pub relationships: Relationships,

    /// Known Tasks
    #[serde(default)]
    pub tasks: Tasks,

    /// VRCs Issued
    /// key = remote P-DID
    pub vrcs_issued: Vrcs,

    /// VRCs received
    /// key = remote P-DID
    pub vrcs_received: Vrcs,
}

impl ProtectedConfig {
    /// Converts ProtectedConfig to an encrypted BASE64 string for saving to disk
    pub fn save(&self, seed_bytes: &SecretVec<u8>) -> Result<String, OpenVTCError> {
        let bytes = serde_json::to_vec(self)?;

        match unlock_code_encrypt(
            seed_bytes.expose_secret().first_chunk::<32>().unwrap(),
            &bytes,
        ) {
            Ok(result) => Ok(BASE64_URL_SAFE_NO_PAD.encode(&result)),
            Err(e) => Err(e),
        }
    }

    pub fn load(seed_bytes: &SecretVec<u8>, input: &str) -> Result<ProtectedConfig, OpenVTCError> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(input)?;

        let bytes = unlock_code_decrypt(
            seed_bytes.expose_secret().first_chunk::<32>().unwrap(),
            &bytes,
        )?;

        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn get_seed(bip32: &ExtendedSigningKey, path: &str) -> Result<SecretVec<u8>, OpenVTCError> {
        Ok(SecretVec::new(
            bip32
                .derive(&path.parse::<DerivationPath>().map_err(|e| {
                    OpenVTCError::BIP32(format!("Couldn't parse derivation path ({}): {}", path, e))
                })?)
                .map_err(|e| {
                    OpenVTCError::BIP32(format!(
                        "Couldn't derive secret key for path ({}): {}",
                        path, e
                    ))
                })?
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ))
    }

    /// Derives an encryption seed from a VTA credential's private key multibase
    /// Used as a replacement for BIP32 m/0'/0'/0' when using VTA key backend
    pub fn get_seed_from_credential(private_key_multibase: &str) -> Result<SecretVec<u8>, OpenVTCError> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(private_key_multibase.as_bytes());
        Ok(SecretVec::new(hash.to_vec()))
    }
}
