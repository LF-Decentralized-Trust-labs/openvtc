//! A two-tier credential store: durable when it safely can be, volatile when it
//! cannot.
//!
//! This is what OpenVTC registers on Linux when no Secret Service daemon is
//! reachable. It pairs the durable [`file`](super::file) store with the kernel
//! keyring, and picks per write:
//!
//! - an **encrypted** blob (the profile has a passphrase or a hardware token)
//!   goes to the durable store, because writing it to disk reveals nothing;
//! - an **unencrypted** blob is refused by the file store's policy and falls
//!   back to the volatile store, so a bare seed is never written to disk as a
//!   side effect of a fallback the user never chose.
//!
//! Reads try durable first, then volatile, which makes the migration free: an
//! existing kernel-keyring entry keeps working, and the first save after a
//! passphrase is set moves it to disk.
//!
//! The per-entry truth — which tier is actually holding a given profile — is
//! what [`super::probe`] reports and what the volatile-profile warning is keyed
//! on. Asking the *store* is not enough, because this one is both.

use keyring_core::{
    Entry, Error, Result,
    api::{CredentialApi, CredentialPersistence, CredentialStore, CredentialStoreApi},
};
use std::{any::Any, collections::HashMap, sync::Arc};

/// Attribute key under which a credential reports its tier.
///
/// Namespaced because Secret Service items carry arbitrary caller-set
/// attributes: a third-party item with a bare `backend` key would otherwise be
/// read as one of ours.
pub const BACKEND_ATTR: &str = "openvtc-backend";

/// Value of [`BACKEND_ATTR`] for a credential served by the volatile tier.
pub const BACKEND_VOLATILE: &str = "volatile";

/// A durable store fronting a volatile one.
pub struct Store {
    durable: Arc<CredentialStore>,
    volatile: Arc<CredentialStore>,
    id: String,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeStore")
            .field("durable", &self.durable.vendor())
            .field("volatile", &self.volatile.vendor())
            .finish()
    }
}

impl Store {
    /// Pair a durable store with a volatile fallback.
    #[must_use]
    pub fn new(durable: Arc<CredentialStore>, volatile: Arc<CredentialStore>) -> Arc<Self> {
        Arc::new(Store {
            id: format!("{} over {}", durable.vendor(), volatile.vendor()),
            durable,
            volatile,
        })
    }
}

/// One credential per tier, resolved lazily on each call.
struct Cred {
    durable: Entry,
    volatile: Entry,
    service: String,
    user: String,
}

impl std::fmt::Debug for Cred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeCred")
            .field("service", &self.service)
            .field("user", &self.user)
            .finish()
    }
}

impl CredentialApi for Cred {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        match self.durable.set_secret(secret) {
            Ok(()) => {
                // The durable copy is now authoritative and reads check it
                // first, so a stale volatile copy is only a liability — an old
                // seed left sitting in the kernel keyring. Best-effort: failing
                // to clean it up must not fail the save that already succeeded.
                let _ = self.volatile.delete_credential();
                Ok(())
            }
            // The durable store's policy refused this secret (an unencrypted
            // blob). That is a deliberate refusal, not a fault: fall back.
            Err(Error::NotSupportedByStore(_)) => self.volatile.set_secret(secret),
            Err(e) => Err(e),
        }
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        match self.durable.get_secret() {
            Err(Error::NoEntry) => self.volatile.get_secret(),
            other => other,
        }
    }

    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        match self.durable.get_attributes() {
            Err(Error::NoEntry) => {
                // Errors in the same cases as get_secret, per the contract.
                self.volatile.get_secret()?;
                Ok(HashMap::from([(
                    BACKEND_ATTR.to_string(),
                    BACKEND_VOLATILE.to_string(),
                )]))
            }
            other => other,
        }
    }

    fn delete_credential(&self) -> Result<()> {
        let durable = self.durable.delete_credential();
        let volatile = self.volatile.delete_credential();
        match (durable, volatile) {
            // Nothing anywhere — the caller asked to delete what isn't there.
            (Err(Error::NoEntry), Err(Error::NoEntry)) => Err(Error::NoEntry),
            // A real failure on either tier is reported; a NoEntry alongside a
            // success just means that tier didn't hold a copy.
            (Err(e), _) if !matches!(e, Error::NoEntry) => Err(e),
            (_, Err(e)) if !matches!(e, Error::NoEntry) => Err(e),
            _ => Ok(()),
        }
    }

    fn get_credential(&self) -> Result<Option<Arc<keyring_core::api::Credential>>> {
        // `None` means "I am already a wrapper — keep using me", which is what
        // this credential is: it spans both tiers, and which one holds the
        // secret can change on the next save. All we owe the caller here is
        // whether a credential exists at all, without pulling the secret.
        match self.durable.get_credential() {
            Ok(_) => Ok(None),
            Err(Error::NoEntry) => self.volatile.get_credential().map(|_| None),
            Err(e) => Err(e),
        }
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        format!(
            "OpenVTC composite store ({} over {})",
            self.durable.vendor(),
            self.volatile.vendor()
        )
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        Ok(Entry::new_with_credential(Arc::new(Cred {
            durable: self.durable.build(service, user, modifiers)?,
            volatile: self.volatile.build(service, user, modifiers)?,
            service: service.to_string(),
            user: user.to_string(),
        })))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Deliberately [`Unspecified`](CredentialPersistence::Unspecified): this
    /// store's durability is a per-credential fact, not a store-wide one.
    /// [`super::probe`] answers it for a given profile.
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::Unspecified
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_store::file;
    use std::path::PathBuf;

    /// Stands in for "is this blob encrypted?" — the real policy is
    /// `config::secured_config::require_encrypted_blob`.
    fn refuse_plain(secret: &[u8]) -> std::result::Result<(), String> {
        if secret.starts_with(b"plain:") {
            Err("unencrypted".to_string())
        } else {
            Ok(())
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("openvtc-composite-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Two file stores stand in for the two tiers: the "volatile" one simply
    /// has no policy. This exercises the routing, which is the part that can be
    /// wrong — the kernel keyring's own behaviour is not ours to test.
    fn pair(name: &str) -> (Arc<Store>, PathBuf, PathBuf) {
        let durable_dir = tmpdir(&format!("{name}-durable"));
        let volatile_dir = tmpdir(&format!("{name}-volatile"));
        let store = Store::new(
            file::Store::new(durable_dir.clone(), Some(refuse_plain)),
            file::Store::new(volatile_dir.clone(), None),
        );
        (store, durable_dir, volatile_dir)
    }

    fn cleanup(a: &PathBuf, b: &PathBuf) {
        let _ = std::fs::remove_dir_all(a);
        let _ = std::fs::remove_dir_all(b);
    }

    #[test]
    fn encrypted_secret_goes_to_the_durable_tier() {
        let (store, durable, volatile) = pair("encrypted");
        let entry = store.build("openvtc", "default", None).unwrap();
        entry.set_secret(b"sealed").unwrap();
        assert!(durable.exists(), "durable tier should hold the secret");
        assert!(
            !volatile.exists(),
            "volatile tier should not have been touched"
        );
        assert_eq!(entry.get_secret().unwrap(), b"sealed");
        assert_eq!(
            entry.get_attributes().unwrap().get(BACKEND_ATTR).unwrap(),
            crate::secure_store::BACKEND_FILE
        );
        cleanup(&durable, &volatile);
    }

    /// The security property: an unprotected profile is never written to disk
    /// in the clear as a side effect of wanting durability.
    #[test]
    fn unencrypted_secret_falls_back_to_the_volatile_tier() {
        let (store, durable, volatile) = pair("plain");
        let entry = store.build("openvtc", "default", None).unwrap();
        entry.set_secret(b"plain:seed").unwrap();
        assert!(
            !durable.exists(),
            "a bare seed must not reach the durable tier"
        );
        assert_eq!(entry.get_secret().unwrap(), b"plain:seed");
        assert_eq!(
            entry.get_attributes().unwrap().get(BACKEND_ATTR).unwrap(),
            BACKEND_VOLATILE
        );
        cleanup(&durable, &volatile);
    }

    /// The migration path: an existing volatile entry keeps working, and the
    /// first encrypted save moves it — leaving no stale copy behind.
    #[test]
    fn setting_a_passphrase_migrates_the_secret_and_clears_the_old_copy() {
        let (store, durable, volatile) = pair("migrate");
        let entry = store.build("openvtc", "default", None).unwrap();

        entry.set_secret(b"plain:seed").unwrap();
        assert_eq!(entry.get_secret().unwrap(), b"plain:seed");

        // The user sets a passphrase; the blob is now encrypted.
        entry.set_secret(b"sealed").unwrap();
        assert_eq!(entry.get_secret().unwrap(), b"sealed");
        assert_eq!(
            entry.get_attributes().unwrap().get(BACKEND_ATTR).unwrap(),
            crate::secure_store::BACKEND_FILE
        );

        // The old plaintext copy must not survive in the volatile tier, where
        // a later read-fallback could resurrect a superseded seed.
        let volatile_entry = file::Store::new(volatile.clone(), None)
            .build("openvtc", "default", None)
            .unwrap();
        assert!(matches!(volatile_entry.get_secret(), Err(Error::NoEntry)));
        cleanup(&durable, &volatile);
    }

    #[test]
    fn reads_prefer_the_durable_tier() {
        let (store, durable, volatile) = pair("prefer");
        // Seed both tiers directly, behind the composite's back.
        file::Store::new(volatile.clone(), None)
            .build("openvtc", "default", None)
            .unwrap()
            .set_secret(b"stale")
            .unwrap();
        file::Store::new(durable.clone(), None)
            .build("openvtc", "default", None)
            .unwrap()
            .set_secret(b"current")
            .unwrap();
        let entry = store.build("openvtc", "default", None).unwrap();
        assert_eq!(entry.get_secret().unwrap(), b"current");
        cleanup(&durable, &volatile);
    }

    #[test]
    fn delete_clears_both_tiers_and_reports_nothing_to_delete() {
        let (store, durable, volatile) = pair("delete");
        let entry = store.build("openvtc", "default", None).unwrap();
        assert!(
            matches!(entry.delete_credential(), Err(Error::NoEntry)),
            "deleting what is not there must report NoEntry"
        );

        file::Store::new(volatile.clone(), None)
            .build("openvtc", "default", None)
            .unwrap()
            .set_secret(b"stale")
            .unwrap();
        file::Store::new(durable.clone(), None)
            .build("openvtc", "default", None)
            .unwrap()
            .set_secret(b"current")
            .unwrap();

        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
        cleanup(&durable, &volatile);
    }

    /// A tier holding nothing is not an error when the other one succeeded.
    #[test]
    fn delete_succeeds_when_only_one_tier_holds_the_secret() {
        let (store, durable, volatile) = pair("delete-one");
        let entry = store.build("openvtc", "default", None).unwrap();
        entry.set_secret(b"sealed").unwrap();
        entry.delete_credential().unwrap();
        cleanup(&durable, &volatile);
    }
}
