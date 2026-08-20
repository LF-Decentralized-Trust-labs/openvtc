//! Where OpenVTC keeps a profile's secrets, and how durable that place is.
//!
//! The `SecuredConfig` blob — a profile's BIP32 seed or VTA credential bundle —
//! is written to an OS credential store through [`keyring_core`]. Which store
//! that is depends on the platform, and **they do not all keep what you give
//! them**: the Linux kernel keyring is documented as RAM-only. Treating every
//! backend as equally permanent is how a reboot came to look like a corrupt
//! install (`No matching credential found`) instead of the expected loss it was.
//!
//! This module makes durability a first-class, queryable property:
//!
//! - [`Durability`] classifies a backend by how long it keeps a secret;
//! - [`describe_active`] says which store this process registered;
//! - [`probe`] answers the only question that matters for a given profile —
//!   is the credential there, and will it still be there after a reboot?
//!
//! [`mod@file`] is the durable store an operator can select deliberately on a
//! machine with no OS keyring. There is no automatic downgrade: registration
//! lives in the binary, which fails closed when the OS store cannot be opened
//! and calls [`record_active`] so diagnostics can report what was chosen.

pub mod file;

use crate::{config::secured_config::service_name, errors::OpenVTCError};

/// Attribute key under which a credential reports which backend served it.
///
/// Namespaced because Secret Service items carry arbitrary caller-set
/// attributes: a third-party item with a bare `backend` key would otherwise be
/// read as one of ours.
pub const BACKEND_ATTR: &str = "openvtc-backend";

/// Value of [`BACKEND_ATTR`] for a credential served by the durable file store.
pub const BACKEND_FILE: &str = "file";
use keyring_core::{Entry, api::CredentialPersistence};
use std::sync::OnceLock;

/// How long a credential store keeps what it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Survives reboots — kept on disk until explicitly deleted.
    Durable,
    /// Lost at logout.
    UntilLogout,
    /// Lost at reboot — the Linux kernel keyring.
    UntilReboot,
    /// Lost when the process exits.
    UntilExit,
    /// The store did not say, or says it depends on the credential.
    Unknown,
}

impl Durability {
    /// True when a secret stored here can disappear without the user deleting
    /// it — the condition that warrants warning them to keep a backup.
    #[must_use]
    pub fn is_volatile(&self) -> bool {
        matches!(
            self,
            Durability::UntilLogout | Durability::UntilReboot | Durability::UntilExit
        )
    }

    /// A short phrase naming what destroys the secret, for user-facing text.
    #[must_use]
    pub fn lifetime_phrase(&self) -> &'static str {
        match self {
            Durability::Durable => "kept until deleted",
            Durability::UntilLogout => "lost when you log out",
            Durability::UntilReboot => "lost when this machine reboots",
            Durability::UntilExit => "lost when OpenVTC exits",
            Durability::Unknown => "lifetime not reported by the store",
        }
    }
}

impl From<CredentialPersistence> for Durability {
    fn from(p: CredentialPersistence) -> Self {
        match p {
            CredentialPersistence::UntilDelete => Durability::Durable,
            CredentialPersistence::UntilLogout => Durability::UntilLogout,
            CredentialPersistence::UntilReboot => Durability::UntilReboot,
            CredentialPersistence::ProcessOnly | CredentialPersistence::EntryOnly => {
                Durability::UntilExit
            }
            // `CredentialPersistence` is `#[non_exhaustive]`; an unrecognised
            // value must not be optimistically reported as durable.
            _ => Durability::Unknown,
        }
    }
}

/// What the running binary registered as its credential store.
#[derive(Debug, Clone)]
pub struct StoreDescription {
    /// Short human name, e.g. `macOS Keychain`.
    pub label: String,
    /// Where the secrets physically live, in words the user can act on.
    pub location: String,
    /// Store-wide durability. `Unknown` for the composite store, whose answer
    /// is per credential — see [`probe`].
    pub durability: Durability,
    /// A shell command that shows the user the entry themselves, if one exists.
    pub inspect_hint: Option<String>,
}

static ACTIVE: OnceLock<StoreDescription> = OnceLock::new();

/// Record which store this process registered.
///
/// Called once, by the binary, right after `keyring_core::set_default_store`.
/// Later calls are ignored — the default store is set once per process, so a
/// second description would describe a store nothing is using.
pub fn record_active(description: StoreDescription) {
    let _ = ACTIVE.set(description);
}

/// The store this process registered, if [`record_active`] was called.
#[must_use]
pub fn describe_active() -> Option<&'static StoreDescription> {
    ACTIVE.get()
}

/// Whether a profile's credential is present, and how long it will survive.
#[derive(Debug, Clone)]
pub struct EntryProbe {
    /// Presence of the credential.
    pub status: EntryStatus,
    /// Durability of the credential *as actually stored* — which, on the
    /// composite store, can differ from the store-wide answer.
    pub durability: Durability,
    /// Filesystem path holding it, when the backend is file-based.
    pub path: Option<String>,
}

/// Presence of a profile's credential in the active store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    /// A credential exists for this profile.
    Present,
    /// The store is reachable and holds nothing for this profile.
    Missing,
    /// The store could not be consulted; the string is its own message.
    Unavailable(String),
}

/// Ask the active store about one profile's credential.
///
/// This is the question a user actually has when startup fails — "is my key
/// still there?" — and the one behind the volatile-profile warning. It reads
/// the credential to answer it, which is no more exposure than the startup
/// path that is about to read the same bytes.
#[must_use]
pub fn probe(profile: &str) -> EntryProbe {
    let store_durability = keyring_core::get_default_store()
        .map_or(Durability::Unknown, |s| Durability::from(s.persistence()));

    let entry = match Entry::new(service_name(), profile) {
        Ok(entry) => entry,
        Err(e) => {
            return EntryProbe {
                status: EntryStatus::Unavailable(e.to_string()),
                durability: store_durability,
                path: None,
            };
        }
    };

    match entry.get_attributes() {
        Ok(attrs) => {
            // The composite store reports which tier answered; anything else
            // is as durable as the store said it was.
            // The file store names itself; anything else is as durable as the
            // store said it was.
            let durability = match attrs.get(BACKEND_ATTR).map(String::as_str) {
                Some(BACKEND_FILE) => Durability::Durable,
                _ => store_durability,
            };
            EntryProbe {
                status: EntryStatus::Present,
                durability,
                path: attrs.get("path").cloned(),
            }
        }
        Err(keyring_core::Error::NoEntry) => EntryProbe {
            status: EntryStatus::Missing,
            durability: store_durability,
            path: None,
        },
        Err(e) => EntryProbe {
            status: EntryStatus::Unavailable(e.to_string()),
            durability: store_durability,
            path: None,
        },
    }
}

/// Directory the file-backed store keeps secrets in for a given profile's
/// config location: `<config dir>/secrets`.
///
/// Deliberately alongside the config rather than in a separate data directory —
/// the two halves of a profile are already lost together when one is copied
/// without the other, and keeping them adjacent makes that visible.
pub fn secrets_dir(profile: &str) -> Result<std::path::PathBuf, OpenVTCError> {
    Ok(crate::config::public_config::profile_dir(profile)?.join("secrets"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The store policy, pinned as a test because it is a policy and not an
    /// implementation detail: **OpenVTC never chooses a volatile store.**
    ///
    /// If the OS store cannot be opened, the binary fails closed and tells the
    /// operator how to choose file storage deliberately. A store that reports
    /// itself volatile can therefore only have been selected explicitly, and
    /// must always be flagged to the user.
    #[test]
    fn every_default_store_is_durable() {
        // Every store `vta_sdk::keyring_init::install_default_store` registers —
        // Keychain, Credential Manager, Secret Service — reports `UntilDelete`,
        // as does the file store an operator may select.
        assert!(
            !Durability::from(CredentialPersistence::UntilDelete).is_volatile(),
            "a default store must be durable"
        );
        // The kernel keyring is not, which is why it is migration-only.
        assert!(Durability::from(CredentialPersistence::UntilReboot).is_volatile());
    }

    #[test]
    fn volatile_classification_matches_lifetime() {
        assert!(!Durability::Durable.is_volatile());
        assert!(Durability::UntilReboot.is_volatile());
        assert!(Durability::UntilLogout.is_volatile());
        assert!(Durability::UntilExit.is_volatile());
        // Unknown is not treated as volatile: we warn on what we know is
        // volatile, not on everything we cannot classify.
        assert!(!Durability::Unknown.is_volatile());
    }

    #[test]
    fn persistence_maps_to_durability() {
        assert_eq!(
            Durability::from(CredentialPersistence::UntilDelete),
            Durability::Durable
        );
        assert_eq!(
            Durability::from(CredentialPersistence::UntilReboot),
            Durability::UntilReboot
        );
        assert_eq!(
            Durability::from(CredentialPersistence::Unspecified),
            Durability::Unknown
        );
    }
}
