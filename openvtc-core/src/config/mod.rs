/*! Contains the OpenVTC CLI Tool Configuration
*
* Configuration is spread across four different contexts:
* 1. [Config]: Represents the active in-memory application config
* 2. [secured_config::SecuredConfig]: Represents [Config] info that is stored securely (key info)
* 3. [public_config::PublicConfig]: Represents [Config] info that is stored in plaintext on disk
* 4. [protected_config::ProtectedConfig]: Represents [Config] info that is encryoted and stored on disk
*
* NOTE: Secure Config information is saved item by item as needed to the secure storage
*/

use crate::{
    config::{
        protected_config::ProtectedConfig,
        secured_config::{KeyInfoConfig, KeySourceMaterial, ProtectionMethod},
    },
    errors::OpenVTCError,
};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek_bip32::ExtendedSigningKey;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

pub mod account;
pub mod context_path;
pub mod did;
pub mod keys;
pub mod loading;
pub mod protected_config;
pub mod public_config;
pub mod saving;
pub mod secured_config;

/// Derives a 32-byte key from a user-provided passphrase using Argon2id.
///
/// Uses Argon2id (RFC 9106) with a domain-specific salt derived from `info`.
/// This provides strong resistance against brute-force and GPU-based attacks
/// on user-chosen passphrases.
///
/// # Parameters
///
/// - `passphrase`: The user-provided passphrase bytes.
/// - `info`: A domain-separation label (e.g., `b"openvtc-unlock-code-v1"`).
///   Different labels produce different keys from the same passphrase.
///
/// # Errors
///
/// Returns an error if Argon2 key derivation fails (e.g., memory allocation).
///
/// # Examples
///
/// ```
/// use openvtc_core::config::derive_passphrase_key;
///
/// let key1 = derive_passphrase_key(b"my-passphrase", b"context-a").unwrap();
/// let key2 = derive_passphrase_key(b"my-passphrase", b"context-b").unwrap();
///
/// // Same passphrase with different context produces different keys
/// assert_ne!(key1, key2);
///
/// // Deterministic for the same inputs
/// let key3 = derive_passphrase_key(b"my-passphrase", b"context-a").unwrap();
/// assert_eq!(key1, key3);
/// ```
pub fn derive_passphrase_key(passphrase: &[u8], info: &[u8]) -> Result<[u8; 32], OpenVTCError> {
    // Legacy v1 KDF: deterministic salt derived from the info label.
    //
    // This is kept for backwards-compatible decryption of v1 ciphertext
    // (data written before the per-entry random salt migration). The
    // deterministic salt means two users with the same passphrase produce
    // the same key, and rainbow-table attacks parallelise across all
    // OpenVTC users — which is the H2 finding from the v0.2.0 review.
    //
    // New ciphertext is always written via `derive_passphrase_key_v2`
    // (random per-entry salt) and the v2 magic-prefix format. The
    // unlock-code path auto-detects the format and reaches for this
    // legacy KDF only when consuming pre-migration data.
    let salt = Sha256::digest(info);
    derive_argon2_key(passphrase, &salt)
}

/// Derive a 32-byte AEAD key from `passphrase` using a per-entry random
/// `salt`. Pair with the v2 ciphertext format so the salt stored
/// alongside the ciphertext is what gets fed back here at decrypt time.
pub fn derive_passphrase_key_v2(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], OpenVTCError> {
    derive_argon2_key(passphrase, salt)
}

/// Async wrapper for [`derive_passphrase_key`] that runs the (CPU-bound,
/// ~0.5–1 s) Argon2id derivation on `tokio::task::spawn_blocking` instead of
/// inline on the async runtime (R12).
///
/// The synchronous [`derive_passphrase_key`] pegs a tokio worker for the full
/// derive; at the user-initiated set/change-passphrase site that worker is the
/// event-loop thread, freezing the UI for ~1 s. This helper owns its inputs (so
/// the closure is `Send + 'static`) and moves the blocking crypto onto the
/// blocking pool, keeping the runtime / render task live. The KDF, salt
/// handling (the legacy v1 deterministic info-salt), and result are identical
/// to the sync path — only *where* the CPU work runs changes.
///
/// `passphrase` is taken by value so the secret bytes are moved into the
/// closure and dropped there; callers should pass an owned copy of the exposed
/// secret rather than logging or widening its exposure.
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] if Argon2 derivation fails, or if the
/// blocking task panics. The `JoinError` carries only the thread/panic
/// location — never the passphrase or the derived key — so the secret cannot
/// leak through the error path.
pub async fn derive_passphrase_key_blocking(
    passphrase: Vec<u8>,
    info: Vec<u8>,
) -> Result<[u8; 32], OpenVTCError> {
    // Wrap the moved passphrase copy in `Zeroizing` so the transient plaintext
    // is wiped when the closure scope ends, preserving the zeroization the
    // borrowed `SecretString`/`SecretBox` would otherwise give.
    let passphrase = zeroize::Zeroizing::new(passphrase);
    tokio::task::spawn_blocking(move || derive_passphrase_key(&passphrase, &info))
        .await
        .map_err(|e| OpenVTCError::Config(format!("Argon2 derivation task panicked: {e}")))?
}

/// Shared Argon2id derivation. OWASP "high-value KEK" profile:
///   m = 128 MiB (GPU-resistant; fits comfortably on 4 GiB devices)
///   t = 4 iterations
///   p = 1 lane (parallelism helps attackers more than users at this cost)
fn derive_argon2_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], OpenVTCError> {
    let mut key = [0u8; 32];
    let params = Params::new(128 * 1024, 4, 1, Some(32))
        .map_err(|e| OpenVTCError::Config(format!("Invalid Argon2 parameters: {e}")))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| OpenVTCError::Config(format!("Argon2 key derivation failed: {e}")))?;
    Ok(key)
}

/// Minimum passphrase length for unlock codes and export passphrases.
pub const MIN_PASSPHRASE_LENGTH: usize = 8;

/// Validates that a passphrase meets minimum strength requirements.
///
/// Returns `Ok(())` if the passphrase is at least [`MIN_PASSPHRASE_LENGTH`] characters.
pub fn validate_passphrase(passphrase: &str) -> Result<(), OpenVTCError> {
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(OpenVTCError::Config(format!(
            "Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters (got {})",
            passphrase.len()
        )));
    }
    Ok(())
}

/// A 32-byte symmetric key derived from a user-provided passphrase via Argon2id.
/// Used to encrypt/decrypt the secured configuration on disk.
pub struct UnlockCode(pub(crate) SecretBox<Vec<u8>>);

impl UnlockCode {
    /// Derives an unlock code from a plaintext passphrase string using Argon2id.
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is shorter than [`MIN_PASSPHRASE_LENGTH`].
    pub fn from_string(s: &str) -> Result<Self, OpenVTCError> {
        validate_passphrase(s)?;
        let key = derive_passphrase_key(s.as_bytes(), b"openvtc-unlock-code-v1")?;
        Ok(UnlockCode(SecretBox::new(Box::new(key.to_vec()))))
    }
}

/// Describes how the configuration secrets are protected at rest.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub enum ConfigProtectionType {
    /// Requires a hardware token with the Token ID to unlock config
    /// Will need to provide the USER PIN to the token
    Token(String),

    /// Requires an unlock passphrase to unlock config
    /// Will need to provide the unlock passphrase
    #[default]
    Encrypted,

    /// Is not encrypted in any way
    Plaintext,
}

#[cfg(feature = "openpgp-card")]
/// Callback trait for hardware token (e.g. YubiKey) user interaction.
///
/// Implementors receive notifications before and after the token may require
/// a physical touch, allowing the UI to prompt the user accordingly.
pub trait TokenInteractions: Send + Sync {
    /// Called before the token may require a physical touch from the user.
    fn touch_notify(&self);

    /// Called after the token operation has completed.
    fn touch_completed(&self);
}

/// The key backend determines how cryptographic keys are stored and managed.
///
/// Either keys are derived locally from a BIP32 seed, or they are managed
/// remotely by a Verifiable Trust Authority (VTA) service.
pub enum KeyBackend {
    /// Legacy BIP32 hierarchical-deterministic key derivation from a local seed.
    Bip32 {
        /// The BIP32 extended signing key root, derived from the seed.
        root: ExtendedSigningKey,
        /// The base64url-encoded seed material (kept in secret memory).
        seed: SecretString,
    },
    /// Keys are managed remotely by a VTA service and fetched on demand.
    Vta {
        /// Encoded VTA credential bundle for authentication.
        credential_bundle: SecretString,
        /// DID associated with the VTA credential.
        credential_did: String,
        /// Private key multibase string for signing VTA challenge-response.
        credential_private_key: SecretString,
        /// DID of the VTA service itself.
        vta_did: String,
        /// Base URL of the VTA service. Empty for DIDComm-only VTAs.
        vta_url: String,
        /// DIDComm mediator DID advertised by the VTA's DID document. Set
        /// during setup when the bootstrap was reached over DIDComm; lets
        /// runtime open new DIDComm sessions instead of falling back to
        /// REST. `None` for REST-only VTAs.
        mediator_did: Option<String>,
        /// SHA-256 hash of the private key multibase, used as the encryption seed
        /// for `ProtectedConfig` (replaces BIP32 `m/0'/0'/0'` in the VTA flow).
        encryption_seed: SecretBox<Vec<u8>>,
    },
}

impl std::fmt::Debug for KeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyBackend::Bip32 { .. } => f.debug_struct("KeyBackend::Bip32").finish_non_exhaustive(),
            KeyBackend::Vta {
                credential_did,
                vta_did,
                vta_url,
                ..
            } => f
                .debug_struct("KeyBackend::Vta")
                .field("credential_did", credential_did)
                .field("vta_did", vta_did)
                .field("vta_url", vta_url)
                .finish_non_exhaustive(),
        }
    }
}

/// Configuration information for openvtc tool
/// This is the active configuration used by the application itself
/// When you want to load/save this configuration, it will become:
/// 1. [public_config::PublicConfig]: Configuration information that is saved to disk
/// 2. [secured_config::SecuredConfig]: Configuration information that is encrypted and saved to secure storage
#[derive(Debug)]
pub struct Config {
    /// Public readable config items when saved to disk
    pub public: public_config::PublicConfig,

    /// Private sensitive config items which are encrypted on disk
    pub private: ProtectedConfig,

    /// Key backend - either local BIP32 or VTA-managed
    pub key_backend: KeyBackend,

    /// Where did the key values come from? Derived or Imported?
    pub key_info: HashMap<String, KeyInfoConfig>,

    // *********************************************
    // Temporary Config values
    /// What protection method is being used for the secured config.
    pub protection_method: ProtectionMethod,

    /// Hardware token Admin PIN
    #[cfg(feature = "openpgp-card")]
    pub token_admin_pin: Option<SecretString>,

    /// Hardware token User PIN
    #[cfg(feature = "openpgp-card")]
    pub token_user_pin: SecretString,

    /// Argon2id-derived 32-byte symmetric key used to encrypt/decrypt `SecuredConfig`.
    ///
    /// Wrapped in `SecretBox` to ensure the key material is zeroed on drop and
    /// never accidentally logged or compared in constant time.  Set when the
    /// user provides an unlock passphrase; `None` for plaintext or token flows.
    pub unlock_code: Option<SecretBox<Vec<u8>>>,

    /// Config v2 multi-community account model (personas + communities).
    ///
    /// The persisted source of truth for the account's personas and community
    /// memberships (stored encrypted in [`ProtectedConfig`]). The persona DID,
    /// mediator DID, and org DID that used to live as `public.*` singletons are
    /// now read from here via [`Config::persona_did`], [`Config::mediator_did`],
    /// and `account.org_did`.
    pub account: account::Account,

    /// Runtime-resolved identities (resolved DID document + ATM profile),
    /// keyed by persona id. Not persisted — rebuilt at load from `account`.
    ///
    /// Holds one entry per persona — load resolves an [`IdentityContext`] for
    /// every persona in the account, and a DIDComm listener is started for each.
    /// [`Config::active_identity`] still surfaces the first as the "active" one
    /// for user-initiated outbound actions; explicit persona *selection* lands in
    /// a later slice.
    ///
    /// A `BTreeMap` (ordered by [`account::PersonaId`]) so that iteration — and
    /// therefore [`Config::active_identity`] — is deterministic across process
    /// runs and insertion orders.
    pub identities: BTreeMap<account::PersonaId, crate::identity::IdentityContext>,

    /// The persona the user's selected working community resolves to (D10) — the
    /// runtime "active identity". Set by the StateHandler loop from
    /// `State.selected_community`; `None` falls back to the first persona so
    /// startup/setup (which run before any selection) behave exactly as before.
    /// Not persisted — a pure runtime selection pointer over `identities`.
    pub active_persona: Option<account::PersonaId>,
}

/// Serializable bundle of public and secured config, used for import/export.
#[derive(Deserialize, Serialize)]
pub struct ExportedConfig {
    /// The public (plaintext) portion of the configuration.
    pub pc: public_config::PublicConfig,
    /// The secured (secret key material) portion of the configuration.
    pub sc: secured_config::SecuredConfig,
}

impl Config {
    /// Returns the 32-byte encryption seed used to encrypt/decrypt `ProtectedConfig`.
    ///
    /// For `Bip32` backends, this derives the seed from path `m/0'/0'/0'`.
    /// For `Vta` backends, this returns the pre-computed SHA-256 hash of the private key.
    pub fn get_encryption_seed(&self) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
        match &self.key_backend {
            KeyBackend::Bip32 { root, .. } => ProtectedConfig::get_seed(root, "m/0'/0'/0'"),
            KeyBackend::Vta {
                encryption_seed, ..
            } => Ok(SecretBox::new(Box::new(
                encryption_seed.expose_secret().to_vec(),
            ))),
        }
    }

    /// The currently-active runtime identity — the persona the selected working
    /// community resolves to (D10 / R-C-6/7).
    ///
    /// Honours [`Config::active_persona`] (set by the loop from the selected
    /// community) so all identity-derived reads — [`Config::persona_did`],
    /// [`Config::mediator_did`], the main-page identity chrome, outbound actions —
    /// scope to the working community without threading a selection through every
    /// call site. Falls back to the first persona (lowest [`account::PersonaId`],
    /// deterministic because `identities` is a `BTreeMap`) when no selection is
    /// set — i.e. during startup/setup, or single-persona accounts — preserving
    /// the prior behaviour.
    pub fn active_identity(&self) -> Option<&crate::identity::IdentityContext> {
        self.active_persona
            .and_then(|id| self.identities.get(&id))
            .or_else(|| self.identities.values().next())
    }

    /// Point the runtime active identity at `persona` (the selected working
    /// community's persona, D10), or clear it back to the first-persona default.
    /// A no-op-safe setter the loop calls each iteration from the selection.
    pub fn set_active_persona(&mut self, persona: Option<account::PersonaId>) {
        self.active_persona = persona;
    }

    /// The active persona's `did:webvh` as a string slice.
    ///
    /// Replaces the removed `public.persona_did` singleton. Returns `""` when no
    /// identity is resolved — which should not occur after a successful load or
    /// setup, where exactly one persona is always active.
    pub fn persona_did(&self) -> &str {
        self.active_identity().map(|i| i.did.as_str()).unwrap_or("")
    }

    /// The active persona's `did:webvh` as an owned `Arc<String>`.
    ///
    /// For the call sites that previously cloned the `Arc<String>` singleton
    /// (e.g. to stash the DID on a message or relationship). The returned `Arc`
    /// is freshly allocated; equality is by value, so sharing is not required.
    pub fn persona_did_arc(&self) -> std::sync::Arc<String> {
        std::sync::Arc::new(self.persona_did().to_string())
    }

    /// The active persona's mediator DID as a string slice (`""` if unset).
    ///
    /// Replaces the removed `public.mediator_did` singleton.
    pub fn mediator_did(&self) -> &str {
        self.active_identity()
            .and_then(|i| i.mediator_did.as_deref())
            .unwrap_or("")
    }

    /// Human label for the active persona's messaging profile: the community it
    /// belongs to (its display name, else the VTC DID slug), so each community's
    /// profile is identifiable rather than a generic "Persona". Falls back to
    /// "Persona" when the persona has no community yet.
    pub fn persona_profile_label(&self) -> String {
        match self.active_identity().map(|i| i.persona_id) {
            Some(pid) => self.persona_profile_label_for(pid),
            None => "Persona".to_string(),
        }
    }

    /// Human label for a *specific* persona's messaging profile (see
    /// [`Config::persona_profile_label`]). Used when building one DIDComm
    /// listener per persona so each is named after its community.
    pub fn persona_profile_label_for(&self, persona_id: account::PersonaId) -> String {
        self.account
            .communities
            .values()
            .find(|c| c.persona_ref == persona_id)
            .map(|c| {
                c.display_name.clone().unwrap_or_else(|| {
                    crate::config::context_path::render_for_display(&c.vtc_did).to_string()
                })
            })
            .unwrap_or_else(|| "Persona".to_string())
    }

    /// Set the active persona's mediator DID, updating both the persisted
    /// `account` record and the runtime `IdentityContext` so subsequent reads
    /// (and the next save) see the new value. No-op if no identity is active.
    pub fn set_active_mediator_did(&mut self, did: &str) {
        let Some(id) = self.active_identity().map(|i| i.persona_id) else {
            return;
        };
        if let Some(persona) = self.account.personas.get_mut(&id) {
            persona.mediator_did = Some(did.to_string());
        }
        if let Some(ctx) = self.identities.get_mut(&id) {
            ctx.mediator_did = Some(did.to_string());
        }
    }

    /// Whether `did` is one of our resolved persona DIDs (vs. a relationship
    /// R-DID or a remote party's DID). Used to route inbound replies out of the
    /// addressed persona and to map a persona DID to its DIDComm listener.
    pub fn is_persona_did(&self, did: &str) -> bool {
        self.identities.values().any(|i| i.did == did)
    }
}

/// Build an authenticated [`vta_sdk::client::VtaClient`] from a `KeyBackend::Vta`,
/// preserving whichever transport (REST or DIDComm) was selected at setup.
///
/// - **DIDComm** — `mediator_did` is `Some`: opens a fresh DIDComm session
///   as the credential DID against the advertised mediator. The session
///   itself is the authenticator; no separate token round-trip happens.
/// - **REST** — `mediator_did` is `None`: runs a challenge-response auth
///   against `vta_url`, then attaches the bearer token to a REST client.
///
/// Returns an error for non-VTA backends (callers should branch on the
/// backend variant before calling).
pub async fn build_runtime_vta_client(
    backend: &KeyBackend,
) -> Result<vta_sdk::client::VtaClient, OpenVTCError> {
    let KeyBackend::Vta {
        vta_url,
        vta_did,
        credential_did,
        credential_private_key,
        mediator_did,
        ..
    } = backend
    else {
        return Err(OpenVTCError::Config(
            "build_runtime_vta_client called on a non-VTA key backend".to_string(),
        ));
    };

    // The transport choice (DIDComm vs REST), the `rest_fallback` derivation,
    // and the empty-URL rule are SDK-level knowledge — `connect_auto`
    // encapsulates them so this no longer hand-rolls the branch (R22). The
    // issued REST token is dropped: runtime clients re-auth per process and
    // never cached it here.
    vta_sdk::client::VtaClient::connect_auto(vta_sdk::client::AutoConnect {
        vta_url,
        vta_did,
        credential_did,
        private_key_multibase: credential_private_key.expose_secret(),
        mediator_did: mediator_did.as_deref(),
    })
    .await
    .map(|connected| connected.client)
    .map_err(map_connect_error)
}

/// Map a `vta_sdk` connect error onto the typed [`OpenVTCError`] taxonomy so
/// callers can keep distinguishing retryable transport/auth failures from
/// genuine config corruption (R18). An empty `vta_url` on the REST path comes
/// back as [`vta_sdk::error::VtaError::Validation`] — that is a bad on-disk
/// config, so it maps to [`OpenVTCError::Config`]; auth rejection maps to
/// [`OpenVTCError::Auth`]; everything else (network, DIDComm session open) is a
/// live-VTA reachability problem, [`OpenVTCError::Vta`].
fn map_connect_error(e: vta_sdk::error::VtaError) -> OpenVTCError {
    use vta_sdk::error::VtaError;
    match e {
        VtaError::Validation(msg) => OpenVTCError::Config(msg),
        VtaError::Auth(msg) => OpenVTCError::Auth(format!("VTA authentication failed: {msg}")),
        other => OpenVTCError::Vta(format!("VTA connection failed: {other}")),
    }
}

/// Run `f` with a runtime VTA client built from `backend`, guaranteeing the
/// (DIDComm) session is shut down whether `f` returns `Ok` **or** `Err`.
///
/// Mirrors [`vta_sdk::client::VtaClient::with_didcomm`] but threads the caller's
/// own error type — any `E: From<OpenVTCError>` (e.g. [`OpenVTCError`] or
/// `anyhow::Error`). `shutdown` is a no-op for the REST transport. Prefer this
/// over [`build_runtime_vta_client`] + a manual `shutdown()`: an early `?` in the
/// body can otherwise drop the session without closing it, leaking a live
/// session (and tripping the SDK's `LeakGuard`).
pub async fn with_runtime_vta_client<F, Fut, T, E>(backend: &KeyBackend, f: F) -> Result<T, E>
where
    F: FnOnce(vta_sdk::client::VtaClient) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: From<OpenVTCError>,
{
    // Hand the body an owned clone (a `VtaClient` shares its session across
    // clones, and `shutdown` is idempotent) — passing by value sidesteps the
    // async-closure-borrowed-argument lifetime limitation.
    let client = build_runtime_vta_client(backend).await?;
    let result = f(client.clone()).await;
    client.shutdown().await;
    result
}

// ****************************************************************************
// Key Types
// ****************************************************************************

/// Classifies how a cryptographic key is used within the OpenVTC system.
#[derive(Clone, Serialize, Default, Deserialize, Debug)]
pub enum KeyTypes {
    /// Ed25519 key used for signing assertions on the persona DID.
    PersonaSigning,
    /// Ed25519 key used for authenticating the persona DID.
    PersonaAuthentication,
    /// X25519 key used for encryption on the persona DID.
    PersonaEncryption,
    /// Other persona-level key not fitting the above categories.
    PersonaOther,
    /// Ed25519 verification key bound to a specific relationship DID.
    RelationshipVerification,
    /// X25519 encryption key bound to a specific relationship DID.
    RelationshipEncryption,
    /// Key used for managing (updating) a `did:webvh` DID log.
    WebVHManagement,
    /// Key purpose has not been determined.
    #[default]
    Unknown,
}

impl Display for KeyTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyTypes::PersonaSigning => "Persona Signing Key",
            KeyTypes::PersonaAuthentication => "Persona Authentication Key",
            KeyTypes::PersonaEncryption => "Persona Encryption Key",
            KeyTypes::PersonaOther => "Persona Other Key",
            KeyTypes::RelationshipVerification => "Relationship Verification Key",
            KeyTypes::RelationshipEncryption => "Relationship Encryption Key",
            KeyTypes::WebVHManagement => "Web VH Management Key",
            KeyTypes::Unknown => "Unknown Key Type",
        };
        write!(f, "{}", s)
    }
}

/// Secrets for the Persona DID.
///
/// Implements [`Drop`] to zeroize contained key material when the struct goes out of scope.
#[derive(Clone)]
pub struct PersonaDIDKeys {
    pub signing: KeyInfo,
    pub authentication: KeyInfo,
    pub decryption: KeyInfo,
}

impl std::fmt::Debug for PersonaDIDKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersonaDIDKeys")
            .field("signing", &"[REDACTED]")
            .field("authentication", &"[REDACTED]")
            .field("decryption", &"[REDACTED]")
            .finish()
    }
}

/// Contains relevant key information required for setting up, configuring and managing keys.
///
/// Implements [`Drop`] to zeroize contained key material when the struct goes out of scope.
#[derive(Clone)]
pub struct KeyInfo {
    /// Secret Key Material that can be used within the TDK environment
    pub secret: Secret,
    /// Where did this key come from? Derived from BIP32 or Imported?
    pub source: KeySourceMaterial,

    /// Section 5.5.2 of RFC 4880 - Expiry time if set is # of days since creation
    pub expiry: Option<TimeDelta>,
    pub created: DateTime<Utc>,
}

impl std::fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyInfo")
            .field("secret", &"[REDACTED]")
            .field("source", &self.source)
            .field("expiry", &self.expiry)
            .field("created", &self.created)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_derive_passphrase_key_deterministic() {
        let key1 = derive_passphrase_key(b"my-passphrase", b"info-label").unwrap();
        let key2 = derive_passphrase_key(b"my-passphrase", b"info-label").unwrap();
        assert_eq!(key1, key2, "Same inputs must produce the same derived key");
    }

    #[test]
    fn test_derive_passphrase_key_different_info_differs() {
        let key_a = derive_passphrase_key(b"same-passphrase", b"info-a").unwrap();
        let key_b = derive_passphrase_key(b"same-passphrase", b"info-b").unwrap();
        assert_ne!(
            key_a, key_b,
            "Different info labels must produce different keys"
        );
    }

    #[test]
    fn test_derive_passphrase_key_different_passphrase_differs() {
        let key_a = derive_passphrase_key(b"passphrase-one", b"same-info").unwrap();
        let key_b = derive_passphrase_key(b"passphrase-two", b"same-info").unwrap();
        assert_ne!(
            key_a, key_b,
            "Different passphrases must produce different keys"
        );
    }

    #[test]
    fn test_unlock_code_from_string_deterministic() {
        let uc1 = UnlockCode::from_string("my-unlock-phrase").unwrap();
        let uc2 = UnlockCode::from_string("my-unlock-phrase").unwrap();
        assert_eq!(
            uc1.0.expose_secret(),
            uc2.0.expose_secret(),
            "Same input string must produce the same unlock code"
        );
    }

    #[test]
    fn test_unlock_code_from_string_different_inputs_differ() {
        let uc1 = UnlockCode::from_string("phrase-alpha-long").unwrap();
        let uc2 = UnlockCode::from_string("phrase-beta-long").unwrap();
        assert_ne!(
            uc1.0.expose_secret(),
            uc2.0.expose_secret(),
            "Different input strings must produce different unlock codes"
        );
    }

    #[test]
    fn test_unlock_code_rejects_short_passphrase() {
        assert!(
            UnlockCode::from_string("short").is_err(),
            "Passphrase shorter than MIN_PASSPHRASE_LENGTH should be rejected"
        );
    }

    #[test]
    fn test_validate_passphrase_minimum_length() {
        assert!(validate_passphrase("12345678").is_ok());
        assert!(validate_passphrase("1234567").is_err());
        assert!(validate_passphrase("").is_err());
    }

    /// Build a minimal [`Config`] carrying the given runtime identities.
    fn test_config(
        identities: BTreeMap<account::PersonaId, crate::identity::IdentityContext>,
    ) -> Config {
        Config {
            public: public_config::PublicConfig::default(),
            private: ProtectedConfig::default(),
            key_backend: KeyBackend::Bip32 {
                root: ExtendedSigningKey::from_seed(&[7u8; 32]).unwrap(),
                seed: SecretString::new("seed".into()),
            },
            key_info: HashMap::new(),
            protection_method: ProtectionMethod::default(),
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: None,
            #[cfg(feature = "openpgp-card")]
            token_user_pin: SecretString::new("".into()),
            unlock_code: None,
            account: account::Account::default(),
            identities,
            active_persona: None,
        }
    }

    /// Build a minimal [`crate::identity::IdentityContext`] for tests — no
    /// network, no ATM service; the profile and DID document are constructed
    /// directly from their (public) fields.
    fn test_identity(
        persona_id: account::PersonaId,
        did: &str,
    ) -> crate::identity::IdentityContext {
        use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
        use std::sync::Arc;

        let document: affinidi_tdk::did_common::Document =
            serde_json::from_value(serde_json::json!({ "id": did }))
                .expect("minimal DID document deserializes");
        crate::identity::IdentityContext {
            persona_id,
            did: did.to_string(),
            document,
            profile: Arc::new(ATMProfile {
                inner: Arc::new(ATMProfileInner {
                    did: did.to_string(),
                    alias: did.to_string(),
                    mediator: Arc::new(None),
                }),
            }),
            mediator_did: None,
        }
    }

    /// A State-A (account-bootstrap, R-A-5) config carries an account but no
    /// persona, so it resolves no runtime identity. The accessors must degrade
    /// to the documented "no active community" sentinels rather than panic.
    #[test]
    fn zero_persona_config_has_no_active_identity() {
        let config = test_config(BTreeMap::new());

        assert!(config.active_identity().is_none());
        assert_eq!(config.persona_did(), "");
        assert_eq!(config.mediator_did(), "");
    }

    /// R7: with multiple personas resolved, `active_identity()` must be
    /// deterministic — the identity with the lowest `PersonaId` wins, and the
    /// result is independent of the order entries were inserted. Interim
    /// behaviour until explicit persona selection lands (T1 Stage 5).
    #[test]
    fn active_identity_is_deterministic_regardless_of_insertion_order() {
        let pid_low = account::PersonaId(uuid::Uuid::from_u128(1));
        let pid_high = account::PersonaId(uuid::Uuid::from_u128(2));
        assert!(pid_low < pid_high);

        // Insert low-id first…
        let mut forward = BTreeMap::new();
        forward.insert(pid_low, test_identity(pid_low, "did:example:low"));
        forward.insert(pid_high, test_identity(pid_high, "did:example:high"));
        let config_forward = test_config(forward);

        // …and high-id first.
        let mut reverse = BTreeMap::new();
        reverse.insert(pid_high, test_identity(pid_high, "did:example:high"));
        reverse.insert(pid_low, test_identity(pid_low, "did:example:low"));
        let config_reverse = test_config(reverse);

        // The lexicographically-first persona id is the active identity…
        let active_forward = config_forward.active_identity().expect("identity resolved");
        assert_eq!(active_forward.persona_id, pid_low);
        assert_eq!(active_forward.did, "did:example:low");

        // …regardless of insertion order.
        let active_reverse = config_reverse.active_identity().expect("identity resolved");
        assert_eq!(active_reverse.persona_id, active_forward.persona_id);
        assert_eq!(active_reverse.did, active_forward.did);
        assert_eq!(config_forward.persona_did(), config_reverse.persona_did());
    }
}
