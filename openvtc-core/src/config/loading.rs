//! Configuration loading logic (step 1 and step 2).

use crate::{
    config::{
        Config, ConfigProtectionType, KeyBackend, UnlockCode, protected_config::ProtectedConfig,
        public_config::PublicConfig, secured_config::SecuredConfig,
    },
    errors::OpenVTCError,
};
use affinidi_tdk::{TDK, messaging::profiles::ATMProfile};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek_bip32::ExtendedSigningKey;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::collections::HashMap;
use tracing::{info, warn};
use vta_sdk::credentials::CredentialBundle;

#[cfg(feature = "openpgp-card")]
use super::TokenInteractions;

/// Hierarchical startup-progress callback: invoked as `(major, sub)` when a new
/// sub-step of a major task begins, so the UI can build a two-level loading view
/// with per-step and per-major timing.
pub type ProgressFn<'a> = &'a (dyn Fn(&str, &str) + Send + Sync);

impl Config {
    /// Step 1 of loading the configuration: reads the public config from disk.
    ///
    /// Use this to inspect [`PublicConfig::protection`] and determine what additional
    /// credentials (passphrase, OpenPGP card PIN, etc.) are needed for step 2.
    ///
    /// # Errors
    ///
    /// Returns an error if the public config file cannot be read or deserialized.
    pub fn load_step1(profile: &str) -> Result<PublicConfig, OpenVTCError> {
        PublicConfig::load(profile)
    }

    /// Step 2 of loading the configuration: decrypts secrets, resolves the DID,
    /// regenerates keys, and builds the full [`Config`].
    ///
    /// Requires the [`PublicConfig`] from [`Config::load_step1`] plus any unlock
    /// credentials determined by the protection type.
    ///
    /// On success returns the loaded [`Config`] **and** the still-open admin VTA
    /// session (PERF #1) so the caller can reuse the single mediator connection
    /// for the context-name fetch, relationship/community operations, and joins,
    /// instead of opening a second session. The session is `None` for non-VTA
    /// backends or a no-persona (State-A) account, where none was opened. The
    /// caller is then responsible for shutting it down on every exit path.
    ///
    /// Progress is reported hierarchically via `on_progress(major, sub)`: each
    /// call names the major task and the sub-step now starting, letting the UI
    /// build a two-level loading view with per-step and per-major timing.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails, the BIP32 seed or VTA credential
    /// bundle is invalid, DID resolution fails, key regeneration fails, or
    /// ATM profile creation fails.
    pub async fn load_step2(
        tdk: &mut TDK,
        profile: &str,
        public_config: PublicConfig,
        unlock_passphrase: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] token_user_pin: &SecretString,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
        on_progress: Option<ProgressFn<'_>>,
    ) -> Result<(Self, Option<vta_sdk::client::VtaClient>), OpenVTCError> {
        use tracing::debug;

        fn report_progress(on_progress: &Option<ProgressFn<'_>>, major: &str, sub: &str) {
            if let Some(f) = on_progress {
                f(major, sub);
            }
        }

        report_progress(&on_progress, "Local configuration", "Decrypting secrets");

        let sc = SecuredConfig::load(
            profile,
            #[cfg(feature = "openpgp-card")]
            token_user_pin,
            if let ConfigProtectionType::Token(token) = &public_config.protection {
                Some(token)
            } else {
                None
            },
            unlock_passphrase,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        debug!(
            "Secured Config loaded (key_info entries: {})",
            sc.key_info.len()
        );

        // Determine key backend from secured config
        let key_backend = if let Some(ref bip32_seed) = sc.bip32_seed {
            // Legacy BIP32 config — call .expose_secret() to get the inner &str.
            let bip32_root = ExtendedSigningKey::from_seed(
                BASE64_URL_SAFE_NO_PAD
                    .decode(bip32_seed.expose_secret())?
                    .as_slice(),
            )
            .map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Couldn't get bip32 root from the secret seed material: {}",
                    e
                ))
            })?;
            KeyBackend::Bip32 {
                root: bip32_root,
                seed: bip32_seed.clone(),
            }
        } else if let Some(ref credential_bundle) = sc.credential_bundle {
            // VTA-managed config — expose only at the point of decoding.
            let bundle: CredentialBundle = serde_json::from_str(credential_bundle.expose_secret())
                .map_err(|e| {
                    OpenVTCError::Config(format!("Couldn't decode VTA credential bundle: {e}"))
                })?;
            let encryption_seed =
                ProtectedConfig::get_seed_from_credential(&bundle.private_key_multibase)?;
            KeyBackend::Vta {
                credential_bundle: credential_bundle.clone(),
                credential_did: bundle.did.clone(),
                credential_private_key: SecretString::new(
                    bundle.private_key_multibase.clone().into(),
                ),
                vta_did: sc.vta_did.clone().unwrap_or_default(),
                vta_url: sc.vta_url.clone().unwrap_or_default(),
                mediator_did: sc.mediator_did.clone(),
                encryption_seed,
            }
        } else {
            return Err(OpenVTCError::Config(
                "SecuredConfig has neither bip32_seed nor credential_bundle".to_string(),
            ));
        };

        // Get the encryption seed for ProtectedConfig
        let encryption_seed = match &key_backend {
            KeyBackend::Bip32 { root, .. } => ProtectedConfig::get_seed(root, "m/0'/0'/0'")?,
            KeyBackend::Vta {
                encryption_seed, ..
            } => SecretBox::new(Box::new(encryption_seed.expose_secret().to_vec())),
        };

        // Unencrypt the private config data, with migration from legacy seed
        let (private_cfg, needs_migration) = if let Some(private_cfg_str) = &public_config.private {
            match ProtectedConfig::load(&encryption_seed, private_cfg_str) {
                Ok(cfg) => (cfg, false),
                Err(_) => {
                    // Try legacy seed (pre-0.1.4 used verifying key instead of signing key)
                    if let KeyBackend::Bip32 { root, .. } = &key_backend {
                        let legacy_seed = ProtectedConfig::get_seed_legacy(root, "m/0'/0'/0'")?;
                        match ProtectedConfig::load(&legacy_seed, private_cfg_str) {
                            Ok(cfg) => {
                                warn!(
                                    "Config was encrypted with legacy seed — will be \
                                         re-encrypted with the new seed on next save"
                                );
                                (cfg, true)
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        return Err(OpenVTCError::Decrypt(
                            "Failed to decrypt protected config".to_string(),
                        ));
                    }
                }
            }
        } else {
            (ProtectedConfig::default(), false)
        };

        // If migrating from legacy seed, flag for re-encryption on next save
        if needs_migration {
            info!("Config will be re-encrypted with the updated seed derivation on next save");
        }

        log_private_config_shape(&private_cfg);

        // The v2 `account` persisted in the protected tier is the source of
        // truth. v1 (singleton) configs are reset before reaching here
        // (D13/R-RST), so a loadable config always carries an account.
        let account = private_cfg.account.clone();

        // Resolve runtime identities from the account's personas.
        //
        // A State-A (account-bootstrap, R-A-5) account persists with NO persona:
        // the app loads to a "no active community" state and a persona is minted
        // later in a State-B join. Such an account has no DID to resolve and no
        // persona/relationship messaging profiles to register, so the whole
        // resolve/keygen/profile block is skipped and `identities` stays empty.
        // A State-B account currently carries a single persona, resolved here.
        // The account's VTA mediator (captured at provisioning). Used as the
        // fallback below for any persona stored without one.
        let account_mediator = match &key_backend {
            KeyBackend::Vta { mediator_did, .. } => mediator_did.clone().unwrap_or_default(),
            KeyBackend::Bip32 { .. } => String::new(),
        };
        // Resolve a runtime identity for EVERY persona in the account, not just
        // the first: each persona gets its own DIDComm listener at runtime, so
        // all of them must be hydrated here (keys regenerated + an ATM messaging
        // profile registered). A State-A account has zero personas, so the loop
        // below never runs and `identities` stays empty.
        type PersonaSeed = (
            crate::config::account::PersonaId,
            std::sync::Arc<String>,
            String,
            Option<affinidi_tdk::did_common::Document>,
        );
        let personas: Vec<PersonaSeed> = account
            .personas
            .values()
            .map(|p| {
                // A persona minted before the mediator fix was stored with an
                // empty mediator, which leaves its DIDComm listener failing with
                // "No Mediator is configured" in an endless reconnect loop.
                // Repair it at load by falling back to the account's VTA mediator
                // — the persona DID was minted with the VTA's mediator service,
                // so they match — so an already-broken persona comes good on the
                // next launch with no re-join. (Runtime-only; the record is
                // rewritten on the next save.)
                let mediator = {
                    let stored = p.mediator_did.clone().unwrap_or_default();
                    if stored.is_empty() {
                        if account_mediator.is_empty() {
                            warn!(
                                persona = %p.did,
                                "persona has no mediator and the account has none either — \
                                 the persona listener will not connect"
                            );
                        } else {
                            warn!(
                                persona = %p.did,
                                "persona stored without a mediator — falling back to the \
                                 account VTA mediator"
                            );
                        }
                        account_mediator.clone()
                    } else {
                        stored
                    }
                };
                (
                    p.persona_id,
                    std::sync::Arc::new(p.did.clone()),
                    mediator,
                    // PERF #3: the cached DID document, used instead of a network
                    // resolve when present.
                    p.did_document.clone(),
                )
            })
            .collect();

        // Open the admin VTA session ONLY when there's a persona to rehydrate
        // (regenerate its keys + register messaging profiles). A State-A account
        // has none, so opening one here is useless — and opening it then shutting
        // it down right before `main_loop` opens its own admin session leaves the
        // shut-down session's auto-reconnect briefly dueling the live one on the
        // mediator (WebSocket churn → a dropped response on the first burst of
        // requests, e.g. the join's key creation). Skipping it leaves a single
        // admin session for the whole runtime.
        let vta_client = if matches!(&key_backend, KeyBackend::Vta { .. }) && !personas.is_empty() {
            report_progress(&on_progress, "VTA establishment", "Connecting to VTA");
            Some(super::build_runtime_vta_client(&key_backend).await?)
        } else {
            None
        };

        let mut identities = HashMap::new();

        // Hydrate every persona, then register relationship profiles once. The
        // whole block is wrapped in an inner future so that on ANY `?` error the
        // admin VTA session is shut down before the error propagates (a leaked
        // session trips the SDK `LeakGuard` and duels other sessions on the
        // mediator). On SUCCESS the session is returned to the caller alive
        // (PERF #1) — it is NOT shut down here.
        let hydrate: Result<(), OpenVTCError> = async {
            for (persona_id, persona_did, persona_mediator, cached_document) in &personas {
                // Name the persona's messaging profile after its community so it
                // is identifiable (not a generic "Persona") — matches the runtime
                // listener label (`Config::persona_profile_label`).
                let profile_label = account
                    .communities
                    .values()
                    .find(|c| c.persona_ref == *persona_id)
                    .map(|c| {
                        c.display_name.clone().unwrap_or_else(|| {
                            crate::config::context_path::render_for_display(&c.vtc_did).to_string()
                        })
                    })
                    .unwrap_or_else(|| "Persona".to_string());

                // PERF #3: prefer the persisted persona DID document over a fresh
                // network resolve (~1s). did:webvh docs change rarely between
                // launches; a stale doc only matters if the persona rotated keys
                // out-of-band — rare, and recoverable on the next mint/resolve.
                let document = if let Some(doc) = cached_document.clone() {
                    report_progress(&on_progress, "Identity", "Loading DID document (cached)");
                    doc
                } else {
                    report_progress(&on_progress, "Identity", "Resolving DID document");
                    tdk.did_resolver()
                        .resolve(persona_did)
                        .await
                        .map_err(|e| {
                            OpenVTCError::Resolver(format!(
                                "Couldn't resolve Persona DID ({persona_did}): {e}"
                            ))
                        })?
                        .doc
                };

                // Final mediator resolution. If neither the persona record nor
                // the account carried a mediator, recover it from the DID
                // document itself — the persona DID was minted with a
                // DIDCommMessaging service whose endpoint IS the mediator, so it
                // is always authoritative. Without this the persona listener
                // fails with "No Mediator is configured" and reconnect-loops.
                let persona_mediator = if persona_mediator.is_empty() {
                    match super::did::mediator_from_document(&document) {
                        Some(m) => {
                            warn!(
                                persona = %persona_did,
                                mediator = %m,
                                "recovered persona mediator from its DID document"
                            );
                            m
                        }
                        None => {
                            warn!(
                                persona = %persona_did,
                                "persona has no mediator anywhere (record, account, \
                                 or DID document) — its listener will not connect"
                            );
                            persona_mediator.clone()
                        }
                    }
                } else {
                    persona_mediator.clone()
                };

                report_progress(&on_progress, "Identity", "Fetching persona keys");
                Config::regenerate_persona_keys(
                    tdk,
                    &sc,
                    &key_backend,
                    &document,
                    vta_client.as_ref(),
                )
                .await?;

                report_progress(&on_progress, "Identity", "Building messaging profiles");
                let persona_profile = ATMProfile::new(
                    tdk.atm.as_ref().ok_or_else(|| {
                        OpenVTCError::Config("TDK ATM service not initialized".to_string())
                    })?,
                    Some(profile_label.clone()),
                    persona_did.to_string(),
                    Some(persona_mediator.clone()),
                )
                .await?;

                // Register the persona profile with the TDK ATM Service but do
                // NOT open a WebSocket — the DIDComm service owns connections.
                let atm = tdk.atm.clone().ok_or_else(|| {
                    OpenVTCError::Config("TDK ATM service not initialized".to_string())
                })?;
                let persona_profile = atm.profile_add(&persona_profile, false).await?;

                identities.insert(
                    *persona_id,
                    crate::identity::IdentityContext {
                        persona_id: *persona_id,
                        did: persona_did.to_string(),
                        document,
                        profile: persona_profile,
                        mediator_did: Some(persona_mediator.clone()),
                    },
                );
            }

            // Register relationship (R-DID) profiles ONCE, excluding ALL persona
            // DIDs (each persona's own listener carries the relationships served
            // by its DID). Personas share the account VTA mediator, so any
            // persona's mediator is correct for the R-DID profiles — use the
            // first. Registers each profile with the ATM service as a side-effect;
            // the returned map is no longer stored on `Config`.
            if let Some((_, _, first_mediator, _)) = personas.first() {
                report_progress(&on_progress, "Identity", "Loading relationships");
                let our_p_dids: std::collections::HashSet<String> = personas
                    .iter()
                    .map(|(_, did, _, _)| did.to_string())
                    .collect();
                private_cfg
                    .relationships
                    .generate_profiles(
                        tdk,
                        &our_p_dids,
                        first_mediator,
                        &key_backend,
                        &sc.key_info,
                        vta_client.as_ref(),
                    )
                    .await?;
            }
            Ok(())
        }
        .await;

        // On ERROR, close the admin session before propagating (a leaked session
        // would duel others on the mediator). On SUCCESS, the session is returned
        // to the caller alive (PERF #1) and is NOT shut down here.
        if let Err(e) = hydrate {
            if let Some(client) = &vta_client {
                client.shutdown().await;
            }
            return Err(e);
        }

        Ok((
            Config {
                account,
                identities,
                key_backend,
                public: public_config,
                private: private_cfg,
                key_info: sc.key_info.clone(),
                #[cfg(feature = "openpgp-card")]
                token_admin_pin: None,
                #[cfg(feature = "openpgp-card")]
                token_user_pin: token_user_pin.clone(),
                protection_method: sc.protection_method.clone(),
                unlock_code: unlock_passphrase
                    .map(|uc| SecretBox::new(Box::new(uc.0.expose_secret().to_owned()))),
            },
            // PERF #1: hand the still-open admin session back to the caller for
            // reuse (context-name fetch, relationships, joins). `vta_client` is
            // `Some` only for a VTA backend with an active persona.
            vta_client,
        ))
    }
}

/// Log the *shape* (collection sizes only) of the decrypted private config.
///
/// Deliberately never logs the contents: the protected tier holds contacts
/// (DIDs + aliases), the full relationship graph, tasks, and credential
/// claims, and the tracing sink can be a plaintext file on disk
/// (`OPENVTC_DEBUG_LOG`). Counts are enough for debugging load issues.
fn log_private_config_shape(private_cfg: &ProtectedConfig) {
    tracing::debug!(
        contacts = private_cfg.contacts.contacts.len(),
        relationships = private_cfg.relationships.relationships.len(),
        tasks = private_cfg.tasks.tasks.len(),
        vrcs_issued = private_cfg.vrcs_issued.keys().len(),
        vrcs_received = private_cfg.vrcs_received.keys().len(),
        "private config loaded"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::protected_config::Contact,
        relationships::{Relationship, RelationshipState},
    };
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    /// `MakeWriter` that appends all output to a shared buffer so the test
    /// can inspect exactly what the tracing layer emitted.
    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Regression test for the privacy finding where the entire decrypted
    /// `ProtectedConfig` (contacts, relationships, tasks, credentials) was
    /// pretty-printed to the debug log. The load-path log statement must emit
    /// shape information only — none of the sensitive field values may leak.
    #[test]
    fn private_config_shape_log_does_not_leak_contents() {
        const MARKER: &str = "MARKER_MUST_NOT_LEAK";

        let mut private_cfg = ProtectedConfig::default();

        // Contact whose DID and alias both carry the marker.
        let did = Arc::new(format!("did:web:{MARKER}.example.com"));
        private_cfg.contacts.contacts.insert(
            did.clone(),
            Arc::new(Contact {
                did: did.clone(),
                alias: Some(MARKER.to_string()),
            }),
        );

        // Relationship whose DIDs all carry the marker.
        private_cfg.relationships.relationships.insert(
            did.clone(),
            Arc::new(Mutex::new(Relationship {
                task_id: Arc::new(MARKER.to_string()),
                our_did: did.clone(),
                remote_did: did.clone(),
                remote_p_did: did.clone(),
                created: chrono::Utc::now(),
                state: RelationshipState::Established,
            })),
        );

        let writer = SharedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(writer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_private_config_shape(&private_cfg);
        });

        let output = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("private config loaded"),
            "shape log line was not captured; got: {output}"
        );
        assert!(
            output.contains("contacts=1") && output.contains("relationships=1"),
            "expected collection counts in the log line; got: {output}"
        );
        assert!(
            !output.contains(MARKER),
            "decrypted private-config contents leaked into log output: {output}"
        );
    }
}
