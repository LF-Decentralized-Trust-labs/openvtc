# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-05-05

### Added

- **Full TUI main menu panels** in `openvtc` — 8 panels: Inbox, Relationships, Credentials, Settings, VTA Service, Logs, Help/Status, Quit
- **Inbox panel** with real-time task processing: auto-handles trust-pongs, relationship finalization, and rejections; queues interactive tasks; detail views for all task types (inbound/outbound requests, VRCs, pings, informational)
- **Relationships panel** with list/detail/new-request views, inline alias editing ('e' key), R-DID privacy toggle, trust-ping with RTT latency
- **Credentials panel** with Received/Issued tabs, raw VRC JSON in detail view, clipboard copy ('c' key), VRC request and removal
- **Settings panel** with inline editing, config export/import, passphrase protection management, hardware token detection and factory reset
- **VTA Service panel** showing VTA URL, DID, credential DID, key count, and backend type
- **Logs panel** with scrollable timestamped activity log, selected entry copy ('c'), copy all ('a')
- **Activity log panel** at bottom of screen showing real-time timestamped events (`[HH:MM:SS] message`)
- **Status/Help panel** with DID clipboard copy hotkeys ([1] persona, [2] mediator), visual feedback on copy
- **R-DID generation** for both BIP32 and VTA backends — VTA path authenticates and creates keys via API; both sender and receiver can use R-DIDs
- **Dynamic R-DID listeners** — automatically added when creating R-DIDs (sender or receiver), enabling message delivery to relationship-specific DIDs
- **VRC issuance** from inbox with DataIntegrityProof signing; **VRC rejection** with message back to requester
- **Friendly name in relationship requests** — sender's name included in request body, auto-set as contact alias on accept, R-DID recommendation shown when sender uses one
- **DIDComm service integration** (`affinidi-messaging-didcomm-service` 0.2) — replaces manual messaging with Router-based dispatch, automatic reconnection, message pickup, and multi-DID listener support
- **Periodic keepalive ping** (60s) with live RTT latency in connection status header
- **Inbox task count badge** on menu item ("Inbox (3)" in red when tasks pending)
- **Bracketed paste** for all 21 text input fields — paste is instant regardless of string length
- **Up/Down arrow navigation** in all multi-field forms alongside Tab
- **Config versioning** with stepwise migration framework
- **Panel trait** for content panels — unified render interface
- **Outbound message retry** via `DIDCommService::send_message_with_retry`
- **Auto-reconnect mediator** on DID change in settings
- 15 unit tests covering core functions
- **Contact management** actions (add/remove)

### Security

- Trust-pings only responded to from mediator DID or established relationships — prevents presence leakage
- Passphrases removed from cloned State — length-only fields in UI, consumed via `mem::take`
- Token admin PIN wrapped in `Arc<SecretString>` for shared allocation
- Inbound message body size validation (1MB limit), task ID deduplication, sender verification
- Collection bounds (10K tasks, 5K relationships), untrusted display text sanitization
- Unlock rate limiting (5 attempts, exponential backoff), path redaction, file path validation
- Key material explicit drop with documented zeroization limitation
- Structured audit log entries for security-relevant operations

### Fixed

- **R-DID message routing** — acceptance, finalize, VRC, and ping messages now use relationship DID instead of persona DID when R-DID exists
- **Config persistence** — all mutating actions save to disk
- **Setup → main transition** — `sync_from_config()` now called after setup wizard completes
- **VRC "From:" blank** — extract remote DID from relationship for VRC tasks
- **Alias on accept** — sender's name set as contact alias, existing alias-less contacts updated
- **Backspace to empty** in relationship form fields
- **Tab after backspace fix** — dedicated `FocusField` action for field switching
- **DIDComm listener secrets** — pass DID secrets to listeners for mediator authentication
- All `.unwrap()`/`.expect()` replaced with proper error propagation
- Clipboard graceful degradation, `sanitize_display` ANSI stripping order

### Changed

- **Workspace consolidation** — renamed the active CLI package and binary `openvtc-cli2` → `openvtc`, and renamed the supporting library `openvtc-lib` → `openvtc-core`. The unsuffixed name now belongs to the user-facing binary, matching the convention used by uv, ruff, deno, and cargo. The library is `publish = false`, so no external consumers are affected.
- **`vta-sdk` 0.5** consumed from crates.io — dropped the temporary `../verifiable-trust-infrastructure/vta-sdk` path pin so the workspace no longer requires a sibling checkout to build.
- **Replaced manual messaging layer** with `affinidi-messaging-didcomm-service` — deleted messaging/mod.rs (~280 lines) and outbound_queue.rs (~90 lines), added didcomm.rs (~260 lines) with Router, listeners, and send_message_with_retry
- Grouped ~65-variant Action enum into 5 domain sub-enums
- `tokio::sync::watch` replaces mpsc for State updates
- Panel trait with per-panel structs implementing unified render interface
- Dynamic DID display width (`shorten_did(did, max_width)` — 60 chars default, full if fits)
- `Cow<str>` for zero-alloc DID truncation
- Explicit `Arc::clone()`, `#[must_use]` on pure functions, doc comments on State types
- `VecDeque<String>` for O(1) bounded activity log
- `RelationshipRequestBody.name` protocol field for friendly names

### Removed

- **Legacy `openvtc-cli` crate** — the original prompt-driven CLI was phased out in favour of the TUI. All ongoing work lives in `openvtc`.
- **Dead `VtaAuthenticate` setup page** — online provisioning emits `VtaAuthCompleted` directly from `VtaProvisioning`, so the legacy authenticate screen was unreachable.

### Post-release deep-review pass

After cutting the v0.2.0 branch a multi-axis review (code quality, security, tests, docs) flagged a set of findings that landed on the same release branch before merge. They're listed separately so the diff between v0.1.x and v0.2.0 stays readable.

#### Security

- **Per-entry random Argon2 salt with transparent v1→v2 migration.** `derive_passphrase_key` previously used a deterministic salt = SHA-256(info), so two operators with the same passphrase produced the same KEK and exported backups were byte-comparable. The new `passphrase_encrypt_v2` / `passphrase_decrypt` API in `openvtc-core::config::secured_config` writes a magic-prefixed `[OPV2 | salt(16) | nonce(12) | ct+tag]` blob with a fresh random salt; the decrypt path auto-detects v1/v2 so existing exports keep opening. Argon2id parameters bumped to OWASP "high-value KEK" floor (m=128 MiB, t=4, p=1).
- **`did-git-sign` signing policy.** The proxy now refuses to sign unless the parent process name starts with `git` or `ssh-keygen`, and writes every signing attempt — accepted or denied — to `~/.config/did-git-sign/audit.log` (mode 0600) with parent PID/name, namespace, buffer path and SHA-256. Blocks the "malicious build script obtains a signature with namespace=git over attacker-chosen content" pivot.
- **DIDComm replay window + seen-message LRU** in `process_inbound_message`: drop messages with `created_time` outside ±48h / +5m skew, drop messages whose `expires_time` already passed, dedupe on a 1024-entry process-lifetime ID LRU.
- **DID validation** uses a real W3C DID Core 1.0 syntax parser instead of a `did:` prefix check; rejects bidi-override / zero-width chars in DID fields.
- **Inbox display-name sanitisation** strips bidi-override / isolate / zero-width / BOM unicode (Cf class) plus ANSI escapes / control chars, and clamps inbound contact aliases to 64 chars before persistence.
- **Bounded DIDComm event channel** (256-entry capacity) so a noisy mediator can't grow memory without limit; overflow logs and drops, mediator pickup redelivers when we drain.
- **`did.jsonl` write path** is now the resolved profile dir, not the current working directory.
- **Dependabot:** transitive openssl/rustls-webpki/rand bumped via `cargo update` to clear nine open advisories. `pgp` was already at the patched 0.19.
- **Tagged-variant downgrade defence on `SecuredConfigFormat`.** Switched the on-disk variant tag from `#[serde(untagged)]` to `#[serde(tag = "format")]` so every blob carries an explicit `"format"` discriminator. Without it, an attacker with write access to the OS keychain could substitute a `PasswordEncrypted` blob with `{"text": "<plaintext>"}` and serde would silently match it as `PlainText`, bypassing AES-256-GCM. New `assert_format_matches_intent` cross-validation gate adds a second defence layer — a tagged-but-weaker blob is rejected before any decrypt or re-save. Old (untagged) blobs migrate transparently on first load. Folded from @ojasshelke's PR #34; the PR's HKDF v2 fixed-salt variant is superseded by our random-per-entry-salt v2 (`OPV2` magic prefix) above.

#### Community contributions

Three community PRs against `main` were assessed and folded into the release. Each PR's substantive value is preserved with `Co-authored-by:` trailers; the corresponding PRs are closed with a comment pointing here.

- **#57 — profile-name validation hardening (@sameerchore).** `validate_profile_name` now trims leading/trailing whitespace before validating, and the empty/whitespace check runs before the character check (so `"   "` gets a clear "cannot be empty or contain only whitespace" error instead of the confusing "Invalid profile name '   '"). Three new integration tests pin the behaviour.
- **#51 — cross-platform config paths (@krsatyamthakur-droid, closes #47).** `profile_dir` and `get_lock_file` now use `dirs::config_dir()` on Windows (typically `%APPDATA%\openvtc`); Unix/macOS continues to use `~/.config/openvtc/` so existing installs don't move. `get_config_path` and `get_lock_file` return `PathBuf` instead of `String` end-to-end.
- **#34 — `SecuredConfig` serde-format hardening (@ojasshelke).** Tagged-variant downgrade defence + intent-gate cross-validation, described under Security above. The PR's HKDF v2 fixed-salt scheme was superseded by our random-salt OPV2 v2 and intentionally not folded.

#### Architecture & code quality

- **State-handler split.** `state_handler/mod.rs` was 2,255 lines with a 500-line `tokio::select!` arm; it's now 813 lines (-64%). Each per-domain match (Inbox, Relationship, Credential, Settings, Contact) was extracted to a `dispatch(action, ctx).await` entry point in the corresponding sub-module.
- **Layering:** moved `colors.rs` and the `dialoguer` passphrase prompt out of `openvtc-core` so the daemon (`openvtc-service`) and automation (`robotic-maintainers`) crates no longer pull in `ratatui` + `dialoguer` transitively.
- **Lifted four DID-truncation helpers** into a single `openvtc-core::display` module (`truncate_did`, `truncate_did_centered`).
- **Tightened `openvtc-core` public surface** — dropped a dead `pub use` re-export and scoped two helpers to `pub(crate)`.
- **Fixed silent failures** in the state handler: surfaced previously-swallowed `save_config` / `remove_listener` / inbox-task errors via `log_error`. Replaced four `.expect("valid route")` panics in DIDComm router init with `?`. Replaced `panic!("Cannot create log file …")` with stderr + continue.
- **Fixed DIDComm-only VTA fallback** in `relationships.rs` (used `build_runtime_vta_client` instead of REST-only `challenge_response`).

#### Tests & CI

- **In-process mediator harness** (`openvtc-core/tests/common/mod.rs`): wraps the upstream `affinidi-messaging-test-mediator` 0.2 fixture via `TestMediator::with_users(["alice", "bob"])`, which boots a real `affinidi-messaging-mediator` on an ephemeral loopback port (memory-backed store, generated `did:peer` identity advertising `dm`/`#auth`/`#ws`, Ed25519 JWT signing keypair) and returns Alice + Bob as ALLOW_ALL accounts whose DIDComm service URI is the mediator's DID — the routing/2.0 shape required for forwards to short-circuit to local delivery instead of being enqueued for external forwarding. The previous in-tree harness predated the test-mediator crate; the migration drops ~400 lines of fixture code and four dev-deps (`affinidi-messaging-mediator`, `-mediator-common`, `-sdk`, `sha256`).
- **End-to-end integration tests** (`relationship_e2e.rs`): drive a real Alice→Mediator→Bob DIDComm round-trip, a production `RelationshipRequestBody` round-trip, and a two-leg VRC request/reject round-trip — all in ~350ms once the mediator is up. Plus a smoke test (`mediator_smoke.rs`) that asserts the well-known endpoint serves a DID Document. Marked `#[ignore]` (each spawns the mediator, ~1s); CI's coverage job runs them with `--include-ignored`.
- **38 new unit tests** across `setup_flow/navigation` (25 table-driven), BIP32 derivation (7 known-answer vectors), AES-GCM tampering (6) — locking the wizard flow, derivation contract, and AEAD failure modes before the v0.3.0 work begins.
- **CI** adds a `cargo-deny` job (advisories + licenses + bans + sources, with documented `RUSTSEC-2023-0071` rsa Marvin-Attack and `RUSTSEC-2024-0370` proc-macro-error ignores) and a `cargo-llvm-cov` coverage job (uploads `lcov.info` artifact, runs ignored tests). MSRV check bumped 1.91 → 1.94 to match `Cargo.toml`.

#### Dependency refresh

Picks up the May 2026 Affinidi-stack releases. All bumps cleared on crates.io; build, full test suite, and integration tests pass.

- **`affinidi-tdk` 0.6 → 0.7** — accessor-method API on `TDKSharedState`/`TDKEnvironment`/`TDKProfile`. Field accesses (`.secrets_resolver`, `.environment`, `.profiles`, `.default_mediator`, `.ssl_certificate_paths`) are now method calls. `TDKSharedState::default().await` (removed in tdk 0.6) replaced with `TDKSharedState::new(TDKConfig::headless()?).await?` in `openvtc-service`.
- **`affinidi-messaging-didcomm-service` 0.2 → 0.3** — version bump driven by the upstream `MediatorACLSet` error-type relocation; downstream impact is `?`-transparent thanks to `From<ACLError> for ATMError`.
- **`affinidi-messaging-test-mediator` 0.1 → 0.2** (dev-deps only) — `TestMediator::with_users(["alice", "bob"])` replaces our hand-rolled `MemoryStore` + ALLOW_ALL registration dance. Drops `affinidi-messaging-mediator`, `-mediator-common`, `-sdk` and `sha256` from dev-deps.
- Working with the upstream maintainers, this branch's review of the May 2026 test-mediator changes also surfaced two follow-ups landing post-publication: an IPv6 routing-classification fix and `mediator-common` feature-gating to keep the SDK light. Neither is on the path used by openvtc tests (loopback over `127.0.0.1`).

#### Docs

- README, CONTRIBUTING, SECURITY, CLAUDE.md aligned to the post-rename workspace shape (`openvtc` binary + `openvtc-core` lib).
- CHANGELOG `[0.2.0]` entry above describes the release as it actually shipped.

## [0.1.5] - 2026-04-14

### Security

- Upgraded `pgp` 0.18 &rarr; 0.19, resolving 3 Dependabot alerts: parser crash on crafted RSA secret key packets (CVE-2026-21895), crash from deeply nested messages, and integrity protection not always checked on encrypted data

### Added

- Hardware token touch prompt overlay in `openvtc-cli2` — a centered popup now appears when a YubiKey (or other OpenPGP card) requires physical touch confirmation, and auto-dismisses when the touch completes
- Progress feedback during VTA credential validation in `openvtc-cli2` setup wizard
- Unit tests for `MessageType` and `KeyPurpose` in `openvtc-lib`
- GitHub Discussions guidance in `CONTRIBUTING.md`

### Changed

- Upgraded `secrecy` 0.8 &rarr; 0.10 (`SecretVec<u8>` replaced with `SecretBox<Vec<u8>>`, `SecretString::new()` API updated)
- Upgraded `openpgp-card` 0.5 &rarr; 0.6 and `openpgp-card-rpgp` 0.6 &rarr; 0.7
- Migrated pgp 0.19 API changes: `EncryptionKey`/`DecryptionKey` traits, `SubpacketData::IssuerKeyId`, `Timestamp` types

### Removed

- Stale `openvtc-cli2/did.jsonl` test artifact

## [0.1.4] - 2026-04-12

### Breaking Changes

- **Removed legacy SHA-256+HKDF encryption** — existing configs must be recreated with `openvtc setup`
- **`UnlockCode::from_string()` now returns `Result`** and enforces minimum 8-character passphrase
- **`derive_passphrase_key()` now returns `Result`** — callers must handle the error

### Security

- Replaced `rand::thread_rng()` with `OsRng` in all cryptographic key generation paths (BIP39 entropy, PGP export, DID key generation)
- Hardened Argon2id parameters: 64 MiB memory / 3 iterations (up from default 19 MiB / 2 iterations) per OWASP recommendations
- Added `#![deny(unsafe_code)]` to `openvtc-lib` — no unsafe code in production paths
- Added DID format validation for `OPENVTC_MEDIATOR_DID` and `OPENVTC_ORG_DID` environment variable overrides
- Replaced all production `unwrap()` calls with proper error handling in setup wizard, clipboard operations, and service initialization
- Replaced ~15 silent `let _ =` error discards with `debug!`/`warn!` logging in state handler, service, and robotic-maintainers

### Added

- Argon2id as sole KDF (removed legacy fallback)
- Profile name validation (alphanumeric, hyphens, underscores only)
- Rate limiting to `openvtc-service` (50 msg/sec with throttle logging)
- Graceful shutdown signal handling (SIGINT/SIGTERM) in `openvtc-service`
- Criterion benchmarks for `derive_passphrase_key` and `unlock_code_encrypt`/`unlock_code_decrypt`
- Integration tests for profile validation, relationships, VRCs, tasks, and logs (38 new tests)
- `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1)
- Windows to CI test matrix
- MSRV verification (Rust 1.91.0) in CI pipeline
- API documentation for public modules (relationships, VRCs, tasks, logs, config)

### Fixed

- All Clippy warnings (migrated deprecated Protocols API, collapsible-if, items-after-test-module)
- Corrected valid-until prompt handling for VRC issuance in `openvtc-cli` (PR #23)

### New: `did-git-sign` crate

A standalone CLI tool for signing git commits using DID Ed25519 keys managed by a VTA. Acts as a git SSH signing proxy — no private key material ever touches disk.

- Git SSH signing proxy via `gpg.ssh.program` integration
- VTA authentication with token caching in OS keyring
- Credential private key stored in OS keyring (macOS Keychain / Linux Secret Service)
- Ed25519 signing key fetched from VTA at sign-time and zeroized after use
- SSH signature output in PROTOCOL.sshsig format
- `init` command — configures git and sets up allowed_signers for verification
- `status` command — displays current signing configuration and keyring state
- `verify` command — end-to-end test of keyring, VTA auth, key fetch, and signing
- Config validation: rejects non-HTTPS VTA URLs, empty credentials, non-Ed25519 keys
- Retry logic for VTA authentication (up to 2 attempts on transient failures)

### Dependency Updates

- `didwebvh-rs` 0.1 &rarr; 0.4
- `affinidi-tdk` 0.5 &rarr; 0.6 (`affinidi-messaging-didcomm` 0.12 &rarr; 0.13)
- `affinidi-data-integrity` 0.4 &rarr; 0.5
- `dtg-credentials` switched from local path to crates.io (`0.1`)
- `vta-sdk` updated to 0.3 (`health.version` is now `Option<String>`, `VtaClient::set_token` no longer requires `&mut self`, `CreateDidWebvhRequest` has new optional fields)
- All transitive dependencies updated to latest compatible versions via `cargo update`

### didwebvh-rs 0.4 Migration

- Replaced manual `DIDWebVHState::default()` + `create_log_entry()` pattern with the new `create_did(CreateDIDConfig)` API in both `openvtc-lib` and `openvtc-cli`
- `create_initial_webvh_did()` is now async (required by `create_did`)
- Added `LogEntryMethods` trait import for `get_did_document()` access

### Breaking API Changes (from dependency updates)

- `DataIntegrityProof::sign_jcs_data()` is now async — added `.await` in `openvtc-cli`, `robotic-maintainers`, and `dtg-credentials`
- `DTGCredential::sign()` is now async
- `CreateDidWebvhRequest.server_id` changed from `String` to `Option<String>`
- `CreateDidWebvhRequest` now requires `url: Option<String>` field and new optional fields (`did_document`, `did_log`, `signing_key_id`, `ka_key_id`, `set_primary`)
- `CreateDidWebvhResultBody.mnemonic` changed to `Option<String>`
- `Message::pack_encrypted()` removed — replaced with `ATM::pack_encrypted(&msg, to, from, sign_by)`
- `Message.type_` field renamed to `Message.typ`
- `didcomm::error::Error` replaced by `didcomm::DIDCommError`
- `PackEncryptedOptions` removed — encryption options are now implicit in the pack function choice
- `UnpackMetadata` moved from `didcomm` to `messaging::messages::compat`
- `VtaClient::set_token()` no longer requires `&mut self`
- `HealthResponse.version` changed from `String` to `Option<String>`

### Security Improvements

- Custom `Debug` implementations for `PersonaDIDKeys` and `KeyInfo` that redact secret material
- Replaced debug logging of full `SecuredConfig` struct with safe summary
- Fixed `unwrap()` in SSH signature encoding path with `expect()` and context
- VTA URL validation — rejects plain HTTP (except localhost for development)
- Ed25519 key type validation when fetching signing keys from VTA
- Empty access token rejection after VTA authentication

### Code Quality

- Extracted 11 hardcoded protocol URLs to `protocol_urls` constants module in `openvtc-lib`
- Added `mediator_did()` and `org_did()` helper functions with environment variable overrides (`OPENVTC_MEDIATOR_DID`, `OPENVTC_ORG_DID`)
- Updated `MessageType` `From`/`TryFrom` impls and VRC message builders to use protocol URL constants
- Removed unused `console` and `crossterm` dependencies from `openvtc-lib`

### Tests

- **openvtc-lib**: Added 14 new tests (2 &rarr; 16 total)
  - Encrypt/decrypt roundtrip, wrong key rejection, empty data, large data, different key ciphertext divergence, corrupted data detection, zeroize verification
  - Protected config save/load roundtrip, wrong seed rejection, serialization, contacts find/remove, credential seed determinism and divergence
- **did-git-sign**: Added 6 new tests (5 &rarr; 11 total)
  - Config validation (empty URL, HTTP rejection, HTTPS acceptance, localhost exception, empty key ID rejection, seed material zeroization)

### Documentation

- Added `did-git-sign/README.md` with setup instructions, architecture diagram, security model, and config format reference
- Added workspace crates table and DID Git Signing section to root `README.md`

## [0.1.3] - 2026-04-03

### Security

- Fixed deterministic encryption vulnerability in `unlock_code_encrypt`/`unlock_code_decrypt` (`openvtc-lib`). The previous implementation used a seeded PRNG to derive both the AES-256-GCM key and nonce from the unlock code, producing identical ciphertext for the same password and plaintext. The fix uses HKDF-SHA256 for key derivation with a random nonce (via `OsRng`), ensuring each encryption produces unique output. Existing configs encrypted with the old format are transparently decrypted via a legacy fallback and re-encrypted with the secure format on the next save.

## [0.1.2] - 2026-04-03

### Added

- CLI interface for `openvtc-service` with `--config`/`-c` flag to specify an alternate configuration file path (default: `conf/config.json`).
- `--help` and `--version` flags for `openvtc-service`.
- Comprehensive operator documentation for `openvtc-service`: configuration schema, logging (`RUST_LOG`), runtime behavior, and protocol context.

### Removed

- Unused `chrono` and `rand` dependencies from `openvtc-service`.

## [0.1.1] - 2026-04-03

### Fixed

- Aligned documented minimum Rust version with workspace `rust-version` (1.91.0) in root README, `openvtc-lib`, and `openvtc-service` READMEs.
- Removed duplicate introductory paragraph and repeated bullet in Decentralised Identity section.
- Fixed typo "Remove" to "Remote" in Private Configuration section.
- Changed incorrect `html` code fence to `text` for a URL example under Host Your DID Document.
- Updated README badges to link to current repository (`OpenVTC/openvtc`).
