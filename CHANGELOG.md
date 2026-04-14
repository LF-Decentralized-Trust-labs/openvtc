# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-04-15

### Added

- **Full TUI main menu panels** in `openvtc-cli2` — 8 panels: Inbox, Relationships, Credentials, Settings, VTA Service, Logs, Help/Status, Quit
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

- **Replaced manual messaging layer** with `affinidi-messaging-didcomm-service` — deleted messaging/mod.rs (~280 lines) and outbound_queue.rs (~90 lines), added didcomm.rs (~260 lines) with Router, listeners, and send_message_with_retry
- Grouped ~65-variant Action enum into 5 domain sub-enums
- `tokio::sync::watch` replaces mpsc for State updates
- Panel trait with per-panel structs implementing unified render interface
- Dynamic DID display width (`shorten_did(did, max_width)` — 60 chars default, full if fits)
- `Cow<str>` for zero-alloc DID truncation
- Explicit `Arc::clone()`, `#[must_use]` on pure functions, doc comments on State types
- `VecDeque<String>` for O(1) bounded activity log
- `RelationshipRequestBody.name` protocol field for friendly names

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
