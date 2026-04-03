# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
