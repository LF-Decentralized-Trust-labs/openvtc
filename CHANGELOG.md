# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
