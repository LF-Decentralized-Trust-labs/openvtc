//! Library entry point for `did-git-sign`.
//!
//! The binary at `src/main.rs` is a thin wrapper around the modules below.
//! These modules are also reusable from other workspace crates — e.g.
//! `openvtc` calls [`init::install`] from its setup wizard so it can
//! configure git signing for a freshly-provisioned persona without
//! re-running the VTA bootstrap.

pub mod config;
pub mod init;
pub mod policy;
pub mod sign;
pub mod vta;
