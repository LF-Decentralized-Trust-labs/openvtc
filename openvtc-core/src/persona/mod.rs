//! The holder's own identity — the faces, the facts behind them, and what each
//! face presents where.
//!
//! # Two meanings of "persona", and they compose
//!
//! [`config::account::PersonaRecord`](crate::config::account::PersonaRecord) is
//! a face as an *identity*: a `did:webvh`, its keys, its mediator. That record
//! is local, and the TUI has always been able to mint one.
//!
//! The agent's `persona/*` Trust Tasks use the same word one layer up: a pool
//! of identity attributes, named projections over that pool ([`profile`]), and
//! the assignment of a projection to a persona DID within one trust context
//! ([`binding`]). Those live in the VTA, not in `Config`, and every function
//! here is a round-trip to it.
//!
//! This crate holds the face; the agent holds what the face says. They join on
//! the `(context_id, persona_did)` pair every community membership already
//! carries.
//!
//! # The boundary this module sits astride
//!
//! [`pool`], [`profile`] and [`disclosure`] are **holder-scoped**: they read
//! across every trust context and the VTA gates them on *unrestricted*
//! authority. [`binding`] is **context-scoped**. That asymmetry is the design, not an accident of the
//! API — the holder pushes a materialised projection down into a context, and a
//! context never pulls from the pool. Everything in [`binding`] therefore names
//! a context; nothing in [`pool`] or [`profile`] can.
//!
//! An OpenVTC operator holds the account's admin credential, which is
//! unrestricted, so all three work from the TUI. A caller holding anything
//! narrower will see `e.p.msg.forbidden` from the holder-scoped half, and that
//! is the boundary working rather than a misconfiguration.
//!
//! # Reads are best-effort; writes are not
//!
//! A read failure must never stop OpenVTC starting or a panel drawing — a
//! membership works whether or not we can say what it presents, and
//! [`binding::BindingSummary::unknown`] is the honest thing to draw while we
//! cannot. A *write* is a decision the operator just made about their own
//! identity, so it returns its error and the panel says so.

pub mod binding;
pub mod disclosure;
pub mod pool;
pub mod profile;
