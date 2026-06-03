# Design Documents

This folder holds design thinking for OpenVTC — specifications, architecture
decisions, and proposals — kept under version control so the *why* behind
changes is discoverable alongside the code.

## Conventions
- One document per feature/topic, kebab-case filename
  (e.g. `multi-community-support.md`).
- Each doc carries a **Status** line near the top: `DRAFT` → `ACCEPTED` →
  `IMPLEMENTED` (or `SUPERSEDED by …`).
- Specs use stable **requirement IDs** (e.g. `R-B-3`) so task breakdowns and
  PRs can reference them directly.

## Index

| Document | Status | Summary |
|----------|--------|---------|
| [multi-community-support.md](./multi-community-support.md) | DRAFT v4 | Split setup into account bootstrap + per-community join; join multiple VTCs (concurrent live sessions); account-level personas; Communities overview page; VTA-as-store; breaking config reset. |
| [multi-community-presentation.html](./multi-community-presentation.html) | Deck | Visual before/after walkthrough of the multi-community design — Mermaid flows + TUI mockups. Open in a browser; `←`/`→` to navigate. |
