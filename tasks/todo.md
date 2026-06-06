# Task List — Multi-Community Support

Live checklist. See [`tasks/plan.md`](./plan.md) for rationale, dependency
graph, and checkpoints; [`docs/design/multi-community-support.md`](../docs/design/multi-community-support.md)
for the spec and requirement IDs.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## Phase 0 — Foundation (`openvtc-core`)

### [ ] T1 — Config v2 model + breaking reset + **full consumer refactor** + **community-scoped main page** + **supervised multi-session manager**
- **Crate:** `openvtc-core` **and** `openvtc` (must land together — workspace
  won't build otherwise)
- **Satisfies:** R-RST-1..4 · R-P-1, R-P-2 · D1(#1), D6, D7, D8, D10, D11, D12,
  D13, D14, D15 · §4 model
- **Largest PR in the plan.** Organise as reviewable commits (core model →
  reset detection → active-identity abstraction → main-page scoping →
  supervised session manager → consumer migration).
- **Description:**
  - Add `Account`, `Persona`, `Community` types; `personas: Map<PersonaId,
    Persona>`, `communities: Map<VtcDid, Community>`.
  - `CommunityStatus` enum: `Pending { request_id }`, `Active`, `Left`,
    `Rejected`, `Removed`, `Expired` (D8); `favourite`, `archived`,
    `requested_at`; `member_since` set on Active.
  - **VTA as store (D12):** personas hold VTA `key_refs`, not key material;
    only the account admin credential is a local secret. Tier placement §10.2.
  - **Breaking reset, no migration (D13):** bump `CONFIG_VERSION` to 2; on load,
    detect a v1 config → warn the user it will be deleted → on confirm, delete
    config + keyring entries → run State A (R-RST-1..4). New install skips the
    prompt.
  - **Referential integrity (R-P-1/2):** `community.persona_ref` must resolve;
    block persona deletion while referenced.
  - **Active-identity abstraction (no shim, D10):** explicit persona registry +
    a **selected working community** in runtime `State`. **Refactor every
    consumer** of the singleton (`persona_did`, `key_backend`, single ATM
    profile) to resolve via the abstraction.
  - **Community-scoped main page (R-C-6, D1#1):** `MainPageState`
    (relationships/contacts/VRCs/messaging) operates on the selected working
    community; add a "no active community" state (zero communities).
  - **Supervised multi-session manager (D11, D15):** replace the single ATM
    session / `connection.messaging_active` with a manager running **one
    supervised task per active community session**, each independently
    recoverable (a mediator outage on one must not affect others), bounded max
    concurrency, partial-failure-tolerant launch. Built now at **N=1**; exposes
    register/deregister APIs for Phase 3.
- **Acceptance criteria:**
  - Workspace builds; full CI gate green. No reference to removed singleton
    fields remains (grep clean).
  - A v1 config triggers the warn-and-reset path (gated on confirm); a fresh
    install goes straight to State A with empty collections (R-RST-*).
  - Messaging runs through the supervised manager at N=1 with identical behavior;
    manager unit-tested with ≥2 simulated sessions for isolation + recovery +
    register/deregister.
  - Main page renders the selected community's context and a clean "no active
    community" state.
  - Persona deletion blocked while referenced (R-P-1).
- **Verification:** `cargo test --workspace`; manual: confirm an old config is
  detected and reset; confirm fresh bootstrap.
- **Depends on:** —

### [ ] T2 — `context_path` module (hierarchy convention)
- **Crate:** `openvtc-core`
- **Satisfies:** D2, D9 · spec §6, §10.4
- **Description:**
  - New module (proposed `openvtc-core/src/config/context_path.rs`): build a
    sub-context id `<top>/<slug-from-name>`, parse one back, render for display.
  - Slug rule (§10.4): lowercase; keep `[a-z0-9-]`; collapse other runs to `-`;
    trim; cap 32; collision suffix `-2`, `-3`, …; name-less fallback derives a
    stable token from the VTC DID via `didwebvh-rs` (no hand-rolled parsing).
    Each segment must be a valid context identifier and the full path satisfy
    `validate_context_path` (depth ≤ 8) — **mirror `vti-common::context_path`**
    (reuse if consumable; else replicate its rules to avoid drift).
  - **Hierarchy is VTA-enforced (VTI #257)** — the VTA validates depth/segments
    and ancestry ACL server-side; this module just builds/validates paths. **No
    `vta-sdk` change needed** (`create_context` already takes a path id).
- **Acceptance criteria:**
  - build/parse/render round-trip tests pass; slug + collision + fallback cases
    covered; paths satisfy the `vti-common` rules; no `format!`-style DID
    surgery (uses `didwebvh-rs`).
- **Verification:** `cargo test -p openvtc-core` (context_path unit tests).
- **Depends on:** — (parallelizable with T1)

> **CHECKPOINT 0** before Phase 1 (see plan §3).

---

## Phase 1 — Bootstrap (`openvtc`)

### [ ] T3 — State A: split wizard, account bootstrap (no persona DID)
- **Crate:** `openvtc` (uses `openvtc-core` from T1/T2)
- **Satisfies:** R-A-1, R-A-2, R-A-3, R-A-4, R-A-5, R-A-6 · D5, D7
- **Description:**
  - Refactor `SetupPage` (`setup_sequence/mod.rs:26`) into two entry points:
    bootstrap (State A) and join (State B, stubbed page for now). Join steps
    must not assume an empty config.
  - State A steps: enter VTA DID → resolve + ephemeral `did:key` →
    `vta_admin_rotated` → admin credential → `create_context` top-level context
    (persist `top_context_id`) → protection + did-git-sign → save v2 `account`.
  - **No** `did:webvh`, **no** mediator selection (relocate `MediatorAsk` /
    `MediatorCustom` to T5's mint sub-flow), no community at bootstrap.
  - On completion land on the Communities surface (empty placeholder until T4).
- **Acceptance criteria:**
  - Fresh install (no config) → bootstrap → v2 config with `account` set,
    `personas` and `communities` empty, no DID created (R-A-5).
  - Re-running with existing config does **not** re-bootstrap.
- **Verification:** `cargo test -p openvtc`; manual run of `openvtc setup`
  against a test VTA; inspect persisted config has no persona DID.
- **Depends on:** T1, T2

> **CHECKPOINT 1** before Phase 2.

---

## Phase 2 — Communities display (`openvtc`)

### [ ] T4 — Communities overview page + active-community switcher
- **Crate:** `openvtc`
- **Satisfies:** R-C-1, R-C-2, R-C-3, R-C-4, R-C-5, R-C-6, R-C-7 · R-S-2
- **Description:**
  - New page under `openvtc/src/ui/pages/`; `communities` view model in
    `state.rs`; `Action` variants (`actions/mod.rs:186`) for star / open /
    join-nav / switch-community.
  - Row renders: display name (or VTC DID), status (all §5.6 states, read-only
    styling for inactive), member-since (Active), persona presented.
  - Actions-required badge + count via a single predicate (triggers: Pending,
    unacknowledged Rejected/Removed/Expired, "more info required" — §10.3).
  - Favourite toggle → sorts favourites first → persists (ProtectedConfig).
  - Empty-state: a **playful, welcoming message** nudging the user to go find a
    community to join (not a dry "no items") + the join entry point (R-C-5).
  - **Active-community chrome (R-C-7):** top-of-screen active community name +
    **dropdown switcher**; selecting an Active community sets the working
    context that the (community-scoped, from T1) main page renders.
  - Minimal but **extensible** detail view (status / persona / leave) (R-C-6).
- **Acceptance criteria:**
  - With seeded community fixtures, list renders correct status/member-since/
    persona/badges; favourites sort first and survive reload.
  - Empty state shown when no communities; offers join entry point.
  - Switching the active community via the dropdown updates the main-page
    working context; "no active community" handled.
- **Verification:** `cargo test -p openvtc` (view-model sort/render/badge-count
  + switch tests); manual render with fixtures.
- **Depends on:** T1, T3

> **CHECKPOINT 2** before Phase 3.

---

## Phase 3 — Join & lifecycle (`openvtc`)

### [ ] T5 — State B: join a community (stubbed VP)
- **Crate:** `openvtc`
- **Satisfies:** R-B-1, R-B-2, R-B-3, R-B-4, R-B-5, R-B-6, R-B-9 · D1, D3, D4, D6, D7, D16
- **Description:**
  - Join entry from Communities page (and immediately post-bootstrap).
  - Enter VTC DID → resolve → capture display name from DID doc.
  - Identity choice (D1/D6): reuse an existing persona (list) or mint a new one;
    reuse shows the cross-community linkage warning.
  - Mint sub-flow: WebVH-server select + create `did:webvh`; **optional**
    mediator override defaulting to the VTA mediator (D7).
  - Create sub-context via `context_path` (T2).
  - Submit `join-requests/submit` with a **stub/placeholder VP** isolated in one
    function (D4); persist `Community` with status from the receipt
    (`Pending{request_id}` or `Active`).
  - **Register a live session** for the new community/persona with the
    multi-session manager (D11) so it becomes concurrently active.
  - Duplicate `vtc_did` detected and surfaced; re-join of `Left` allowed (R-B-7).
- **Acceptance criteria:**
  - Join → community persisted and visible on the overview page with the
    receipt's status and the chosen persona.
  - Mint path creates exactly one new persona + sub-context; reuse path creates
    none and references the existing persona.
  - **Joining a second community brings up a concurrent live session without
    disrupting the first** (D11).
  - VP construction confined to one stub function (grep shows a single call site).
- **Verification:** `cargo test -p openvtc`; manual join against a test VTC;
  confirm config + overview reflect it.
- **Depends on:** T1, T2, T3, T4

### [ ] T6 — Lifecycle: pending resolution, timeout, more-info
- **Crate:** `openvtc`
- **Satisfies:** R-B-7, R-B-8, R-S-1, R-S-2, R-S-3 · D16
- **Description:**
  - In the multi-session manager (D11/D15), match an inbound message to its
    community session + `request_id`, transitioning Pending → Active / Rejected
    / Removed / "more info required"; persist; set member-since on Active; raise
    actions-required for Rejected/Removed/more-info until acknowledged (R-S-2).
  - **7-day client-side timeout (R-B-7):** an unanswered Pending → `Expired`
    (actions-required). "More info required" content handling is a stub until D4.
  - Inactivation **deregisters** the session (R-S-3); records retained (R-S-1).
- **Acceptance criteria:**
  - Simulated acceptance flips Pending → Active + member-since; rejection →
    Rejected + badge; a Pending older than 7 days → Expired + badge.
  - Acknowledging Rejected/Removed/Expired clears the badge; session deregistered
    on inactivation.
- **Verification:** `cargo test -p openvtc` (transition + timeout tests with
  simulated inbound + clock injection).
- **Depends on:** T5

### [ ] T7 — Leave + read-only + archive/delete
- **Crate:** `openvtc`
- **Satisfies:** R-L-1 · R-C-8 · R-S-1, R-S-3 · D14
- **Description:**
  - Leave action → `MEMBER_SELF_REMOVE` → on success set `Left`, **deregister
    the session** (D15/R-S-3), retain record read-only.
  - **Read-only enforcement (D14):** inactive communities (Left / Rejected /
    Removed / Expired) cannot send/act; the working-context UI reflects this.
  - **Archive** (set `archived`, hide from default list) and **Delete** (purge
    local data, with confirmation) actions for inactive communities (R-C-8).
    Active communities require leaving before delete. Persona referential
    integrity respected on delete (R-P-1).
- **Acceptance criteria:**
  - Leaving an Active community → Left, session gone, record listed read-only;
    re-join allowed (cycles through Pending).
  - Archive hides from default list (still discoverable); Delete purges after
    confirm; deleting a community doesn't orphan a still-referenced persona.
- **Verification:** `cargo test -p openvtc`; manual leave → archive → delete →
  re-join.
- **Depends on:** T5

### [ ] T8 — did-git-sign: select signing community persona
- **Crate:** `did-git-sign` (+ `openvtc-core` for persona resolution)
- **Satisfies:** R-G-1, R-G-2 · D17
- **Description:**
  - Resolve the signing persona from an **env var** and/or **per-repo git
    config** against the account's personas; drop the single-persona assumption.
  - Fail clearly when no persona is selected/resolvable (no silent fallback).
- **Acceptance criteria:**
  - Signing uses the persona named by env var / git config; with multiple
    personas the correct one signs; unset/unresolvable → clear error.
- **Verification:** `cargo test -p did-git-sign`; manual sign in a repo with
  the git-config / env override set.
- **Depends on:** T1 (persona model) · independent of T3–T7 otherwise.

### [ ] T9 — MockVta integration harness
- **Crate:** test-only — **`MockVta` now exists** (VTI #256, in the `vta-service`
  crate: `MockVta::start()` → `base_url()` → `shutdown()`).
- **Satisfies:** spec §9 testing
- **Description:**
  - Add `vta-service` as a **git dev-dependency** (VTI repo) and write
    integration tests that start a `MockVta`, point the CLI at `base_url()`, and
    exercise bootstrap (State A) → join (State B) → lifecycle.
  - **CI prerequisite:** add the VTI git URL to `deny.toml` `[sources].allow-git`
    (currently `[]` with `unknown-git = "deny"`), or `cargo deny check sources`
    fails.
- **Acceptance criteria:** end-to-end bootstrap→join→resolve runs against a live
  `MockVta` in CI or locally; `cargo deny` passes with the git source allowed.
- **Depends on:** T5 · promoted from nice-to-have now that MockVta exists.

> **CHECKPOINT 3** — feature complete (minus deferred VP). See plan §3.

---

## Deferred (not scheduled here)
- D4 VP construction + VP requirement discovery (spec §8, §10.1).
- *(Resolved — VTI #257)* hierarchical contexts + sub-context authorization are
  now VTA-enforced; `context_path` (T2) mirrors `vti-common::context_path`.
- *New* per-community capabilities beyond porting today's main page; persona
  key rotation (R-P-3).
