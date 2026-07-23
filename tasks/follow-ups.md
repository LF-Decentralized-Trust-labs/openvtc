# Open Follow-ups

Carried forward from the completed trackers (multi-community T1–T9, remediation
R0–R27) when those were archived on 2026-07-20. Everything numbered in those
plans shipped; what remains are small, unscheduled items that lived in the
prose notes rather than as checkboxes.

Companion: [`d4-scoping.md`](./d4-scoping.md) — the one item large enough to
have its own scoping doc.

Status legend: `[ ]` open · `[~]` in progress · `[x]` done

---

## Scoped work

### [ ] D4 — Verifiable Presentation construction + VP requirement discovery
Join step 4 still submits a stub VP (`openvtc/src/state_handler/join_flow.rs`,
single call site). Closes the last deferred item from the multi-community spec
(`docs/design/multi-community-support.md` §8, §10 Q1).
**See [`d4-scoping.md`](./d4-scoping.md) for the full scoping** — not scheduled.

### [ ] Persona key rotation (R-P-3)
Deferred from the multi-community plan; never scoped. No config-model or UI
support for rotating a persona's keys today.

---

## Small / unscheduled

### [x] Agent names — claim / park / resume for a persona
DONE. `openvtc/src/state_handler/agent_name_manage.rs` wraps the six VTA verbs
(`set`/`remove`/`enable`/`disable`/`list`/`check`, published `vta-sdk` 0.19.17)
over `VtaClient::dispatch_trust_task`; the VTA panel's DID list gains `g` to open
a per-persona manager overlay (list served + parked names, claim with an
availability pre-check, park/resume/remove). A successful mutation reconciles the
persisted name cache (first served name → the persona's displayed name) so the
header/panels update without waiting for the background sweep.
The destructive `remove` is gated behind a local `y`/Enter confirm (#169).

### [ ] Agent names — remaining input surfaces
Consumer **display** is done. On top of relationships, communities, the header,
VTA/settings persona lines and every log message (`resolve_did_to_display`), the
last three panels now use the same view-model + `display_identifier` approach:
VRC remote/issuer/subject (`credentials_panel.rs`, via
`VrcSummary::{remote,issuer,subject}_agent_name`), inbox message DIDs
(`inbox_panel.rs`, via `TaskSummary::remote_agent_name` and the per-variant
`*_agent_name` on `ActiveTaskView`), and the persona/context DID lists
(`ActiveDid::agent_name` / `ManagedDid::agent_name` in `vta_panel.rs`).
Deliberately left on the raw DID: the requester's R-DID on an inbound
relationship request (a per-relationship pseudonym), and the mediator / VTA /
credential DIDs — `Config::agent_name_refresh_targets` never resolves those, so
a name for them could not appear without also extending the refresh sweep.

Input support covers the join VTC-DID entry and the new relationship request;
the setup-time entries (VTA DID, webvh import, custom mediator, org DID) still
take a DID only — apply the same `looks_like_agent_name` + `resolve_identifier`
pattern, threading a resolver into those setup handlers.

### [x] Agent names — resolve → verify e2e
DONE (#168). `openvtc-core/tests/agent_name_e2e.rs` drives the whole chain
through a real `DIDCacheClient`: a wiremock host serves `/@name` → 302 → DID, the
document is seeded to run the `alsoKnownAs` check, and the happy path + spoof
(different-DID) + unclaimed + nameless + DID-passthrough cases are covered.
**Remaining gap:** the DID→document hop is seeded (immutable `did:key`), so a
live `did:webvh` resolve against a real agent-name-serving host is still only
provable by running OpenVTC end to end.

### [ ] Outbound size guard on join submit
A bridge file-size limit silently dropped a join submit once (root cause behind
PR #137). A guard that fails loudly on an oversized outbound payload was
deferred at the time, not abandoned.

### [ ] Auto-archive a VIC on `forbidden`
A VIC that the VTC rejects as forbidden should be archived automatically rather
than lingering in the vault as a selectable invitation.

### [ ] MockVta vault e2e coverage
The MockVta harness covers bootstrap → persona mint → mediator join/lifecycle,
but not the VIC vault manager path.

### [ ] Shared persona-mint helper
`mint_persona_into` exists twice in `openvtc/src/state_handler/setup_sequence/config.rs`
(:64 and :231). The join flow also makes key calls the standalone mint path
already covers. Worth one shared helper.

### [ ] Mirror `needs_reestablishment` badge into the relationship *detail* view
The badge renders in `relationships_panel.rs:109`. **Unverified** whether that
is the list row only or the detail pane too — check before doing work.

---

## Deliberately declined (documented, not lost)

### R23 — send-on-change state broadcast
Not a bug. The dirty-tracking needed to avoid re-broadcasting unchanged state
risks a stale UI in exchange for a micro-optimization. The safe half (Arc heavy
data, defer credential JSON to view time) already landed. **Revisit only if
`State` grows enough that per-tick cloning shows up in a profile.**

---

## Moved out of this repo

### `did-git-sign::authenticate` leaks DIDComm sessions
Returns the client without calling `shutdown()`. Pre-existing. The vendored
crate was dropped from this workspace in `0d6317b` (now consumed as a published
dep), so **this belongs to the `did-git-sign` repo**, not here.

---

## Closed while archiving (verified in code, 2026-07-20)

- **`rollback_minted_persona` friendly_name restore** — fixed. It now takes
  `prior_friendly_name` and restores it (`join_flow.rs:1087`).
- **Per-community capabilities beyond the main page** — shipped as the
  Capabilities panel in #157 (`29758a3`).
