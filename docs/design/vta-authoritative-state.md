# SPEC — VTA-Authoritative State and Reinstall Recovery

> Status: **DRAFT v1** — for review. Decisions D1–D9 proposed, none settled.
> Scope: the `openvtc` CLI and `openvtc-core` config model, **plus** two
> required changes in `verifiable-trust-infrastructure` called out as
> **external dependencies** (E1, E2). Per the repo CLAUDE.md, protocol-layer
> work belongs in that repo; this doc specifies the contract between them.

---

## 1. Objective

Make the VTA the keeper of keys, identities, and credentials, and reduce
OpenVTC's local state to a cache it can rebuild.

The target user story, in full:

> My laptop died. I install OpenVTC on a new machine, enrol it against my VTA's
> Trust Context, and everything comes back — my personas, my communities, my
> relationships, my credentials. I did not have to have kept a backup file.

Today none of that survives. A profile is two halves — a config file and an OS
credential-store secret — and losing either loses the account. The encrypted
export (`Settings → Export Config`) is the only defence, and it requires the
user to have thought of it in advance.

### Non-goals

- Multi-device *concurrent* editing with full conflict resolution. §6 defines a
  deliberately narrow write-behind model; genuine multi-writer merge is out of
  scope and called out as a risk (R2).
- Changing the VTA's trust posture. §3 argues this moves no trust boundary,
  because the boundary was already crossed.
- Recovering a VTA that is itself lost. VTA-side durability is that repo's
  concern (it has `backup_export`/`backup_import` already).

---

## 2. Where authority sits today

Established by reading `openvtc-core/src/config/{loading,keys,secured_config}.rs`
and `vta-sdk` 0.25.1.

| State | Authoritative today | Target |
|---|---|---|
| Persona **private keys** | **VTA** — `KeySourceMaterial::VtaManaged` → `get_key_secret`, fetched on *every* startup | unchanged |
| Persona DIDs + documents | **VTA** — `list_dids_webvh`, `get_did_webvh_log`; local copy is already a perf cache (PERF #3) | unchanged |
| VICs (invitations) | **VTA** — credential vault, `cred_vault_{receive,query,get}` | unchanged |
| Account model — persona list, labels, mediator refs | OpenVTC `ProtectedConfig` only | **→ VTA** |
| Community memberships — status, sub-context, VMC, request ids | OpenVTC only | **→ VTA** |
| Relationships (R-DIDs, `did:peer`) | OpenVTC only | **→ VTA** |
| VRCs issued / received | OpenVTC only | **→ VTA credential vault** |
| Contacts, tasks, agent-name cache | OpenVTC only | stays local (pure cache, D8) |
| **Admin credential bundle** | **OpenVTC keyring only** | **→ enrolment (§4)** |

**Half the target is already the reality.** Persona keys — the most sensitive
material in the system — are escrowed at the VTA and re-fetched on every launch.
The rows marked *→ VTA* are a migration, not a new architecture.

---

## 3. D1 — The VTA may read this state

**Decision: store the account model as structured documents the VTA can read.**

The argument is short: the VTA already holds every persona's private signing,
authentication, and encryption key. A party that can sign as you can do anything
you can do. Withholding your *membership list* from that party protects nothing
it could not already obtain by acting as you.

Encrypting to a key only the client holds is the one alternative that would
change the trust position — and it defeats the objective, because recovery would
then require a secret the user kept, which is the situation we are trying to
escape. That is the circularity in §4, reappearing.

What this does mean, and must be stated in the UI:

- The VTA can see your community memberships and your relationship graph.
- A VTA operator, or a VTA database leak, exposes that graph.
- This is a property of using a hosted agent, and it should be said plainly in
  the docs rather than discovered.

**D1a**: contacts and the agent-name cache are *not* uploaded (§D8). They are
local-only conveniences with no recovery value, and the contact list is the most
socially sensitive thing OpenVTC holds.

---

## 4. The bootstrap problem, and the one answer

Moving state to the VTA does not, by itself, deliver reinstall recovery.

The admin `CredentialBundle` cannot be recovered *from* the VTA, because it is
what authenticates you *to* the VTA. This is circular, not a gap — no amount of
server-side storage resolves it. `provision_integration` requires an existing
admin token, so re-provisioning is not self-service either.

A fresh install therefore needs an **enrolment** step that does not depend on
the lost secret.

### E1 (external, VTI) — sealed-bootstrap Mode A

`verifiable-trust-infrastructure/sealed-bootstrap.md` already specifies exactly
this, currently marked *"Design — not yet implemented"*. Its **Mode A** is
verbatim our case:

> **A. Online, non-TEE** — Operator adds a new client to an existing VTA.
> Trust anchor: operator-issued one-time token (ephemeral, role+context-bound
> ACL entry).

The primitive is already shipped: `vta_sdk::sealed_transfer` (HPKE / RFC 9180,
DHKEM-X25519 + HKDF-SHA256 + ChaCha20-Poly1305, ASCII-armored with chunk headers
bound as AEAD AAD, single-use and replay-resistant). `SealedPayloadV1` already
has an `AdminCredential(CredentialBundle)` variant.

**What E1 needs to deliver:** the server-side issue-and-redeem path for a
one-time enrolment token, and a `bootstrap` ACL role that cannot escalate.

**D2 — OpenVTC's side of enrolment.** `openvtc enrol --token <one-time-token>`:

1. Generate an ephemeral X25519 keypair; the private half never leaves the
   process.
2. Send `BootstrapRequest` with the public half + the token.
3. Receive the armored `SealedBundle`, verify the producer assertion, open it.
4. Persist the `CredentialBundle` to the secure store (§Durability — this is the
   store work already merged: Secret Service → encrypted file).
5. Run §5's rebuild.

**D3 — the token is out-of-band and that is correct.** The user must obtain the
enrolment token from somewhere the lost laptop was not: the VTA's admin UI,
another enrolled device, or an operator. There is no way around this that does
not amount to "anyone who knows your DID can become you". The docs must say so
rather than implying recovery is unconditional.

---

## 5. D4 — Rebuild from a Trust Context

After enrolment (or on `openvtc rebuild` with an existing credential), OpenVTC
reconstructs local state from the VTA. All calls exist in vta-sdk 0.25.1:

| Step | Call | Rebuilds |
|---|---|---|
| 1 | `list_contexts()` | `account.top_context_id` |
| 2 | `get_context(id)` | context DID, sub-contexts |
| 3 | `list_dids_webvh(context)` | persona DIDs |
| 4 | `get_did_webvh(did)` / resolve | `did_document`, and the mediator via the existing `did::mediator_from_document` |
| 5 | `list_keys(.., context)` | `key_info` as `VtaManaged { key_id }` |
| 6 | `memory_list(context)` | the account model — §6 |
| 7 | `cred_vault_query({})` | VICs, VMCs, VRCs |

Steps 1–5 and 7 need **no new VTA work**. Only step 6 does.

**D5 — rebuild is explicit and non-destructive.** It never runs implicitly at
startup. A rebuild into a profile that already has local state presents a diff
and requires confirmation. Silently overwriting local state from the server is
how a stale VTA view destroys good local data.

---

## 6. D6 — Storage: `vta/memory`, one key per record

The VTA has three candidate stores. Only one fits:

- **Secrets vault** (`vault_upsert_typed`) — shaped as a password manager:
  `secret_kind: password | passkey | oauth-tokens | …`, required site-oriented
  `targets`. Our documents are not site credentials; using it would pollute a
  user-facing vault UI. **Rejected.**
- **Credential vault** (`cred_vault_*`) — correct for VCs, and already used for
  VICs. **Adopted for VICs/VMCs/VRCs only.**
- **Agent memory** (`vta/memory/{put,list,delete}/0.1`) — a per-context
  key/value store, ACL-gated on context access, with per-context isolation
  enforced server-side. **Adopted for the account model.**

`memory_put(context_id, key, value: String)` takes a string value, so records
are JSON documents.

**D6a — one memory key per record, never one blob.** Keys:

```
openvtc/v1/account          → { vta_did, vta_url, top_context_id, org_did }
openvtc/v1/persona/{persona_id}
openvtc/v1/membership/{vtc_did_hash}/{persona_id}
openvtc/v1/relationship/{r_did_hash}
```

Three reasons, in order of importance:

1. **Payload size.** A single blob grows without bound, and this project has
   already lost a join to a bridge file-size limit silently dropping an
   oversized submit (PR #137). Per-record keys keep every write small.
2. **Blast radius.** Last-write-wins on one blob loses unrelated records; on one
   record it loses that record.
3. **Partial rebuild.** A record that fails to parse is skipped and reported via
   the existing `LoadIntegrity` machinery, rather than failing the whole
   rebuild.

**D6b — every record carries `schema_version` and `updated_at`.** Forward
compatibility, and the input to conflict resolution.

### E2 (external, VTI) — optimistic concurrency on memory/put

`MemoryPutBody` is `{ contextId, key, value }` with no `expectedVersion`, so
writes are last-write-wins. With two enrolled devices that silently loses edits.

**Requested:** `spec/vta/memory/put/0.2` with an optional `expectedVersion`, and
a version on the listed entry, matching the precondition pattern the vault
tasks already use (`vault_delete(expected_version)`).

Until E2 lands, D6a's per-record keys bound the damage and §6.1 detects it.

### 6.1 D7 — Cache and write-behind

The local config becomes a **full read cache** plus a **pending-write queue**.

- **Reads** never block on the network. Startup uses local state exactly as it
  does today; the VTA is consulted in the background.
- **Writes** apply locally first (preserving today's coalesced save, R11), then
  enqueue a VTA write. The queue is persisted, so a crash does not lose it.
- **Reconcile on connect**: push pending writes, then pull and compare.
- **Conflicts** — a remote record whose `updated_at` is newer than our last sync
  *and* differs from ours — are **never auto-merged**. They surface through the
  same acknowledge-and-continue path as `LoadIntegrity`, naming both sides.
- **Pending state is visible.** A profile with unpushed writes says so. Silent
  divergence is the failure mode that makes people distrust sync.

**D7a — the queue is not a general-purpose sync engine.** It handles the
single-active-device case correctly and reports the multi-device case honestly.
That is the whole commitment.

---

## 7. D8 — What stays local

- **Contacts** — socially sensitive, no recovery value, D1a.
- **Agent-name cache** — re-resolved on launch by design; negatives are already
  pruned at load.
- **Tasks**, activity log, UI preferences, working-community selection.
- **The `SecuredConfig` blob** — the credential bundle stays in the OS store.
  The store work already merged (Secret Service → encrypted file → kernel
  keyring) remains the first line of defence; enrolment is the second.

---

## 8. D9 — Migration

No breaking config reset. The account model gains a mirror, it does not move.

1. **Ship the writer.** Every mutation that touches personas, memberships, or
   relationships also enqueues a `memory_put`. Local remains the read path.
   Existing profiles back-fill on first connect.
2. **Ship the reader** behind `openvtc rebuild`, explicit only (D5).
3. **Ship enrolment** once E1 lands.
4. **Only then** consider demoting the local file from source-of-truth to cache.
   Steps 1–3 are useful on their own and none of them is a one-way door.

---

## 9. Work split

**verifiable-trust-infrastructure** (protocol layer — correct target per CLAUDE.md):

- **E1** — sealed-bootstrap Mode A: one-time enrolment token issue + redeem, and
  the non-escalating `bootstrap` ACL role.
- **E2** — `vta/memory/put/0.2` with `expectedVersion`.
- *Nice to have*: pagination on `memory/list`, and a documented value-size limit
  so clients can chunk deliberately rather than discovering the limit as a
  dropped write.

**openvtc**:

- Mirror the account model to `vta/memory` (D6, D9 step 1).
- Move VRCs and VMCs into the credential vault, alongside VICs.
- `openvtc rebuild` (D4/D5).
- `openvtc enrol --token` (D2), once E1 lands.
- Write-behind queue + reconcile + conflict surfacing (D7), reusing the
  `LoadIntegrity` acknowledge path already merged.

---

## 10. Risks

- **R1 — the enrolment token is a full account takeover if leaked.** It must be
  single-use, short-lived, context-bound, and non-escalating. This is E1's whole
  security burden and it deserves its own review.
- **R2 — multi-device divergence.** Mitigated, not solved, by D6a + D7. E2
  reduces it further. A real merge model is a separate piece of work.
- **R3 — the VTA now sees the relationship graph.** Accepted under D1; must be
  documented, not buried.
- **R4 — a VTA outage becomes a sync outage.** Bounded by D7: reads and writes
  both work offline; only propagation waits.
- **R5 — rebuild from a stale VTA view.** Bounded by D5: explicit, diffed,
  confirmed.
- **R6 — `internal: true` keys are unrecoverable by design.** vta-sdk documents
  them as *"excluded from backup and cannot be recovered from the mnemonic or
  otherwise"*. If OpenVTC ever mints such a key, that persona is outside this
  entire scheme. Today it does not — and it should not start without revisiting
  this doc.
