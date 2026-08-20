# SPEC — VTA-Authoritative State and Reinstall Recovery

> Status: **DRAFT v3** — for review. Decisions D1–D16 proposed, none settled.
> Scope: the `openvtc` CLI and `openvtc-core` config model, plus three asks on
> `verifiable-trust-infrastructure` — **E2 is blocking**, E1 and E3 are not.
> Sealed bootstrap turns out to be **already implemented** in `pnm-cli` (§4).
>
> **Changed in v2:** the admin credential is reframed as an authorisation grant
> rather than an identity (§3); recovery becomes a branch in the existing setup
> flow rather than a separate command (§5); "start fresh" no longer means
> "destroy" (D11); and a latent coupling that currently prevents the whole model
> from working is called out (§7, D12).
>
> **Changed in v3:** concurrency (§8). Two instances against one context is not
> a future risk — the messaging layer breaks on it **today**, by mutual
> eviction. E2 is promoted from a minor ask to **blocking**, because
> `MemoryItem` carries no version at all and there is nothing to build a
> precondition on. New decisions D13–D16 and a new external ask E3.

---

## 1. Objective

Make the VTA the keeper of keys, identities, and credentials, and reduce
OpenVTC's local state to a cache it can rebuild.

> My laptop died. I install OpenVTC on a new machine, point it at my VTA and my
> Trust Context, and it tells me the context already has content and offers to
> recover it. I did not have to have kept a backup file.

### Non-goals

- Automatic *merge* of concurrent edits. §9 detects and surfaces conflicts;
  it never resolves them for you (D14, R2).
- Changing the VTA's trust posture — D1 argues this moves no boundary.
- Recovering a lost VTA. That repo has `backup_export`/`backup_import`.

---

## 2. Where authority sits today

From `openvtc-core/src/config/{loading,keys,secured_config,protected_config}.rs`
against `vta-sdk` 0.25.1.

| State | Authoritative today | Target |
|---|---|---|
| Persona **private keys** | **VTA** — `KeySourceMaterial::VtaManaged` → `get_key_secret`, every startup | unchanged |
| Persona DIDs + documents | **VTA** — `list_dids_webvh`, `get_did_webvh_log`; local copy is a perf cache | unchanged |
| VICs (invitations) | **VTA** — credential vault | unchanged |
| Account model — persona list, labels, mediator refs | OpenVTC only | **→ VTA** |
| Community memberships — status, sub-context, VMC, request ids | OpenVTC only | **→ VTA** |
| Relationships (R-DIDs, `did:peer`) | OpenVTC only | **→ VTA** |
| VRCs issued / received | OpenVTC only | **→ VTA credential vault** |
| Contacts, tasks, agent-name cache | OpenVTC only | stays local (D9) |
| Admin credential bundle | OpenVTC keyring only | re-issuable (§3, §4) |

**Half the target is already the reality.** The rows marked *→ VTA* are a
migration, not a new architecture.

---

## 3. D1 — What the admin credential actually is

**The admin credential is an authorisation grant, not an identity.**

It is a `did:key` whose subject holds an ACL entry against a context. The VTA
owns that ACL. The credential can be rotated (`spec/acl/swap-key/0.1` —
self-service rotation onto a new subject DID, proven by a `link_proof` VP-JWT)
and re-issued (§4). Losing it is losing an authorisation, not an identity — the
same shape as losing an SSH key that is listed in `authorized_keys`.

Your *identity* is the persona `did:webvh`s, and those live at the VTA along
with their private keys.

This is the load-bearing reframing. Everything else follows:

- **Recovery is re-authorisation**, not key recovery (§4).
- **The VTA may read the account model** (D2) — it already holds keys that can
  sign as you, so withholding your membership list protects nothing it could not
  obtain by acting as you.
- **Nothing durable may be derived from the admin credential** — because it is
  designed to change. This is currently violated; see §7.

### D2 — The VTA may read this state

Store the account model as documents the VTA can read. Encrypting to a key only
the client holds is the one alternative that changes the trust position, and it
defeats the objective: recovery would then need a secret the user kept.

What this means, to be said plainly in the docs rather than buried:

- The VTA can see your community memberships and relationship graph.
- A VTA operator, or a VTA database leak, exposes that graph.

**D2a** — contacts and the agent-name cache are *not* uploaded. No recovery
value, and the contact list is the most socially sensitive thing OpenVTC holds.

---

## 4. Re-authorisation — already built

**Correction to v1**, which claimed sealed bootstrap was unimplemented. It is
implemented, in `pnm-cli`. The `sealed-bootstrap.md` status header is stale.

The working flow today:

| Step | Who | Command |
|---|---|---|
| 1 | New install | `pnm bootstrap request --out req.json` — generates an ephemeral X25519 keypair, secret stays local at mode 0600; the file carries only a public key, a fresh nonce, and a label |
| 2 | Operator | `pnm context reprovision --id <context> --recipient req.json` — mints an admin key for the **existing** context and seals the credential to that public key |
| 3 | New install | `pnm bootstrap open --bundle <file> --expect-digest <hex>` — single-use; no silent TOFU |

`vta_sdk::sealed_transfer` carries it: HPKE/RFC 9180, DHKEM-X25519 +
HKDF-SHA256 + ChaCha20-Poly1305, ASCII armor with chunk headers bound as AEAD
AAD. `SealedPayloadV1::AdminCredential` already exists.

Crucially, `reprovision` targets an **existing context and leaves its content
alone**. The new admin credential is a new ACL entry against the same context.
That is exactly "just reconnect and away you go".

### D3 — OpenVTC performs the recipient side natively

Rather than making users drive `pnm` for step 1 and 3, OpenVTC does them itself:
generate the ephemeral key, display/export the request, accept the armored
bundle, verify the digest, open it, store the credential. Step 2 stays with
whoever administers the VTA — see D4.

### E1 (external, VTI) — the only remaining ask

Today step 2 requires operator access to `pnm`. For self-service recovery on a
VTA you already administer, a caller who can prove control of a **second
registered factor** should be able to reprovision without a human in the loop.
The VTA already has the primitives: `spec/device/register/0.2` and
`spec/auth/passkey/login/{start,finish}/0.2`.

**Requested:** allow a passkey- or registered-device-authenticated caller to
issue a reprovision for a context they already hold a factor against.

**D4 — until then, an operator step is correct, not a workaround.** Anything
that lets an unauthenticated caller re-issue an admin credential for a context
means anyone who knows your context id can become you. The out-of-band step is
the security boundary. Docs must say so rather than implying recovery is
unconditional.

---

## 5. D5 — Recovery is a branch in setup, not a command

There is no `openvtc recover` command, because there does not need to be. Setup
already asks for the VTA DID and a context id, and already authenticates. The
moment it holds a `VtaClient`, it can see whether that context has content.

**Flow:**

1. Operator supplies VTA DID + context id (unchanged).
2. Authorise — existing provisioning, or §4's sealed bootstrap.
3. **Probe the context** — `list_dids_webvh`, `memory_list`, `cred_vault_query`.
4. If it is empty → continue as today. Nothing changes for a genuine first run.
5. If it has content → present what was found and offer three choices (D11).

**D6 — the probe is read-only and cheap**, three list calls against a context we
have just authenticated to. It runs on every setup, not behind a flag, because a
user who needs it is by definition not expecting it.

**D7 — the summary is concrete.** "This Trust Context already contains 3
personas, 2 community memberships and 14 credentials, last updated 3 days ago" —
not "existing content found". The user is deciding whether this is *their*
account; they need enough to tell.

---

## 6. D8 — Rebuild, storage, and offline

### Rebuild

| Step | Call | Rebuilds |
|---|---|---|
| 1 | `list_contexts()` | `top_context_id` |
| 2 | `get_context(id)` | context DID, sub-contexts |
| 3 | `list_dids_webvh(context)` | persona DIDs |
| 4 | `get_did_webvh(did)` | documents; mediator via existing `did::mediator_from_document` |
| 5 | `list_keys(.., context)` | `key_info` as `VtaManaged { key_id }` |
| 6 | `memory_list(context)` | the account model |
| 7 | `cred_vault_query({})` | VICs, VMCs, VRCs |

Only step 6 needs new work; the rest exist.

### Storage — agent memory, one key per record

Three candidate stores; one fits:

- **Secrets vault** (`vault_upsert_typed`) — a password manager
  (`secret_kind: password|passkey|oauth-tokens`, required site-oriented
  `targets`). **Rejected**: our records are not site credentials, and it would
  pollute a user-facing vault UI.
- **Credential vault** (`cred_vault_*`) — **adopted for VICs/VMCs/VRCs**, where
  VICs already live.
- **Agent memory** (`vta/memory/{put,list,delete}/0.1`) — per-context key/value,
  ACL-gated on context access, isolation enforced server-side. **Adopted for the
  account model.**

**D8a — one key per record, never one blob:**

```
openvtc/v1/account
openvtc/v1/persona/{persona_id}
openvtc/v1/membership/{vtc_hash}/{persona_id}
openvtc/v1/relationship/{r_did_hash}
```

1. **Payload size** — a blob grows without bound, and this project has already
   lost a join to a bridge file-size limit silently dropping an oversized
   submit (PR #137).
2. **Blast radius** — last-write-wins on a blob loses unrelated records.
3. **Partial rebuild** — an unparseable record is skipped and reported through
   the `LoadIntegrity` machinery already merged.

**D8b** — every record carries `schema_version` and `updated_at`.

### E2 (external, VTI) — **blocking**

`MemoryPutBody` is `{contextId, key, value}` with no precondition, and the
`MemoryItem` returned by `list` is `{key, value}` — **no version, no timestamp,
no ETag**. There is nothing to compare against, so two instances writing the
same record silently overwrite each other and neither can detect it afterwards.

Per-record keys (D8a) bound *which* records collide. They do nothing about
whether a collision is noticed, because nothing is carried that could reveal
one.

**Requested:** `spec/vta/memory/put/0.2` taking an optional `expectedVersion`,
and a `version` (and ideally `updatedAt`) on the listed entry — the same
precondition pattern the vault slice already uses (`vault_delete(expected_version)`).

This is not an optimisation. **The account model must not move to agent memory
until it lands**, or the migration replaces a local single-writer store with a
shared one that corrupts silently. Along with D12, this is one of the two
blockers on the whole spec.

### D8c — Cache and write-behind

Local config becomes a full read cache plus a persisted pending-write queue.
Reads never block on the network. Writes apply locally first (preserving today's
coalesced save), then enqueue. Reconcile on connect: push, then pull and
compare. Conflicts are never auto-merged — they surface through the same
acknowledge-and-continue path as `LoadIntegrity`. Pending state is visible;
silent divergence is what makes people distrust sync.

**D8d** — this is not a general-purpose sync engine. It handles the
single-active-device case correctly and reports the multi-device case honestly.

### D9 — What stays local

Contacts, agent-name cache, tasks, activity log, UI preferences, working-community
selection. All pure cache; none has recovery value.

---

## 7. D12 — Break the credential ⇄ local-encryption coupling

**This currently blocks everything above, and it is a code change in this repo.**

`ProtectedConfig::get_seed_from_credential` derives the local config's
encryption key as:

```
HKDF-SHA256(admin_credential_private_key, "openvtc-protected-config-seed-v1")
```

So the admin credential is simultaneously:

- an **authorisation grant**, designed to rotate and be re-issued (D1), and
- a **data-at-rest encryption key**, which must never change.

Those are irreconcilable. Two concrete consequences:

- Rotating the admin key via `acl/swap-key` — which vta-sdk supports and
  performs — makes the existing `public.private` blob **undecryptable**.
- A recovered install necessarily holds a *different* admin key, so it can never
  decrypt a pre-existing local config. Recovery and local state are mutually
  exclusive.

Not a live bug today: OpenVTC uses `AdminRotated` only at provision time, before
any `ProtectedConfig` exists, and never rotates at runtime. It is a latent
blocker that must clear before the rest of this spec is buildable.

**Fix:** give `ProtectedConfig` its own randomly-generated 32-byte key, stored in
`SecuredConfig` beside the credential bundle — the same keyring entry, already
protected by the same passphrase or token. The admin credential then becomes
purely an authorisation grant, freely rotatable and re-issuable.

**Migration:** on load, try the stored key; fall back to the credential-derived
seed; on fallback success, generate a fresh key and re-encrypt on next save.
Exactly the shape of the legacy-seed migration already in `load_step2`.

---

## 8. D10, D11 — The setup branch, and what "fresh" means

**D10 — recover is the default.** The highlighted choice, because a user who
reaches this screen with content in their context is overwhelmingly a returning
user, not someone who typed the wrong context id.

**D11 — "start fresh" means a different context, not a destroyed one.**

The three choices:

| Choice | Effect | Guard |
|---|---|---|
| **Recover** (default) | Rebuild from this context (§6). Local state untouched at the VTA. | Confirmation showing the D7 summary. |
| **Use a different context** | Create/choose another context id and set up normally. The existing context is left completely alone. | None needed — non-destructive. |
| **Delete and start over** | Destroy the context's DIDs, keys and credentials, then set up fresh. | `preview_delete_context` first, showing exactly what dies; then typed confirmation. Never the default, never one keypress. |

The middle option is the important one. "Start fresh" in most tools means
"destroy what is there", and here that would mean irreversibly destroying
persona DIDs and their keys because someone re-ran setup. Making it mean *use a
different context* removes the destructive path from the common flow entirely
and leaves deletion as a deliberate, separate act.

**D11a** — deletion is never implicit in setup, even with a typed confirmation,
if the context contains personas that are members of a community. Leave the
community first, so the VTC learns about it.

---

## 9. Concurrency — two instances, one context

### 9.1 What guards this today

| Case | Guard | Status |
|---|---|---|
| Same machine, same `OPENVTC_CONFIG_PATH`, same profile | `process_lock.rs` — PID lock file, atomic `create_new` | Covered |
| Same machine, **different** `OPENVTC_CONFIG_PATH`, same profile name | none — the lock path is derived from the config dir, so two config dirs get two lock files | Gap |
| Same machine, different profile names sharing one persona DID | none | Gap |
| Two machines, same context | none | Gap |
| Messaging | mediator ceiling of **one websocket per DID** | **Actively harmful** |
| `vta/memory` writes | none — see E2 | Gap |

### 9.2 The messaging layer is already broken

This is not a future risk. From the SDK's own docs: *"The mediator's real ceiling
is **one websocket per DID**."* It does not refuse a second connection — it
**evicts the first**. Two OpenVTC instances presenting the same persona DID
therefore each connect, each evicts the other, and both reconnect-loop
indefinitely.

That is the listener-flapping class already debugged in this project (openvtc
#231, and the upstream `force_refresh` fix in affinidi-tdk-rs). Eviction is the
worst available behaviour: it does not prevent the conflict, it makes both
parties permanently unstable, and it presents as a network fault rather than as
"you have this open twice".

**Anyone who opens OpenVTC twice against one persona hits this now**, with no
part of this spec implemented.

### 9.3 D13 — Detect and say so, before anything else

The cheapest useful step, and it needs no VTA change: `device_register` at
startup, `device_heartbeat` on the timer, `device_list` to see siblings. All
three are in vta-sdk 0.25.1, and `DeviceBinding` already carries `last_seen_at`.

A `DeviceBinding` is *"the device-facing half of an `AclEntry`"* and the caller
always acts on its own binding — so each install naturally has its own identity
at the VTA, without inventing anything.

Surface it plainly: *"This context is also open on 'glenn-laptop', last seen 30
seconds ago."* It blocks nothing. The point is that the user is not surprised,
and that a support conversation starts from the real cause.

### 9.4 D14 — Optimistic concurrency is the correctness mechanism

**Not a lock.** Every write to agent memory carries `expectedVersion` (E2); a
rejected write is a conflict, surfaced through the same acknowledge-and-continue
path as `LoadIntegrity`, naming both sides. Never auto-merged, never silently
retried with a fresh version — that would be a clobber with extra steps.

This is the layer that *prevents corruption*. Everything else in this section
only reduces how often it is exercised.

### 9.5 D15 — An advisory writer lease, if exclusion is wanted

A single memory record, `openvtc/v1/writer-lease`, holding
`{device_id, display_name, expires_at}`, refreshed by the heartbeat already
running under D13. An instance that sees a live lease held by someone else opens
**read-only** and offers "take over".

Three properties, all deliberate:

- **Advisory, not enforced.** The VTA does not police it. A lease that could
  lock you out of your own account when a laptop dies is a worse failure than
  divergence.
- **It expires.** Takeover after expiry needs no human and no support ticket.
- **It is acquired with `expectedVersion`.** Without E2, two instances can both
  believe they won it — a lease with no precondition is theatre.

**D15a — the lease reduces conflict; the precondition prevents corruption.**
Never rely on the lease alone. D14 stands whether or not D15 is built.

### 9.6 D16 — Persona listener ownership

The messaging problem (§9.2) needs an answer regardless of the state layer,
because it bites first.

**Whoever holds the writer lease runs the persona listeners.** Instances without
it do not open persona sockets at all — they read, and they show why messaging
is idle. That converts a mutual-eviction loop into one working instance and one
that says what is going on.

Without D15, the fallback is D13 alone: still connect, but detect the sibling
and warn loudly that both are open and the connection will be unstable. Better
than today, which is silence.

### E3 (external, VTI/mediator) — refuse, don't evict

The mediator's one-socket-per-DID ceiling would be far safer as a refusal than
an eviction. A second connection for a DID that already has a live socket should
be **rejected with a clear reason** the client can render, rather than silently
displacing the incumbent.

Eviction also has a legitimate use — it is how stored-mail redelivery is
triggered (openvtc #218), so this needs a *deliberate* displace flag rather than
having the two behaviours share one door.

**Requested:** a refuse-by-default connect mode, with displacement as an explicit
opt-in for the redelivery path.

## 10. Migration and work split

No breaking config reset. Steps are independently useful; none is a one-way door.

**Two hard blockers gate everything that touches shared state:** D12 (decouple
the local encryption key) and E2 (a precondition on `memory/put`). Neither is
large; both must land first.

1. **D12** — decouple the ProtectedConfig key. Self-contained, and nothing else
   works until it lands.
2. **D13** — register as a device, heartbeat, and report siblings. Needs no VTA
   change, and is worth shipping on its own: it turns today's silent
   reconnect-loop into a stated cause.
3. **Ship the probe + branch** (§5, D10/D11) — useful before recovery is
   complete, because "this context already has content" is information a user
   always wants.
4. **Ship rebuild** (§6) behind the recover branch. Read-only against the VTA,
   so it does not depend on E2.
5. **E2 lands** → ship the writer. Every mutation to personas, memberships or
   relationships enqueues a `memory_put` with `expectedVersion`; existing
   profiles back-fill on first connect.
6. **Ship the recipient side of sealed bootstrap** (D3).
7. **Optionally D15/D16** — the advisory lease and listener ownership, once
   there is real multi-device usage to justify them.
8. **Only then** consider demoting the local file from source-of-truth to cache.

### Work split

**openvtc**: D12 decoupling · device registration + heartbeat + sibling
reporting (D13) · setup probe and three-way branch (D5–D7, D10, D11) · rebuild
(§6) · account model → agent memory with `expectedVersion` (D14) · VRCs/VMCs →
credential vault · sealed-bootstrap recipient side (D3) · write-behind queue and
conflict surfacing (D8c) · optionally the writer lease and listener ownership
(D15, D16).

**verifiable-trust-infrastructure**:

| Ask | What | Priority |
|---|---|---|
| **E2** | `vta/memory/put/0.2` with `expectedVersion`, and a version on the listed entry | **Blocking** |
| E3 | Mediator: refuse a second socket for a DID rather than evicting the incumbent, with displacement as an explicit opt-in for stored-mail redelivery | High — fixes a live bug |
| E1 | Passkey- or device-authenticated reprovision, for self-service recovery | When convenient |
| — | Fix the stale *"Design — not yet implemented"* header on `sealed-bootstrap.md` | Trivial |

## 11. Risks

- **R1 — reprovision is account takeover if unguarded.** D4 keeps a human or a
  second factor in the loop. E1 must not weaken this to "knows the context id".
- **R2 — multi-device divergence.** Draft 2 called this "mitigated by
  per-record keys", which was too generous. Per-record keys bound *which*
  records collide; they do nothing about whether a collision is noticed,
  because `MemoryItem` carries nothing that could reveal one. Until E2 lands
  there is no detection at all, which is why the account model must not move
  to agent memory before it. After E2, D14 makes a collision a surfaced
  conflict rather than a silent clobber — and D15/D16 reduce how often it
  happens, without ever being the thing that prevents corruption.
- **R3 — the VTA sees the relationship graph.** Accepted under D2; document it.
- **R4 — a VTA outage becomes a sync outage.** Bounded by D8c.
- **R5 — a mis-typed context id shows someone else's summary.** The D7 summary
  must not leak content the caller is not authorised for; the probe is
  ACL-gated, so an unauthorised context returns nothing rather than a teaser.
- **R6 — `internal: true` keys are unrecoverable by design.** vta-sdk documents
  them as excluded from backup and unrecoverable from the mnemonic. OpenVTC sets
  `internal: None` explicitly today, with a comment saying why. If that changes,
  revisit this whole spec.
- **R8 — an advisory lease that is trusted like a real one.** If D15 ships and
  anyone treats it as exclusion rather than advice, a crashed holder locks a
  user out of their own account until expiry. The lease must never be the only
  thing standing between two writers and a corrupt record — that is D14's job
  (D15a).
- **R9 — E3 could break stored-mail redelivery.** Displacing a socket is
  currently how a stored inbox gets redelivered (openvtc #218). A blanket
  refuse-don't-evict change would silently regress that, which is why E3 asks
  for displacement as an explicit opt-in rather than removing it.
- **R7 — D12's migration must not lock anyone out.** The fallback path has to
  survive a profile that is mid-migration when it crashes; the existing
  legacy-seed migration is the template.
