# SPEC — VTA-Authoritative State and Reinstall Recovery

> Status: **DRAFT v2** — for review. Decisions D1–D12 proposed, none settled.
> Scope: the `openvtc` CLI and `openvtc-core` config model. Sealed bootstrap
> turns out to be **already implemented** in `pnm-cli` (see §4), so the only
> external ask is E1, and it is small.
>
> **Changed in v2:** the admin credential is reframed as an authorisation grant
> rather than an identity (§3); recovery becomes a branch in the existing setup
> flow rather than a separate command (§5); "start fresh" no longer means
> "destroy" (D11); and a latent coupling that currently prevents the whole model
> from working is called out (§7, D12).

---

## 1. Objective

Make the VTA the keeper of keys, identities, and credentials, and reduce
OpenVTC's local state to a cache it can rebuild.

> My laptop died. I install OpenVTC on a new machine, point it at my VTA and my
> Trust Context, and it tells me the context already has content and offers to
> recover it. I did not have to have kept a backup file.

### Non-goals

- Multi-device *concurrent* editing with full merge (D8, R2).
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

**E2 (external, VTI, minor):** `MemoryPutBody` is `{contextId, key, value}` with
no precondition, so writes are last-write-wins. A `put/0.2` with an optional
`expectedVersion` — matching the pattern the vault tasks already use — would
close the multi-device gap. Until then D8a bounds the damage.

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

## 9. Migration and work split

No breaking config reset. Steps are independently useful; none is a one-way door.

1. **D12 first** — decouple the ProtectedConfig key. Nothing else works until it
   lands, and it is self-contained.
2. **Ship the writer** — every mutation to personas, memberships or
   relationships also enqueues a `memory_put`. Local stays the read path;
   existing profiles back-fill on first connect.
3. **Ship the probe + branch** (§5, D10/D11) — useful immediately even before
   recovery is complete, because "this context already has content" is
   information a user always wants.
4. **Ship rebuild** (§6) behind the recover branch.
5. **Ship the recipient side of sealed bootstrap** (D3).
6. **Only then** consider demoting the local file from source-of-truth to cache.

**openvtc**: D12 decoupling · account model → agent memory · VRCs/VMCs → credential
vault · setup probe and branch · rebuild · sealed-bootstrap recipient side ·
write-behind queue and conflict surfacing.

**verifiable-trust-infrastructure**: E1 (passkey/device-authenticated
reprovision) · E2 (`memory/put/0.2` with `expectedVersion`) · fix the stale
"not yet implemented" status header on `sealed-bootstrap.md`.

---

## 10. Risks

- **R1 — reprovision is account takeover if unguarded.** D4 keeps a human or a
  second factor in the loop. E1 must not weaken this to "knows the context id".
- **R2 — multi-device divergence.** Mitigated, not solved, by D8a/D8c; E2 helps.
- **R3 — the VTA sees the relationship graph.** Accepted under D2; document it.
- **R4 — a VTA outage becomes a sync outage.** Bounded by D8c.
- **R5 — a mis-typed context id shows someone else's summary.** The D7 summary
  must not leak content the caller is not authorised for; the probe is
  ACL-gated, so an unauthorised context returns nothing rather than a teaser.
- **R6 — `internal: true` keys are unrecoverable by design.** vta-sdk documents
  them as excluded from backup and unrecoverable from the mnemonic. OpenVTC sets
  `internal: None` explicitly today, with a comment saying why. If that changes,
  revisit this whole spec.
- **R7 — D12's migration must not lock anyone out.** The fallback path has to
  survive a profile that is mid-migration when it crashes; the existing
  legacy-seed migration is the template.
