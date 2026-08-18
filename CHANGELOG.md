# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **An explicit `[Ctrl+V]` "paste an invitation" action on the join entry
  page.** Bracketed paste worked the whole time, but nothing on screen said so —
  which is why the issue behind it was filed as "I cannot find anywhere to
  import a VIC". The key is named in every invitation state, and the terminal's
  own paste still works and remains the path that survives SSH, where reading
  the OS clipboard cannot. (vti-setup#29)

### Removed

- **Thirteen setup-wizard pages that had become unreachable.** R-A-5 moved
  persona minting out of setup and into the State-B join flow, which drives it
  from `JoinProgress` rather than through wizard pages. The pages it left behind
  — mediator choice, display name, webvh address and webvh-server selection, DID
  key display and PGP export, and did-git-sign install — had no inbound
  navigation from any reachable page, and had sat that way long enough to start
  reading as live code. Tracing from `StartAsk` confirmed the whole subgraph was
  orphaned: `MediatorAsk` and `WebvhServerSelect` had no callers at all, and
  everything else hung off one of those two.

  Gone with them: `Action::SetDIDKeys` (never sent by anything),
  `VtaCreateKeys`, `ExportDIDKeys`, `DidGitSignInstall`, `WebvhServerCreateDid`,
  `SetCustomMediator`, `SetUsername`, `CreateWebVHDID`, `ResetWebVHDID`,
  `ResolveWebVHDID`; sixteen `SetupEvent` variants; `SetupState.did_git_sign`,
  `.did_keys_export`, `.webvh_server` and `vta.use_webvh_server` /
  `.webvh_servers`; and the webvh-server probe provisioning ran to fill a list
  nothing read. `SetupState` keeps the fields the deleted pages *wrote* —
  `did_keys`, `webvh_address`, `custom_mediator`, `username` — because the join
  flow and the standalone persona mint now fill the same struct themselves
  before calling `Config::mint_persona_into`. Roughly 3,800 lines. (vti-setup#31)

  Note for anyone who wanted the git-signing setup: installing did-git-sign was
  only ever offered by one of these pages, so it has been unreachable since
  R-A-5 regardless. The main page still *detects* an existing did-git-sign
  config; re-offering the install needs a new entry point.

### Fixed

- **The VTA Service panel stops feeling frozen.** Tab into the Invitation
  Credentials list ran a credential-vault query *before* the focus change, and
  the state handler services actions one at a time — so a two-line in-memory
  focus move waited on a network round-trip with a 30-second timeout, and
  nothing on screen explained the pause. The listing now runs off the loop:
  focus moves immediately, the panel says a query is in flight, and "No
  invitation credentials" is only claimed once the vault has actually answered.
  A refresh asked for while one is running is deferred rather than dropped, so a
  just-archived credential is never left rendered as active.
- **`g` opens the agent-name manager whichever list is focused.** It was bound
  only to the Context Identities list, so pressing it after a Tab produced
  nothing at all — no action, no message — which is indistinguishable from a
  dead keyboard and had people restarting the app. Two more silent no-ops
  behind the same report are fixed with it: a persona selection left pointing
  past the end of a rebuilt list disabled every key scoped to that list (and
  restarting "fixed" it only because the selection resets to the first row), and
  both lists drew a "◀ focus" marker from their own focus alone — so a panel the
  keyboard could not reach still claimed focus and advertised keys that were
  being discarded. It now points at the key that gets you there.
- **A claimed agent name is no longer reported as no name at all.** When the
  claim succeeded but the read-back that follows it failed, the overlay rendered
  "No agent names yet." directly above "Applied, but could not reload the list"
  — the prominent half saying the opposite of what had happened, for a name the
  DID document already carried. A registry that could not be read is now shown
  as unknown rather than empty.
- **Listener log lines identify the listener, not just its name.** A name is not
  an identity: aliases and verified agent names are many-to-one, and a
  relationship R-DID resolves through to its peer's name — so two different
  listeners could produce byte-identical activity-log lines. Once names resolved
  a few minutes after launch, a log that had been readable as distinct listeners
  collapsed into one repeated name, and "one listener reconnecting in a loop"
  became indistinguishable from "several reconnecting on their own schedules".
  Every line that names a listener now carries the listener id it resolved from
  — abbreviated beside the name, in full behind `Enter` — because the id is what
  correlates with the mediator's own logs.
- **A disconnect with no transport error says so.** It rendered as a bare
  "disconnected", identical to a drop whose cause was simply not captured, so a
  socket that closed cleanly and one that was lost for unknown reasons read the
  same.

- **A pasted invitation now fills in the community it is for, and Enter says
  something either way.** On the join entry page a pasted VIC was routed to the
  invitation slot and nothing else: the DID input stayed empty, so Enter — which
  swallowed the keypress on an empty field, with no message — did nothing at
  all. The credential in hand names its community (a VIC's issuer *is* the VTC),
  so the operator was being asked to go and find a DID they already had, and got
  a screen that looked frozen when they didn't.

  A paste now records the issuer and prefills the input with it, and the loaded
  invitation says which community it came from. Prefilled, not auto-submitted:
  an invitation arrives from someone else, so the community stays visible and
  editable before Enter commits to joining it. Anything typed by hand wins over
  the credential, and a redraw never overwrites an edit. Enter on an empty field
  now reports why nothing happened. (vti-setup#29)
- **The invitation prompt is legible, and sits where it is needed.** It was dark
  grey italic — the dimmest text on the page — below the input and below the
  brighter examples block, and read as decoration; the reporter could not find
  anywhere to import a VIC at all. The invitation status and any error now sit
  directly above the input in full-contrast colours, and all of it wraps to the
  terminal width rather than clipping its tail. (vti-setup#29)
- **The setup wizard no longer advertises a step it will never run.** R-A-5
  ended setup at profile security — a persona is minted later by the join flow —
  but the breadcrumb still listed a fourth "Digital Identity" step (or "Display
  Name" on the webvh-server path) that could never become active, so the wizard
  appeared to skip a step on the way to Setup Complete. Setup is now shown as
  the four steps it actually has. (vti-setup#31)

- **Take `affinidi-messaging-delivery` 0.1.14, which stops the layer acking a
  message no consumer received.** An ack is a delete at the mediator, and the
  dispatcher acked unconditionally — including when its subscriber broadcast had
  just reported that nobody was listening. Those messages were destroyed: no
  subscriber is installed for a moment at startup and again on the way down, and
  what arrives in that window is whatever the peer happened to send.

  This is the layer-side half of the same defect as the unbounded event channel
  below. That change stopped *this* client discarding messages the mediator had
  already deleted; this one stops them being deleted before this client is
  listening at all. Lockfile only — the requirement was already `0.1.12`, so
  nothing but resolution moves. Verified against a live test mediator: all four
  `didcomm_transport_e2e` cases pass, including the stored-mail pickup path.
- **A join whose reply was lost can be reconciled again.** `join_status_poll`
  exists to ask a community what became of a join it never answered, but it was
  gated on `request_id_confirmed` — and the id it needed is the community's,
  learned from the first correlated reply. A join that never got one held only
  its own placeholder, which the VTC answers `not found` for, so the mechanism
  worked whenever it wasn't needed and failed whenever it was. The other
  recovery, collecting stored mail, is empty once that mail has been acked and
  deleted, so both failed together and the record sat `Pending` for good.

  A poll now omits the id when we don't hold the community's, which asks "what
  is my open request?" — resolved from the authenticated applicant
  (VTI#985). The reply carries the id, and `handle_join_status_response`
  already adopts it, so an unconfirmed record repairs itself on the first answer
  and quotes the real id from then on. `request_id_confirmed` still decides what
  we send; it no longer decides whether we may ask.

  Requires `vta-sdk` 0.24.

- **Inbound messages are no longer dropped when the event channel fills.** The
  DIDComm event channel was a 256-slot bounded channel whose overflow behaviour
  was log-and-drop, on the reasoning that a pathological mediator should not grow
  memory without bound. That missed what a dropped event costs: by the time an
  event reaches this channel the delivery layer has already acked the message,
  and an ack is a delete at the mediator. A dropped event was therefore not a
  deferred message but a **permanently destroyed** one — carrying membership
  credentials and join verdicts — with one `warn!` line as the only record.

  Backpressure was never actually on offer. Blocking on a full channel would
  stall the consumer, the delivery layer's subscriber broadcast would overflow
  instead, and its `subscribe()` stream swallows that as `Lagged` **silently** —
  strictly worse than the warned drop. The only real choice was where the loss
  happens, so the channel is now unbounded and the answer is nowhere.

  `pickup_stored` keeps its ack-after-handoff ordering: a message that cannot be
  taken stays stored at the mediator and is offered again.

### Added

- **A persona minted without TSP now says so, at mint time.** OpenVTC always
  requests the `#tsp` service — `create_did_via_server` sets
  `add_tsp_service: true` on every one of the three paths that mint a persona —
  but the VTA drops it unless it has `[services] tsp` enabled with a mediator
  configured. That refusal was silent, and the resulting persona looks entirely
  healthy: it resolves, it has a mediator, it messages DIDComm peers fine. It is
  only unable to reach a TSP-only community, which surfaces much later as a join
  that goes out and is never answered.

  Since the service is written at mint time and the document is never revisited,
  such a persona never recovers on its own — so the warning names the
  consequence, says the DID cannot gain the service later, and names the VTA
  setting that fixes it. Emitted as a `warn!` at the single mint point (so the
  log always has it) and surfaced on all three user-facing surfaces: the setup
  wizard's message list, the join flow's status line, and the persona manager's
  progress channel. A healthy mint stays silent.

- **`openvtc health` reports progress as it works.** The command is almost
  entirely network waits — a `did:webvh` resolution is an HTTPS fetch and each
  probe is bounded at 10s — so a chain with a few mediators could sit silent for
  most of a run that took 14 seconds. Each step now announces itself *before* the
  wait and reports the time it actually took, which makes the slow step visible
  while it is slow rather than inferable afterwards (it isn't: the finished
  report has no timings). Progress goes to stderr and the report to stdout, so
  `openvtc health --json > report.json` still pipes cleanly while showing the
  operator what is being waited on.

### Changed

- **`openvtc health` no longer probes `#files` and `#whois`.** Both are served by
  the DID host the report just fetched `did.jsonl` from, so resolving the DID had
  already proven that host answers — and `#files` points at the directory rather
  than the document, so the probe reported a 404 for a path that never serves a
  bare GET. Four such lines per party buried the transport probes that carry
  information. Implemented as a skip-list of the two document-adjacent service
  types rather than an allow-list of known transports, so a transport type this
  build has never heard of is still probed.

- **A probe's verdict now agrees with its status code.** "reachable (HTTP 404)"
  read as a contradiction — the word claimed health, the number denied it, and
  nothing told the reader which to believe. Statuses are graded: 2xx/3xx is `ok`,
  4xx is `responding` (the normal answer from an endpoint that takes POSTs and
  websockets rather than GETs), and 5xx is `server error`. Only the last is
  raised as a finding, which is a case the flat "reachable" actively hid: the
  host is up and the service behind it is failing.

- **A DIDComm-only persona against a TSP-only community now says what to do.**
  The advertised sets alone (`we offer [didcomm], they offer [tsp]`) do not tell
  an operator which side to change. A persona minted before the client requested
  `#tsp` cannot reach a TSP-only community and will never gain the service on its
  own — the document is written at mint time and not revisited — so the finding
  now says that, and that re-minting is the fix. Scoped to that one direction:
  re-minting our persona does not fix a DIDComm-only community.

### Fixed

- **The Communities footer no longer advertises `c` twice.** It listed every
  binding unconditionally, so `c: capabilities` and `c: cancel` appeared side by
  side and read as a collision. It never was one — `c` is capabilities on an
  Active row and cancel on a Pending one, and the states are mutually exclusive.
  The footer now shows what the selected row actually accepts, which also removes
  four silent no-ops it was advertising: `l`/`m` on a Pending or Inactive row and
  `x`/`d` on an Active one. The two panel-level keys (`j`, `v`) stay listed
  always, including when nothing is selected.

## [0.3.1] - 2026-08-15

A first-run join could go out and never be answerable. This fixes the state
machine that caused it, and adds the command that would have found it in one
step instead of five service logs.

### Fixed

- **A first-run join is answerable again.** Creating a persona and then joining
  — the ordinary first-run order — left the client in the State-A degraded loop
  instead of handing off to the runtime. That loop has no inbound arm, so the
  community's reply was received by the SDK, acknowledged (and therefore deleted
  at the mediator), and dropped before any handler saw it. The join stayed
  `Pending` forever with a clean log on both sides, and no restart could recover
  it: the mail was gone from the mediator, and `join-requests/status` polling is
  gated on a request id that only arrives in a reply that was never processed.

  The hand-off was gated on the join having minted the account's *first*
  identity. It never was: the degraded loop mints personas too
  (`CreatePersonaSubmit`), and `Config::active_identity()` reports `Some` for any
  persona at all, so the guard was false exactly when a persona had been created
  first. It is now gated on the join alone.

- **A live listener can no longer outlive its consumer.** The degraded loop
  re-checks `list_listeners()` each iteration and hands off whenever it holds
  one, whatever opened it. A socket this loop owns is a mailbox nobody reads, so
  the backstop is unconditional rather than specific to the join path — the
  failure mode it prevents is silent, permanent message loss that looks like a
  community which never answered.

### Added

- **`openvtc health [--vtc <did>] [--json]`** — resolve the messaging chain and
  print the map. For every DID involved (each persona, the VTA, every mediator,
  each VTC) it resolves the document, prints the `service` array verbatim —
  including entries of types this build does not recognise, since a party
  publishing one is indistinguishable from a party publishing nothing when read
  through the capability matcher alone — and probes any transport URLs. It then
  runs the same TSP > DIDComm > REST negotiation a real send performs, so the
  reported transport is the one that would actually be used, and names every
  party behind each mediator so a split-mediator topology is visible rather than
  assumed away.

  Read-only, and deliberately usable while things are broken: it takes no
  process lock (so it runs against a profile a stuck TUI is holding), and account
  details are best-effort (`--vtc` alone works with no account, and a config that
  will not decrypt is reported as a finding rather than an abort). Exits non-zero
  if any DID fails to resolve or any pair shares no transport.

### Changed

- **`trust-tasks-rs` 0.4 → 0.6, `trust-tasks-capability-client` 0.3 → 0.5,
  floor `vta-sdk` at 0.23.3.** This is a follow, not a lead: vta-sdk 0.23.3
  declares `trust-tasks-rs ^0.6` where 0.23.0 declared `^0.4`, so holding 0.4
  stopped matching the stack and started splitting the type — a dependency
  refresh alone put 0.4.1 and 0.6.5 in the same binary, which is precisely what
  the pin exists to prevent. `cargo tree -d` showing two `trust-tasks-rs` rows
  is the check that it has drifted again.

- Dependency refresh: `affinidi-messaging-sdk` 0.19.5 → 0.19.7, `vta-sdk` 0.23.0
  → 0.23.3, `vta-service` 0.15.0 → 0.15.3, `vti-common` 0.11.39 → 0.11.40, plus
  transitive updates.

## [0.3.0] - 2026-08-15

The first tagged release since 0.2.0 (21 May). 0.2.1 was version-bumped and
written up but never tagged or published, so everything under it ships here too.

The theme is the join ceremony's asynchronous half: a community's reply now
reaches the applicant whether or not it happened to be connected when the reply
was sent, and a join left unresolved is reconciled by asking rather than by
waiting.

### Added

- **Ask a community about a join it has not answered** — every way a `Pending`
  join could previously resolve was the community volunteering something: a
  verdict, a credential, a problem-report. If any of those was lost — a socket
  down at the wrong moment, a mediator that dropped it, a decision a human took
  days later when nothing was listening — the record sat `Pending` and this
  client never asked. `join-requests/status/0.1` is the protocol's answer to
  exactly that, and OpenVTC had implemented only the receiving half
  (`handle_join_status_response` existed with nothing to trigger it).

  A minute-by-minute tick now reconciles each pollable `Pending` join, starting
  with an immediate poll at launch — a join still `Pending` when the app starts
  is precisely the one whose answer may have been lost. Per record it then backs
  off 1 → 2 → 4 → 8 minutes, capped at 15, with at most four polls per tick
  across the account (R1.4), so a parked join is noticed promptly without this
  client becoming a load source. Pacing is deliberately in memory: it is about
  this process's politeness, and a stale on-disk backoff would suppress the poll
  a fresh launch most wants to make. The poll takes the transport the submit took
  — a TSP-only community would never see a DIDComm poll.

- **Adopt the community's own request id when it first replies** — a join is
  recorded against the id of the request document *we* sent, because that is the
  only handle available until the VTC answers; the VTC mints its own and returns
  it in the first correlated reply. The submit-receipt path already swapped the
  id in, but a `refer` / `request_more` verdict carries `requestId` too and read
  straight past it — correlation there is by `thid`, so nothing needed it.

  A referred join is the one that then sits `Pending` for as long as a human
  takes, so it is the one that most needs to be askable-about later, and without
  the id there is no handle to ask with. `CommunityRecord::request_id_confirmed`
  now records *whose* id a record holds, and is the gate on polling: quoting our
  own placeholder would be asking about a request the community has never heard
  of. Records written before this default to unconfirmed, which is the safe
  reading — we cannot tell whose id they hold.

  Note what this does **not** cover: a join that received *no* reply at all has
  no confirmed id and cannot be polled. That case is not a gap here — it is
  recovered by collecting the stored mail the reply is sitting in.

### Fixed

- **Collect the messages the mediator is holding, instead of waiting to be
  pushed** — every inbound message OpenVTC has ever received arrived by live
  delivery. A mediator live-streams a message only to a recipient connected at
  the instant it lands; everything else is stored, and a stored inbox is
  redelivered **only** when a new websocket *displaces* an existing one for the
  same DID (`websocket_streaming.rs`, `if replacing`). Enabling live delivery
  drains nothing. So a listener that connects for the first time — the applicant
  persona during a join, a community's session after a restart, any identity
  whose socket was down when a reply arrived — was never told what was already
  waiting for it, and nothing in this client ever asked.

  That is the join that sits `Pending` while the community's outbox reports
  `Sent`, and it is why relaunching the app appeared to fix it: the new process's
  socket displaced the old one, and *that* is what made the mediator redelivery
  fire. The recovery was a side effect of how the previous process happened to
  exit.

  `Messaging::pickup_stored` now collects a listener's stored mail over
  message-pickup 3.0 and hands each message to the state handler on the same
  channel a live frame uses, and `pickup_on_connect` runs it on every connect —
  first connect and reconnect alike, since a reconnect is exactly when something
  may have landed with nobody attached. Messages are acknowledged **after**
  handoff, never before, the same discipline the delivery layer's own dispatcher
  follows; a frame that could not be unsealed, mapped, or queued is deliberately
  *not* acked, so nothing is deleted unread. Bounded at 200 messages per connect
  (R1.4), with the remainder logged rather than silently dropped.

  Classification is shared with the live dispatcher rather than copied
  (`classify_inbound`), so the two paths cannot drift into admitting different
  message types — and the authcrypt sender binding is applied to a collected
  message too, because these carry membership decisions and credentials and must
  not be the one path where a spoofed `from` is believed.

  Delivery is at-least-once by design (a message may also arrive live); the
  runtime loop's `SeenMessages` is what makes that harmless.

- **Start messaging before the first join, not after it** — a State-A account
  (no persona yet) ran its join with no messaging runtime at all, so the
  applicant had no socket for the entire ceremony. A community auto-admitting an
  invited join answers in under a second, so its reply was stored rather than
  streamed — and since the hot-start's listener was a *first* connect, the
  mediator never redelivered it either. The first join a new operator makes was
  the one join with no live recipient.

  The runtime now comes up **before** the State-A branch and empty
  (`start_empty_service`; `Messaging::start` runs its dispatcher before the first
  transport exists, so this is a supported state, not a stub), and the degraded
  loop hands it to `join_flow`. A State-A join therefore connects its applicant
  before submitting, exactly as the runtime-loop join already does.
  `install_listeners` then adds whatever is missing, skipping any the join
  already brought up — one websocket per DID.

  The durable join record also now states whether the applicant was connected at
  submit. A join sent from an unconnected persona is still valid, but it is the
  one that takes the collect-on-connect path, and an operator reading the log
  later could not otherwise tell that from a community that never answered.

- **Connect the applicant persona before submitting the join, not after** — a
  join over an accepted invitation is auto-admitted in well under a second, and
  the community pushes the membership credential (VMC) and role credential (VEC)
  straight back. The persona's mediator socket, though, only came up once the
  join flow had returned to the main page, so the reply arrived while its
  recipient had no live stream. A mediator live-streams a message only if the
  recipient is connected at the instant it lands: both credentials were stored
  and never pushed, and nothing polled the mailbox afterwards.

  It read as a failed join with clean logs at every hop — the community's outbox
  said *sent*, the mediator held two messages, and the membership sat `Pending`
  with no error anywhere. Observed with a ~29 s gap between the credentials
  landing and the persona's websocket registering, which is simply how long the
  operator spent on the confirmation screen.

  `run_join_sequence` now installs the persona listener as soon as the applicant
  identity exists and waits — bounded at 10 s — immediately before
  `submit_join_request`, so the socket is live for the whole window in which a
  reply can arrive and the connect is spent on the invitation resolution and VP
  build rather than on the operator's time. The wait is finite and never fatal
  (R1.2): a slow or failed connect says which it was (R6.4) and the submit goes
  out regardless — the community still admits, and the reply is collected when
  the listener does come up. `register_joined_session` already tolerated a
  listener that exists, so it now binds to it rather than installing a second.

  Cancel-safety is preserved on the pattern `minted_persona` established: the
  listener id is returned only when *this* call installed it, and is held outside
  the interruptible future so a Ctrl-C — or a failed submit — tears it down
  instead of leaving a socket open for a persona that was just rolled back. A
  reused persona already serving another community is never claimed, so its
  session survives a cancelled join.

  Independent of this, the mediator-side half of the same gap is fixed upstream
  in `affinidi-messaging-mediator` 0.18.16: enabling live delivery now redelivers
  what is already queued. Deployments want both — this change stops the reply
  from being stranded, that one stops an already-stranded reply from staying
  stranded.

### Changed

- **Refresh every dependency to its latest release** — `cargo update` across
  the whole graph, plus the manifest bumps needed to cross a major boundary:
  `vta-sdk` 0.20 → 0.21.7, `affinidi-messaging-sdk` 0.18 → 0.19.2,
  `trust-tasks-rs` 0.2 → 0.3.0, `trust-tasks-capability-client` 0.1 → 0.2.0,
  and the `vta-service` dev-dependency 0.13 → 0.14.16.

  One source change was needed. `affinidi-messaging-core` 0.1.6 marks
  `Protocol` `#[non_exhaustive]` and adds a `DIDCommV1` variant (Aries RFC
  0019), so the inbound dispatcher's `match` in `didcomm.rs` no longer
  compiles as written. It gained a wildcard arm that logs and drops: OpenVTC
  speaks DIDComm v2.1 and TSP, neither listener it installs ever negotiates
  v1, and nothing downstream of that match could read a v1 payload. The arm
  is also what keeps the *next* variant from being a compile break.

  Everything else rode the bump untouched — the join ceremony, the reciprocal
  VMC exchange, and the TSP leg all dispatch on `vta_sdk::protocols`
  constants rather than string literals. Verified with the full suite
  including the `#[ignore]`d e2e tests, which are the ones that actually
  exercise these crates: the in-process mediator transport round-trip, the
  join/self-remove lifecycle, and the MockVta bootstrap against
  `vta-service` 0.14.

  Two pins survive re-evaluation and stay: `rand` 0.8 and `x25519-dalek` 2.x
  are both still forced by `pgp` 0.20.0, which remains the latest release and
  declares `rand ^0.8.6` / `x25519-dalek ^2.0.1`.

  Known duplicate, upstream to fix: `did-git-sign` 0.4.1 still depends on
  `vta-sdk` 0.19.28, so the binary links two vta-sdk majors. That belongs to
  `verifiable-git-infrastructure`, not here.

- **Drop two resolved advisory ignores from `deny.toml`** — RUSTSEC-2026-0215
  (`smallstr` unmaintained) and RUSTSEC-2024-0370 (`proc-macro-error`
  unmaintained). Both crates left the dependency graph with this refresh,
  exactly as each ignore's comment predicted, and `cargo deny` now reports
  them as unmatched. The remaining ignores still match and stay.

- **Follow the VTC Trust Tasks onto the `spec/vtc` registry authority** —
  `vta-sdk` 0.20.0 → 0.20.1 (and `trust-tasks-rs` 0.2.26 → 0.2.38). The VTC's
  Trust Tasks have moved off the non-conformant
  `trusttasks.org/openvtc/vtc/…` authority to the canonical registry at
  `trusttasks.org/spec/vtc/…`
  (OpenVTC/verifiable-trust-infrastructure#806, dtgwg-trust-tasks-tf#144).

  No source change was needed: the join ceremony and the reciprocal-VMC
  exchange dispatch on `vta_sdk::protocols` constants rather than string
  literals, so the new URIs arrive with the bump —
  `MEMBER_REQUEST_VMC_TYPE` and `MEMBER_VMC_TYPE` now read
  `spec/vtc/members/{request-vmc,vmc}/0.1`, and the join-request and
  self-remove receipts likewise. That indirection is why this is a lockfile
  change and not an audit of every dispatch site.

  The inbound router already accepted both authorities — `OPENVTC_CATCH_ALL_PATTERN`
  gained its `spec/vtc/` arm ahead of the migration precisely so migrated
  traffic would not be dropped before dispatch. It stays dual-arm for now:
  the `openvtc/vtc/` arm can be retired once no supported VTC emits it, and
  eight VTC tasks are still on the old authority awaiting a canonical fold.

## [0.2.1] - 2026-05-24

### Security

- **Derive unlock key via Argon2id in non-openpgp import path** — the non-`openpgp-card` build was passing the raw passphrase to `SecuredConfig::save()` as the AES-256 key, bypassing the Argon2id KDF and making the saved config unrecoverable since `UnlockCode::from_string()` always applies Argon2id at load time
- **Reject path-traversal characters in profile name** — `--profile` and `OPENVTC_CONFIG_PROFILE` were spliced verbatim into lock-file paths, config paths, and OS keyring account names; now restricted to `[A-Za-z0-9._-]` with no `..` component
- **Redact armored private key block in `DIDKeysExportState` `Debug`** — the derived `Debug` impl could dump the full PGP-armored private key through any `{:?}` of `State` (panic backtrace, tracing, debug print)
- **Warn that `--unlock-code` is visible in the process list** — the flag exposes the passphrase via `ps`/`/proc/<pid>/cmdline` and shell history; help text now documents this and a runtime warning nudges users toward the interactive prompt
- **Restore terminal on panic via panic hook** — panics inside the render loop, key handlers, or spawned tasks no longer leave the TTY in raw mode on the alternate screen
- **Drop exported private-key armor from `State` after use** — the armored PGP private key block was cloned through the state broadcast channel on every tick for the remainder of the setup wizard
- **Avoid OOB panic on stale token-list index** — unplugging or re-enumerating tokens no longer panics the TUI when a retained selection index exceeds the new bounds
- **Clear private-key clipboard when leaving export page** — the ASCII-armored PGP private key block placed on the OS clipboard by `[C]` is now cleared on continue (unless the user has copied something else in the meantime)
- **Clear `ConfigImport` passphrase `Input` buffers after dispatch** — both passphrase inputs are now reset once wrapped in `SecretString` and dispatched, matching the other secret-input pages

## [0.2.0] - 2026-05-05

### Added

- **Full TUI main menu panels** in `openvtc` — 8 panels: Inbox, Relationships, Credentials, Settings, VTA Service, Logs, Help/Status, Quit
- **Inbox panel** with real-time task processing: auto-handles trust-pongs, relationship finalization, and rejections; queues interactive tasks; detail views for all task types (inbound/outbound requests, VRCs, pings, informational)
- **Relationships panel** with list/detail/new-request views, inline alias editing ('e' key), R-DID privacy toggle, trust-ping with RTT latency
- **Credentials panel** with Received/Issued tabs, raw VRC JSON in detail view, clipboard copy ('c' key), VRC request and removal
- **Settings panel** with inline editing, config export/import, passphrase protection management, hardware token detection and factory reset
- **VTA Service panel** showing VTA URL, DID, credential DID, key count, and backend type
- **Logs panel** with scrollable timestamped activity log, selected entry copy ('c'), copy all ('a')
- **Activity log panel** at bottom of screen showing real-time timestamped events (`[HH:MM:SS] message`)
- **Status/Help panel** with DID clipboard copy hotkeys ([1] persona, [2] mediator), visual feedback on copy
- **R-DID generation** for both BIP32 and VTA backends — VTA path authenticates and creates keys via API; both sender and receiver can use R-DIDs
- **Dynamic R-DID listeners** — automatically added when creating R-DIDs (sender or receiver), enabling message delivery to relationship-specific DIDs
- **VRC issuance** from inbox with DataIntegrityProof signing; **VRC rejection** with message back to requester
- **Friendly name in relationship requests** — sender's name included in request body, auto-set as contact alias on accept, R-DID recommendation shown when sender uses one
- **DIDComm service integration** (`affinidi-messaging-didcomm-service` 0.2) — replaces manual messaging with Router-based dispatch, automatic reconnection, message pickup, and multi-DID listener support
- **Periodic keepalive ping** (60s) with live RTT latency in connection status header
- **Inbox task count badge** on menu item ("Inbox (3)" in red when tasks pending)
- **Bracketed paste** for all 21 text input fields — paste is instant regardless of string length
- **Up/Down arrow navigation** in all multi-field forms alongside Tab
- **Config versioning** with stepwise migration framework
- **Panel trait** for content panels — unified render interface
- **Outbound message retry** via `DIDCommService::send_message_with_retry`
- **Auto-reconnect mediator** on DID change in settings
- 15 unit tests covering core functions
- **Contact management** actions (add/remove)

### Security

- Trust-pings only responded to from mediator DID or established relationships — prevents presence leakage
- Passphrases removed from cloned State — length-only fields in UI, consumed via `mem::take`
- Token admin PIN wrapped in `Arc<SecretString>` for shared allocation
- Inbound message body size validation (1MB limit), task ID deduplication, sender verification
- Collection bounds (10K tasks, 5K relationships), untrusted display text sanitization
- Unlock rate limiting (5 attempts, exponential backoff), path redaction, file path validation
- Key material explicit drop with documented zeroization limitation
- Structured audit log entries for security-relevant operations

### Fixed

- **R-DID message routing** — acceptance, finalize, VRC, and ping messages now use relationship DID instead of persona DID when R-DID exists
- **Config persistence** — all mutating actions save to disk
- **Setup → main transition** — `sync_from_config()` now called after setup wizard completes
- **VRC "From:" blank** — extract remote DID from relationship for VRC tasks
- **Alias on accept** — sender's name set as contact alias, existing alias-less contacts updated
- **Backspace to empty** in relationship form fields
- **Tab after backspace fix** — dedicated `FocusField` action for field switching
- **DIDComm listener secrets** — pass DID secrets to listeners for mediator authentication
- All `.unwrap()`/`.expect()` replaced with proper error propagation
- Clipboard graceful degradation, `sanitize_display` ANSI stripping order

### Changed

- **Workspace consolidation** — renamed the active CLI package and binary `openvtc-cli2` → `openvtc`, and renamed the supporting library `openvtc-lib` → `openvtc-core`. The unsuffixed name now belongs to the user-facing binary, matching the convention used by uv, ruff, deno, and cargo. The library is `publish = false`, so no external consumers are affected.
- **`vta-sdk` 0.5** consumed from crates.io — dropped the temporary `../verifiable-trust-infrastructure/vta-sdk` path pin so the workspace no longer requires a sibling checkout to build.
- **Replaced manual messaging layer** with `affinidi-messaging-didcomm-service` — deleted messaging/mod.rs (~280 lines) and outbound_queue.rs (~90 lines), added didcomm.rs (~260 lines) with Router, listeners, and send_message_with_retry
- Grouped ~65-variant Action enum into 5 domain sub-enums
- `tokio::sync::watch` replaces mpsc for State updates
- Panel trait with per-panel structs implementing unified render interface
- Dynamic DID display width (`shorten_did(did, max_width)` — 60 chars default, full if fits)
- `Cow<str>` for zero-alloc DID truncation
- Explicit `Arc::clone()`, `#[must_use]` on pure functions, doc comments on State types
- `VecDeque<String>` for O(1) bounded activity log
- `RelationshipRequestBody.name` protocol field for friendly names

### Removed

- **Legacy `openvtc-cli` crate** — the original prompt-driven CLI was phased out in favour of the TUI. All ongoing work lives in `openvtc`.
- **Dead `VtaAuthenticate` setup page** — online provisioning emits `VtaAuthCompleted` directly from `VtaProvisioning`, so the legacy authenticate screen was unreachable.

### Post-release deep-review pass

After cutting the v0.2.0 branch a multi-axis review (code quality, security, tests, docs) flagged a set of findings that landed on the same release branch before merge. They're listed separately so the diff between v0.1.x and v0.2.0 stays readable.

#### Security

- **Per-entry random Argon2 salt with transparent v1→v2 migration.** `derive_passphrase_key` previously used a deterministic salt = SHA-256(info), so two operators with the same passphrase produced the same KEK and exported backups were byte-comparable. The new `passphrase_encrypt_v2` / `passphrase_decrypt` API in `openvtc-core::config::secured_config` writes a magic-prefixed `[OPV2 | salt(16) | nonce(12) | ct+tag]` blob with a fresh random salt; the decrypt path auto-detects v1/v2 so existing exports keep opening. Argon2id parameters bumped to OWASP "high-value KEK" floor (m=128 MiB, t=4, p=1).
- **`did-git-sign` signing policy.** The proxy now refuses to sign unless the parent process name starts with `git` or `ssh-keygen`, and writes every signing attempt — accepted or denied — to `~/.config/did-git-sign/audit.log` (mode 0600) with parent PID/name, namespace, buffer path and SHA-256. Blocks the "malicious build script obtains a signature with namespace=git over attacker-chosen content" pivot.
- **DIDComm replay window + seen-message LRU** in `process_inbound_message`: drop messages with `created_time` outside ±48h / +5m skew, drop messages whose `expires_time` already passed, dedupe on a 1024-entry process-lifetime ID LRU.
- **DID validation** uses a real W3C DID Core 1.0 syntax parser instead of a `did:` prefix check; rejects bidi-override / zero-width chars in DID fields.
- **Inbox display-name sanitisation** strips bidi-override / isolate / zero-width / BOM unicode (Cf class) plus ANSI escapes / control chars, and clamps inbound contact aliases to 64 chars before persistence.
- **Bounded DIDComm event channel** (256-entry capacity) so a noisy mediator can't grow memory without limit; overflow logs and drops, mediator pickup redelivers when we drain.
- **`did.jsonl` write path** is now the resolved profile dir, not the current working directory.
- **Dependabot:** transitive openssl/rustls-webpki/rand bumped via `cargo update` to clear nine open advisories. `pgp` was already at the patched 0.19.
- **Tagged-variant downgrade defence on `SecuredConfigFormat`.** Switched the on-disk variant tag from `#[serde(untagged)]` to `#[serde(tag = "format")]` so every blob carries an explicit `"format"` discriminator. Without it, an attacker with write access to the OS keychain could substitute a `PasswordEncrypted` blob with `{"text": "<plaintext>"}` and serde would silently match it as `PlainText`, bypassing AES-256-GCM. New `assert_format_matches_intent` cross-validation gate adds a second defence layer — a tagged-but-weaker blob is rejected before any decrypt or re-save. Old (untagged) blobs migrate transparently on first load. Folded from @ojasshelke's PR #34; the PR's HKDF v2 fixed-salt variant is superseded by our random-per-entry-salt v2 (`OPV2` magic prefix) above.

#### Community contributions

Three community PRs against `main` were assessed and folded into the release. Each PR's substantive value is preserved with `Co-authored-by:` trailers; the corresponding PRs are closed with a comment pointing here.

- **#57 — profile-name validation hardening (@sameerchore).** `validate_profile_name` now trims leading/trailing whitespace before validating, and the empty/whitespace check runs before the character check (so `"   "` gets a clear "cannot be empty or contain only whitespace" error instead of the confusing "Invalid profile name '   '"). Three new integration tests pin the behaviour.
- **#51 — cross-platform config paths (@krsatyamthakur-droid, closes #47).** `profile_dir` and `get_lock_file` now use `dirs::config_dir()` on Windows (typically `%APPDATA%\openvtc`); Unix/macOS continues to use `~/.config/openvtc/` so existing installs don't move. `get_config_path` and `get_lock_file` return `PathBuf` instead of `String` end-to-end.
- **#34 — `SecuredConfig` serde-format hardening (@ojasshelke).** Tagged-variant downgrade defence + intent-gate cross-validation, described under Security above. The PR's HKDF v2 fixed-salt scheme was superseded by our random-salt OPV2 v2 and intentionally not folded.

#### Architecture & code quality

- **State-handler split.** `state_handler/mod.rs` was 2,255 lines with a 500-line `tokio::select!` arm; it's now 813 lines (-64%). Each per-domain match (Inbox, Relationship, Credential, Settings, Contact) was extracted to a `dispatch(action, ctx).await` entry point in the corresponding sub-module.
- **Layering:** moved `colors.rs` and the `dialoguer` passphrase prompt out of `openvtc-core` so the daemon (`openvtc-service`) and automation (`robotic-maintainers`) crates no longer pull in `ratatui` + `dialoguer` transitively.
- **Lifted four DID-truncation helpers** into a single `openvtc-core::display` module (`truncate_did`, `truncate_did_centered`).
- **Tightened `openvtc-core` public surface** — dropped a dead `pub use` re-export and scoped two helpers to `pub(crate)`.
- **Fixed silent failures** in the state handler: surfaced previously-swallowed `save_config` / `remove_listener` / inbox-task errors via `log_error`. Replaced four `.expect("valid route")` panics in DIDComm router init with `?`. Replaced `panic!("Cannot create log file …")` with stderr + continue.
- **Fixed DIDComm-only VTA fallback** in `relationships.rs` (used `build_runtime_vta_client` instead of REST-only `challenge_response`).

#### Tests & CI

- **In-process mediator harness** (`openvtc-core/tests/common/mod.rs`): wraps the upstream `affinidi-messaging-test-mediator` 0.2 fixture via `TestMediator::with_users(["alice", "bob"])`, which boots a real `affinidi-messaging-mediator` on an ephemeral loopback port (memory-backed store, generated `did:peer` identity advertising `dm`/`#auth`/`#ws`, Ed25519 JWT signing keypair) and returns Alice + Bob as ALLOW_ALL accounts whose DIDComm service URI is the mediator's DID — the routing/2.0 shape required for forwards to short-circuit to local delivery instead of being enqueued for external forwarding. The previous in-tree harness predated the test-mediator crate; the migration drops ~400 lines of fixture code and four dev-deps (`affinidi-messaging-mediator`, `-mediator-common`, `-sdk`, `sha256`).
- **End-to-end integration tests** (`relationship_e2e.rs`): drive a real Alice→Mediator→Bob DIDComm round-trip, a production `RelationshipRequestBody` round-trip, and a two-leg VRC request/reject round-trip — all in ~350ms once the mediator is up. Plus a smoke test (`mediator_smoke.rs`) that asserts the well-known endpoint serves a DID Document. Marked `#[ignore]` (each spawns the mediator, ~1s); CI's coverage job runs them with `--include-ignored`.
- **38 new unit tests** across `setup_flow/navigation` (25 table-driven), BIP32 derivation (7 known-answer vectors), AES-GCM tampering (6) — locking the wizard flow, derivation contract, and AEAD failure modes before the v0.3.0 work begins.
- **CI** adds a `cargo-deny` job (advisories + licenses + bans + sources, with documented `RUSTSEC-2023-0071` rsa Marvin-Attack and `RUSTSEC-2024-0370` proc-macro-error ignores) and a `cargo-llvm-cov` coverage job (uploads `lcov.info` artifact, runs ignored tests). MSRV check bumped 1.91 → 1.94 to match `Cargo.toml`.

#### Dependency refresh

Picks up the May 2026 Affinidi-stack releases. All bumps cleared on crates.io; build, full test suite, and integration tests pass.

- **`affinidi-tdk` 0.6 → 0.7** — accessor-method API on `TDKSharedState`/`TDKEnvironment`/`TDKProfile`. Field accesses (`.secrets_resolver`, `.environment`, `.profiles`, `.default_mediator`, `.ssl_certificate_paths`) are now method calls. `TDKSharedState::default().await` (removed in tdk 0.6) replaced with `TDKSharedState::new(TDKConfig::headless()?).await?` in `openvtc-service`.
- **`affinidi-messaging-didcomm-service` 0.2 → 0.3** — version bump driven by the upstream `MediatorACLSet` error-type relocation; downstream impact is `?`-transparent thanks to `From<ACLError> for ATMError`.
- **`affinidi-messaging-test-mediator` 0.1 → 0.2** (dev-deps only) — `TestMediator::with_users(["alice", "bob"])` replaces our hand-rolled `MemoryStore` + ALLOW_ALL registration dance. Drops `affinidi-messaging-mediator`, `-mediator-common`, `-sdk` and `sha256` from dev-deps.
- Working with the upstream maintainers, this branch's review of the May 2026 test-mediator changes also surfaced two follow-ups landing post-publication: an IPv6 routing-classification fix and `mediator-common` feature-gating to keep the SDK light. Neither is on the path used by openvtc tests (loopback over `127.0.0.1`).

#### Docs

- README, CONTRIBUTING, SECURITY, CLAUDE.md aligned to the post-rename workspace shape (`openvtc` binary + `openvtc-core` lib).
- CHANGELOG `[0.2.0]` entry above describes the release as it actually shipped.

## [0.1.5] - 2026-04-14

### Security

- Upgraded `pgp` 0.18 &rarr; 0.19, resolving 3 Dependabot alerts: parser crash on crafted RSA secret key packets (CVE-2026-21895), crash from deeply nested messages, and integrity protection not always checked on encrypted data

### Added

- Hardware token touch prompt overlay in `openvtc-cli2` — a centered popup now appears when a YubiKey (or other OpenPGP card) requires physical touch confirmation, and auto-dismisses when the touch completes
- Progress feedback during VTA credential validation in `openvtc-cli2` setup wizard
- Unit tests for `MessageType` and `KeyPurpose` in `openvtc-lib`
- GitHub Discussions guidance in `CONTRIBUTING.md`

### Changed

- Upgraded `secrecy` 0.8 &rarr; 0.10 (`SecretVec<u8>` replaced with `SecretBox<Vec<u8>>`, `SecretString::new()` API updated)
- Upgraded `openpgp-card` 0.5 &rarr; 0.6 and `openpgp-card-rpgp` 0.6 &rarr; 0.7
- Migrated pgp 0.19 API changes: `EncryptionKey`/`DecryptionKey` traits, `SubpacketData::IssuerKeyId`, `Timestamp` types

### Removed

- Stale `openvtc-cli2/did.jsonl` test artifact

## [0.1.4] - 2026-04-12

### Breaking Changes

- **Removed legacy SHA-256+HKDF encryption** — existing configs must be recreated with `openvtc setup`
- **`UnlockCode::from_string()` now returns `Result`** and enforces minimum 8-character passphrase
- **`derive_passphrase_key()` now returns `Result`** — callers must handle the error

### Security

- Replaced `rand::thread_rng()` with `OsRng` in all cryptographic key generation paths (BIP39 entropy, PGP export, DID key generation)
- Hardened Argon2id parameters: 64 MiB memory / 3 iterations (up from default 19 MiB / 2 iterations) per OWASP recommendations
- Added `#![deny(unsafe_code)]` to `openvtc-lib` — no unsafe code in production paths
- Added DID format validation for `OPENVTC_MEDIATOR_DID` and `OPENVTC_ORG_DID` environment variable overrides
- Replaced all production `unwrap()` calls with proper error handling in setup wizard, clipboard operations, and service initialization
- Replaced ~15 silent `let _ =` error discards with `debug!`/`warn!` logging in state handler, service, and robotic-maintainers

### Added

- Argon2id as sole KDF (removed legacy fallback)
- Profile name validation (alphanumeric, hyphens, underscores only)
- Rate limiting to `openvtc-service` (50 msg/sec with throttle logging)
- Graceful shutdown signal handling (SIGINT/SIGTERM) in `openvtc-service`
- Criterion benchmarks for `derive_passphrase_key` and `unlock_code_encrypt`/`unlock_code_decrypt`
- Integration tests for profile validation, relationships, VRCs, tasks, and logs (38 new tests)
- `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1)
- Windows to CI test matrix
- MSRV verification (Rust 1.91.0) in CI pipeline
- API documentation for public modules (relationships, VRCs, tasks, logs, config)

### Fixed

- All Clippy warnings (migrated deprecated Protocols API, collapsible-if, items-after-test-module)
- Corrected valid-until prompt handling for VRC issuance in `openvtc-cli` (PR #23)

### New: `did-git-sign` crate

A standalone CLI tool for signing git commits using DID Ed25519 keys managed by a VTA. Acts as a git SSH signing proxy — no private key material ever touches disk.

- Git SSH signing proxy via `gpg.ssh.program` integration
- VTA authentication with token caching in OS keyring
- Credential private key stored in OS keyring (macOS Keychain / Linux Secret Service)
- Ed25519 signing key fetched from VTA at sign-time and zeroized after use
- SSH signature output in PROTOCOL.sshsig format
- `init` command — configures git and sets up allowed_signers for verification
- `status` command — displays current signing configuration and keyring state
- `verify` command — end-to-end test of keyring, VTA auth, key fetch, and signing
- Config validation: rejects non-HTTPS VTA URLs, empty credentials, non-Ed25519 keys
- Retry logic for VTA authentication (up to 2 attempts on transient failures)

### Dependency Updates

- `didwebvh-rs` 0.1 &rarr; 0.4
- `affinidi-tdk` 0.5 &rarr; 0.6 (`affinidi-messaging-didcomm` 0.12 &rarr; 0.13)
- `affinidi-data-integrity` 0.4 &rarr; 0.5
- `dtg-credentials` switched from local path to crates.io (`0.1`)
- `vta-sdk` updated to 0.3 (`health.version` is now `Option<String>`, `VtaClient::set_token` no longer requires `&mut self`, `CreateDidWebvhRequest` has new optional fields)
- All transitive dependencies updated to latest compatible versions via `cargo update`

### didwebvh-rs 0.4 Migration

- Replaced manual `DIDWebVHState::default()` + `create_log_entry()` pattern with the new `create_did(CreateDIDConfig)` API in both `openvtc-lib` and `openvtc-cli`
- `create_initial_webvh_did()` is now async (required by `create_did`)
- Added `LogEntryMethods` trait import for `get_did_document()` access

### Breaking API Changes (from dependency updates)

- `DataIntegrityProof::sign_jcs_data()` is now async — added `.await` in `openvtc-cli`, `robotic-maintainers`, and `dtg-credentials`
- `DTGCredential::sign()` is now async
- `CreateDidWebvhRequest.server_id` changed from `String` to `Option<String>`
- `CreateDidWebvhRequest` now requires `url: Option<String>` field and new optional fields (`did_document`, `did_log`, `signing_key_id`, `ka_key_id`, `set_primary`)
- `CreateDidWebvhResultBody.mnemonic` changed to `Option<String>`
- `Message::pack_encrypted()` removed — replaced with `ATM::pack_encrypted(&msg, to, from, sign_by)`
- `Message.type_` field renamed to `Message.typ`
- `didcomm::error::Error` replaced by `didcomm::DIDCommError`
- `PackEncryptedOptions` removed — encryption options are now implicit in the pack function choice
- `UnpackMetadata` moved from `didcomm` to `messaging::messages::compat`
- `VtaClient::set_token()` no longer requires `&mut self`
- `HealthResponse.version` changed from `String` to `Option<String>`

### Security Improvements

- Custom `Debug` implementations for `PersonaDIDKeys` and `KeyInfo` that redact secret material
- Replaced debug logging of full `SecuredConfig` struct with safe summary
- Fixed `unwrap()` in SSH signature encoding path with `expect()` and context
- VTA URL validation — rejects plain HTTP (except localhost for development)
- Ed25519 key type validation when fetching signing keys from VTA
- Empty access token rejection after VTA authentication

### Code Quality

- Extracted 11 hardcoded protocol URLs to `protocol_urls` constants module in `openvtc-lib`
- Added `mediator_did()` and `org_did()` helper functions with environment variable overrides (`OPENVTC_MEDIATOR_DID`, `OPENVTC_ORG_DID`)
- Updated `MessageType` `From`/`TryFrom` impls and VRC message builders to use protocol URL constants
- Removed unused `console` and `crossterm` dependencies from `openvtc-lib`

### Tests

- **openvtc-lib**: Added 14 new tests (2 &rarr; 16 total)
  - Encrypt/decrypt roundtrip, wrong key rejection, empty data, large data, different key ciphertext divergence, corrupted data detection, zeroize verification
  - Protected config save/load roundtrip, wrong seed rejection, serialization, contacts find/remove, credential seed determinism and divergence
- **did-git-sign**: Added 6 new tests (5 &rarr; 11 total)
  - Config validation (empty URL, HTTP rejection, HTTPS acceptance, localhost exception, empty key ID rejection, seed material zeroization)

### Documentation

- Added `did-git-sign/README.md` with setup instructions, architecture diagram, security model, and config format reference
- Added workspace crates table and DID Git Signing section to root `README.md`

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
