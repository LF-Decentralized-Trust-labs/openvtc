//! Background-dispatch pattern for network-bound runtime actions (R13).
//!
//! # The problem
//!
//! The runtime `tokio::select!` loop in [`super`] services exactly one arm at a
//! time. Several action dispatches `.await` network I/O *inline* in their arm,
//! so the whole loop is parked for the duration. The worst case is a mediator
//! change / reconnect, which calls
//! [`super::didcomm::reconnect_persona_listener_io`] and waits up to **30
//! seconds** for the listener to connect (`wait_connected(.., 30s)`). While that
//! future is
//! pending, no other select arm runs: queued keystrokes pile up, inbound DIDComm
//! events in the bounded channel get dropped, and even `q` / Exit is dead.
//!
//! # The pattern
//!
//! Startup already solves this (`super::StateHandler::main_loop`'s
//! `MainPageDeferred` arm): the slow load runs as a spawned task that streams
//! progress/completion back into a responsive select loop over a channel. This
//! module generalises that for *runtime* actions:
//!
//! * The background task does **I/O only** and returns a [`DispatchOutcome`]
//!   over an mpsc the loop owns.
//! * **All mutation stays on the loop thread**: a dedicated select arm applies
//!   the outcome (config changes, save/sync helpers, status), so the
//!   single-mutator / unidirectional-data-flow invariant is preserved.
//! * A per-domain [`InFlight`] busy-guard rejects a second action on a busy
//!   domain with a visible status message instead of running it concurrently or
//!   queueing it blind — matching today's effectively-serialised behaviour.
//!
//! R13 migrates the mediator change/reconnect path as the single proving case;
//! R14 migrates the remaining network dispatches onto the same mechanism.

use openvtc_core::config::Config;

use crate::state_handler::didcomm::ReconnectOutcome;
use crate::state_handler::inbox_actions::InboxOutcome;
use crate::state_handler::relationship_actions::{DidDeleteOutcome, RelationshipOutcome};
use crate::state_handler::state::{self, State};

/// A domain that can have at most one background dispatch in flight at a time.
///
/// The set is intentionally small and matches the "one mutating task" model the
/// loop already had: serialising per domain means a user can't, e.g., fire two
/// mediator reconnects at once, while still leaving distinct domains independent
/// (a relationship dispatch and a mediator reconnect don't block each other).
///
/// R14 keeps the granularity conservative: every relationship-panel network
/// action (create / ping / remove) shares one `Relationship` domain, and every
/// inbox network action (accept / reject) shares one `Inbox` domain. Two actions
/// on the *same* domain — even if they target different relationships — are
/// serialised (the second is rejected with a status), matching the loop's
/// pre-R14 "one in-flight mutating await at a time" behaviour. Distinct domains
/// stay independent (a ping and an inbox accept can run concurrently).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum DispatchDomain {
    /// Mediator change / manual reconnect — replaces the persona listener and
    /// waits for it to connect (up to 30 s).
    Mediator,
    /// Relationship-panel network actions: create (VTA round-trip + send), ping
    /// (`send_message_with_retry` ~6 s on a dead peer), remove (`remove_listener`).
    Relationship,
    /// Inbox network actions: accept/reject a relationship request, accept/reject
    /// a VRC request — all do a (retrying) DIDComm send.
    Inbox,
    /// Context-DID deletion: `delete_did_webvh` at the VTA + listener teardown.
    Did,
}

impl DispatchDomain {
    /// Human-readable label for the "already in progress" status message.
    fn label(self) -> &'static str {
        match self {
            DispatchDomain::Mediator => "Mediator reconnect",
            DispatchDomain::Relationship => "Relationship action",
            DispatchDomain::Inbox => "Inbox action",
            DispatchDomain::Did => "Identity deletion",
        }
    }
}

/// Per-domain in-flight guard: at most one background dispatch per
/// [`DispatchDomain`].
///
/// `try_begin` is the gate at every backgrounded call site — it returns `false`
/// (and the caller surfaces a status) when that domain is already busy. The loop
/// clears the flag in [`apply_outcome`] when the matching outcome arrives, so the
/// flag's lifetime brackets exactly the spawned task.
#[derive(Default)]
pub(crate) struct InFlight {
    domains: std::collections::HashSet<DispatchDomain>,
}

impl InFlight {
    /// Attempt to claim `domain`. Returns `true` if it was free (now marked
    /// busy); `false` if a dispatch is already in flight for it.
    pub(crate) fn try_begin(&mut self, domain: DispatchDomain) -> bool {
        self.domains.insert(domain)
    }

    /// Release `domain` once its outcome has been applied.
    pub(crate) fn finish(&mut self, domain: DispatchDomain) {
        self.domains.remove(&domain);
    }

    /// Whether `domain` currently has a dispatch in flight (for tests / status).
    #[cfg(test)]
    pub(crate) fn is_busy(&self, domain: DispatchDomain) -> bool {
        self.domains.contains(&domain)
    }

    /// Status message for a rejected start, e.g. when the user fires a second
    /// mediator reconnect while one is still connecting.
    pub(crate) fn busy_message(domain: DispatchDomain) -> String {
        format!("{} already in progress — please wait.", domain.label())
    }
}

/// The result of a backgrounded network dispatch, delivered into the runtime
/// select loop over an mpsc the loop owns. Each variant carries the I/O result
/// (data/errors only — never a `&mut State`); the loop applies it via
/// [`apply_outcome`], keeping all mutation on the loop thread.
///
/// R14 extends this enum (and [`apply_outcome`]) as it migrates the relationship
/// / inbox / settings / delete-DID dispatches onto the same channel.
pub(crate) enum DispatchOutcome {
    /// A mediator change / manual reconnect finished (success or failure). The
    /// payload is exactly the [`ReconnectOutcome`] the inline path produced, so
    /// the applied state is identical to the pre-R13 synchronous behaviour.
    MediatorReconnect(ReconnectOutcome),
    /// A relationship-panel network action (create / ping / remove) finished.
    /// The payload owns the send result plus the data the post-send config
    /// mutation needs; [`RelationshipOutcome::apply`] reproduces the old inline
    /// success/error block exactly.
    Relationship(RelationshipOutcome),
    /// An inbox network action (accept/reject relationship, accept/reject VRC)
    /// finished. [`InboxOutcome::apply`] reproduces the old inline block.
    Inbox(InboxOutcome),
    /// A context-DID deletion finished (VTA delete + listener teardown done in
    /// the task; local cleanup + save applied here).
    Did(DidDeleteOutcome),
    /// A spawned dispatch job panicked (or was cancelled) and so never produced a
    /// real outcome. Synthesised by [`spawn_dispatch`] from the `JoinError` so the
    /// domain's busy-flag is still cleared (a panicking job that sent nothing would
    /// otherwise leave its domain busy forever) and a generic failure status is
    /// surfaced. Carries the domain to release + label.
    Panicked(DispatchDomain),
}

impl DispatchOutcome {
    /// The domain whose busy-flag this outcome releases.
    fn domain(&self) -> DispatchDomain {
        match self {
            DispatchOutcome::MediatorReconnect(_) => DispatchDomain::Mediator,
            DispatchOutcome::Relationship(_) => DispatchDomain::Relationship,
            DispatchOutcome::Inbox(_) => DispatchDomain::Inbox,
            DispatchOutcome::Did(_) => DispatchDomain::Did,
            DispatchOutcome::Panicked(domain) => *domain,
        }
    }
}

/// Spawn a background dispatch job whose future resolves to a [`DispatchOutcome`],
/// delivering the result over `tx`. **Resilience guarantee:** if the job panics or
/// is cancelled it produces no outcome, which would leave `domain`'s busy-flag set
/// forever (every subsequent action on that domain rejected as "in progress").
/// This wrapper joins the inner task and, on a `JoinError`, synthesises a
/// [`DispatchOutcome::Panicked`] so `apply_outcome` always clears the flag.
pub(crate) fn spawn_dispatch<F>(
    tx: tokio::sync::mpsc::UnboundedSender<DispatchOutcome>,
    domain: DispatchDomain,
    fut: F,
) where
    F: std::future::Future<Output = DispatchOutcome> + Send + 'static,
{
    tokio::spawn(async move {
        let outcome = match tokio::spawn(fut).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(domain = ?domain, error = %e, "dispatch job panicked/cancelled");
                DispatchOutcome::Panicked(domain)
            }
        };
        let _ = tx.send(outcome);
    });
}

/// Apply a completed [`DispatchOutcome`] to `state` and clear the domain's
/// busy-flag. **Pure** over `(&mut State, &mut InFlight, outcome)` — no I/O — so
/// it is unit-testable and is the single place the loop's outcome arm mutates
/// from.
///
/// The mediator-reconnect arm reproduces, byte for byte, the status/log strings
/// the old inline `run_persona_reconnect` set on completion: the only observable
/// difference from before R13 is *when* it runs (after a responsive wait rather
/// than blocking the loop), not *what* it does.
///
/// R14 widens the signature to also take `&mut Config` + `profile`: unlike the
/// mediator reconnect (which mutates `State` only), the migrated relationship /
/// inbox / delete-DID paths persist config changes (the relationship record, the
/// task removal, the issued VRC) that today happen *after* the network send.
/// Doing them here — on the loop thread, only on success — preserves the
/// pre-R14 ordering and durability.
///
/// A send failure records an error status and creates no *task/record that the
/// old inline `Ok` branch would have created* — matching the pre-R14
/// `match … { Ok => persist, Err => status }`. It is not a literal no-op on
/// `Config`, and was never meant to be: it mirrors the in-memory state the old
/// inline path had reached *before* the send. Specifically, the relationship
/// Create path records the minted R-DID `key_info` on both success and failure
/// (key creation happened before the send pre-R14; only the success save
/// persists it), and removes the provisional `RequestSent` record it pre-inserted
/// (see [`RelationshipOutcome::apply`]) so a failed send leaves no relationship
/// record — exactly the pre-R14 net state.
pub(crate) fn apply_outcome(
    state: &mut State,
    config: &mut Config,
    profile: &str,
    in_flight: &mut InFlight,
    outcome: DispatchOutcome,
) {
    let domain = outcome.domain();
    match outcome {
        DispatchOutcome::MediatorReconnect(result) => match result {
            ReconnectOutcome::Connected => {
                state.connection.status = state::MediatorStatus::Connected;
                state.connection.messaging_active = true;
                state.main_page.log("Reconnected to mediator");
            }
            ReconnectOutcome::Failed(reason) => {
                state.connection.status = state::MediatorStatus::Failed(reason.clone());
                state.main_page.log(format!("Reconnect failed: {reason}"));
            }
        },
        DispatchOutcome::Relationship(outcome) => outcome.apply(state, config, profile),
        DispatchOutcome::Inbox(outcome) => outcome.apply(state, config, profile),
        DispatchOutcome::Did(outcome) => outcome.apply(state, config, profile),
        DispatchOutcome::Panicked(domain) => {
            // The job panicked and produced no real outcome. Surface a generic
            // failure so the user isn't left staring at a stuck "in progress"; the
            // busy-flag is cleared below (via `domain()`), freeing the domain.
            let msg = format!("{} failed (internal error)", domain.label());
            state.main_page.log(msg);
        }
    }
    in_flight.finish(domain);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;

    /// The busy-guard serialises per domain: the first claim succeeds, a second
    /// while in flight is rejected, and after `finish` the domain frees up
    /// again. This is the state machine that backs "a second action on a busy
    /// domain is rejected with a status, not queued blind".
    #[test]
    fn busy_guard_serialises_per_domain() {
        let mut in_flight = InFlight::default();

        // First claim succeeds and marks the domain busy.
        assert!(in_flight.try_begin(DispatchDomain::Mediator));
        assert!(in_flight.is_busy(DispatchDomain::Mediator));

        // A second claim while in flight is rejected (would be surfaced as a
        // status via `busy_message`).
        assert!(!in_flight.try_begin(DispatchDomain::Mediator));

        // Releasing frees the domain for the next dispatch.
        in_flight.finish(DispatchDomain::Mediator);
        assert!(!in_flight.is_busy(DispatchDomain::Mediator));
        assert!(in_flight.try_begin(DispatchDomain::Mediator));
    }

    /// The R14 domains (Relationship / Inbox / Did) each serialise independently:
    /// claiming one does not block another, but a re-claim of the same domain is
    /// rejected until it is `finish`ed. This backs the "one in-flight per domain"
    /// model for the migrated network dispatches.
    #[test]
    fn r14_domains_serialise_independently() {
        let mut in_flight = InFlight::default();
        for domain in [
            DispatchDomain::Relationship,
            DispatchDomain::Inbox,
            DispatchDomain::Did,
        ] {
            // Each domain is independent: claiming it succeeds regardless of the
            // others already being busy.
            assert!(in_flight.try_begin(domain), "{domain:?} should be free");
            // A second claim on the same domain is rejected while in flight.
            assert!(
                !in_flight.try_begin(domain),
                "{domain:?} second claim must be rejected"
            );
        }
        // All three are concurrently in flight without blocking each other.
        assert!(in_flight.is_busy(DispatchDomain::Relationship));
        assert!(in_flight.is_busy(DispatchDomain::Inbox));
        assert!(in_flight.is_busy(DispatchDomain::Did));
        // …and a Mediator dispatch is still independently available.
        assert!(in_flight.try_begin(DispatchDomain::Mediator));

        // Releasing one frees only that domain.
        in_flight.finish(DispatchDomain::Inbox);
        assert!(!in_flight.is_busy(DispatchDomain::Inbox));
        assert!(in_flight.is_busy(DispatchDomain::Relationship));
        assert!(in_flight.try_begin(DispatchDomain::Inbox));
    }

    /// Applying a `Connected` outcome reproduces the old inline success state
    /// (status + messaging flag + log line) and clears the busy-flag.
    #[test]
    fn apply_connected_outcome_sets_connected_and_clears_flag() {
        let mut state = State::default();
        let mut config = test_config();
        let mut in_flight = InFlight::default();
        assert!(in_flight.try_begin(DispatchDomain::Mediator));

        apply_outcome(
            &mut state,
            &mut config,
            "test",
            &mut in_flight,
            DispatchOutcome::MediatorReconnect(ReconnectOutcome::Connected),
        );

        assert!(matches!(
            state.connection.status,
            state::MediatorStatus::Connected
        ));
        assert!(state.connection.messaging_active);
        assert!(
            !in_flight.is_busy(DispatchDomain::Mediator),
            "busy-flag must be cleared once the outcome is applied"
        );
    }

    /// Applying a `Failed` outcome reproduces the old inline failure state
    /// (Failed status carrying the reason) and clears the busy-flag.
    #[test]
    fn apply_failed_outcome_sets_failed_and_clears_flag() {
        let mut state = State::default();
        let mut config = test_config();
        let mut in_flight = InFlight::default();
        assert!(in_flight.try_begin(DispatchDomain::Mediator));

        apply_outcome(
            &mut state,
            &mut config,
            "test",
            &mut in_flight,
            DispatchOutcome::MediatorReconnect(ReconnectOutcome::Failed("dead mediator".into())),
        );

        match &state.connection.status {
            state::MediatorStatus::Failed(reason) => assert_eq!(reason, "dead mediator"),
            other => panic!("expected Failed status, got {other:?}"),
        }
        assert!(!state.connection.messaging_active);
        assert!(!in_flight.is_busy(DispatchDomain::Mediator));
    }

    /// Applying a `Panicked` outcome clears the busy-flag (so the domain isn't
    /// stuck "in progress" forever) and surfaces a generic failure log line. This
    /// backs the Fix-3 resilience guarantee: a spawned job that panics still frees
    /// its domain.
    #[test]
    fn apply_panicked_outcome_clears_flag() {
        let mut state = State::default();
        let mut config = test_config();
        let mut in_flight = InFlight::default();
        assert!(in_flight.try_begin(DispatchDomain::Relationship));

        apply_outcome(
            &mut state,
            &mut config,
            "test",
            &mut in_flight,
            DispatchOutcome::Panicked(DispatchDomain::Relationship),
        );

        assert!(
            !in_flight.is_busy(DispatchDomain::Relationship),
            "a panicked job's domain must be freed, not left busy forever"
        );
    }

    /// `spawn_dispatch` converts a panicking job into a synthetic
    /// [`DispatchOutcome::Panicked`] for the right domain, rather than silently
    /// dropping the outcome (which would leave the domain busy forever).
    #[tokio::test]
    async fn spawn_dispatch_panic_yields_panicked_outcome() {
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::unbounded_channel::<DispatchOutcome>();
        spawn_dispatch(tx, DispatchDomain::Inbox, async {
            panic!("boom");
            #[allow(unreachable_code)]
            DispatchOutcome::Panicked(DispatchDomain::Inbox)
        });
        let outcome = rx.recv().await.expect("an outcome must be delivered");
        assert!(matches!(
            outcome,
            DispatchOutcome::Panicked(DispatchDomain::Inbox)
        ));
    }

    /// The busy message names the domain so the UI tells the user *what* is
    /// already running.
    #[test]
    fn busy_message_names_the_domain() {
        let msg = InFlight::busy_message(DispatchDomain::Mediator);
        assert!(msg.contains("Mediator reconnect"));
        assert!(msg.contains("in progress"));
    }

    /// The whole point of R13: a backgrounded dispatch must NOT block the select
    /// loop. This drives a miniature replica of the runtime loop's structure — an
    /// action channel and a dispatch-outcome channel selected together — and
    /// proves that while a (slow) dispatch is still in flight, an interleaved nav
    /// action (`MainPanelSwitch`) is processed and `Exit` is honoured.
    ///
    /// The "slow dispatch" is modelled by a oneshot we hold open: the outcome is
    /// only delivered after we have already observed the nav action take effect,
    /// so the loop demonstrably did real work mid-flight. (The production loop is
    /// not factored into a test-callable unit — see the coverage note in the
    /// PR — so this asserts the *pattern* with the same channel shapes.)
    #[tokio::test]
    async fn loop_processes_nav_and_exit_while_dispatch_in_flight() {
        use crate::state_handler::actions::Action;
        use crate::state_handler::main_page::MainPanel;
        use tokio::sync::mpsc;

        let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();
        let (dispatch_tx, mut dispatch_rx) = mpsc::unbounded_channel::<DispatchOutcome>();
        // The "in flight" dispatch: a task that only completes when we release it.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let mut state = State::default();
        let mut config = test_config();
        let mut in_flight = InFlight::default();

        // Begin a dispatch (busy-flag set) and spawn its "I/O" — it parks on the
        // oneshot, modelling the up-to-30 s `wait_connected` against a dead
        // mediator, then reports Connected.
        assert!(in_flight.try_begin(DispatchDomain::Mediator));
        let bg_tx = dispatch_tx.clone();
        tokio::spawn(async move {
            let _ = release_rx.await;
            let _ = bg_tx.send(DispatchOutcome::MediatorReconnect(
                ReconnectOutcome::Connected,
            ));
        });

        // Queue a nav action and then an Exit. Both must be serviced *before* the
        // dispatch completes (which can't happen until we send on `release_tx`).
        action_tx
            .send(Action::MainPanelSwitch(MainPanel::ContentPanel))
            .unwrap();
        action_tx.send(Action::Exit).unwrap();

        let mut nav_seen = false;
        // Run the replica select loop. The dispatch is still in flight the whole
        // time (we never release it inside the loop), proving the loop is live.
        // The loop breaks `true` once Exit is honoured.
        let exited = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => {
                    if crate::state_handler::handle_nav_action(&mut state, &action) {
                        nav_seen = true;
                        // The nav action took effect mid-flight while the
                        // dispatch is unmistakably still pending.
                        assert!(in_flight.is_busy(DispatchDomain::Mediator));
                        assert!(state.main_page.content_panel.selected);
                    } else if matches!(action, Action::Exit) {
                        break true;
                    }
                }
                Some(outcome) = dispatch_rx.recv() => {
                    apply_outcome(&mut state, &mut config, "test", &mut in_flight, outcome);
                }
            }
        };

        assert!(
            nav_seen,
            "nav action must be processed while dispatch in flight"
        );
        assert!(exited, "Exit must be honoured while dispatch in flight");
        assert!(
            in_flight.is_busy(DispatchDomain::Mediator),
            "dispatch was never released, so it is still in flight — the loop did \
             real work without waiting on it"
        );

        // Releasing now would deliver the outcome, but the loop already exited;
        // the point is proven. Drop the sender to avoid an unused warning.
        let _ = release_tx;
    }
}
