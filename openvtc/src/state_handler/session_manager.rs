//! Supervised multi-session manager (D11/D15).
//!
//! Each Active/Pending community needs a live DIDComm session so it can send and
//! receive. A community presents a *persona*, and because the DIDComm layer keys
//! connections by DID, a **reused** persona (D1) serves several communities over
//! **one shared connection** — so the unit of a "session" is the persona, not the
//! community (mirrors [`openvtc_core::identity::IdentityRegistry::sessions`]).
//!
//! This manager is the app-level **coordinator** over the messaging layer: it owns
//! the registry of live persona-sessions, their per-session connection status, a
//! bounded maximum number of concurrent sessions, and the register/deregister
//! bookkeeping for join/leave. The actual connect / restart / recovery I/O stays
//! in the SDK `DIDCommService`, which already supervises each listener
//! independently (per-listener restart policy) — a mediator outage on one session
//! is contained by the SDK and reflected here as that session's status, never
//! affecting the others.
//!
//! It is **pure bookkeeping** (no I/O, no SDK types) so it is unit-testable with
//! simulated sessions without a live mediator. The runtime loop turns its
//! decisions into `DIDCommService` `add_listener`/`remove_listener` calls and
//! feeds `ListenerEvent`s back into [`SessionManager::mark_connected`] etc.

use std::collections::{BTreeSet, HashMap};

use openvtc_core::config::account::{PersonaId, VtcDid};

/// Default bound on concurrently live persona-sessions — a backstop against
/// unbounded fan-out (D15). Generous relative to any realistic number of joined
/// communities; the cap exists so a runaway never opens an unbounded number of
/// mediator connections at once.
pub const DEFAULT_MAX_SESSIONS: usize = 32;

/// Connection status of a single persona-session, driven by `ListenerEvent`s.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum SessionStatus {
    /// Registered; the listener is being brought up (or retrying after a drop).
    #[default]
    Connecting,
    /// The listener is connected to its mediator — the session is live.
    Connected,
    /// The listener reported a failure. The SDK keeps retrying per its restart
    /// policy; this records the last reason for display. Recovery flips it back
    /// to `Connecting` then `Connected` on the next attempt.
    Failed(String),
    /// The listener cleanly disconnected (e.g. teardown in progress).
    Disconnected,
}

impl SessionStatus {
    /// Whether this session is currently live.
    pub fn is_connected(&self) -> bool {
        matches!(self, SessionStatus::Connected)
    }
}

/// One supervised persona-session: a single DIDComm listener serving every
/// community that presents this persona. Keyed by [`PersonaId`] in the manager.
#[derive(Clone, Debug)]
pub struct Session {
    /// The DIDComm listener id this session owns (opaque; derived by the caller).
    /// Returned by [`SessionManager::deregister`] so the caller can tear it down.
    pub listener_id: String,
    /// The communities this one session serves (≥1 while registered).
    pub communities: BTreeSet<VtcDid>,
    /// Current connection status, driven by `ListenerEvent`s.
    pub status: SessionStatus,
}

/// Outcome of [`SessionManager::register`], telling the caller what I/O to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// A new session was created — the caller must `add_listener` for it.
    Created,
    /// The persona already had a session (reused persona, D1); the community was
    /// attached to it. No new listener — the existing connection is shared.
    JoinedExisting,
    /// The bounded-concurrency cap is reached and this persona had no session;
    /// nothing was registered. The caller surfaces this rather than opening an
    /// unbounded number of connections (D15).
    AtCapacity,
}

/// The app-level registry of live persona-sessions (D11/D15). See module docs.
#[derive(Clone, Debug)]
pub struct SessionManager {
    sessions: HashMap<PersonaId, Session>,
    max_sessions: usize,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SESSIONS)
    }
}

impl SessionManager {
    /// A manager bounded to at most `max_sessions` concurrent persona-sessions.
    pub fn new(max_sessions: usize) -> Self {
        SessionManager {
            sessions: HashMap::new(),
            max_sessions: max_sessions.max(1),
        }
    }

    /// Register that `vtc` (a community) needs `persona`'s live session.
    ///
    /// If the persona already has a session (a reused persona serving multiple
    /// communities, D1), `vtc` is attached to it and [`RegisterOutcome::JoinedExisting`]
    /// is returned — no new listener. Otherwise a fresh `Connecting` session is
    /// created ([`RegisterOutcome::Created`]) unless the bounded-concurrency cap
    /// is hit ([`RegisterOutcome::AtCapacity`]). Partial-failure-tolerant: each
    /// call is independent, so a launch loop registering many communities tolerates
    /// any single one being at capacity without aborting the rest.
    pub fn register(
        &mut self,
        persona: PersonaId,
        listener_id: &str,
        vtc: VtcDid,
    ) -> RegisterOutcome {
        if let Some(session) = self.sessions.get_mut(&persona) {
            session.communities.insert(vtc);
            return RegisterOutcome::JoinedExisting;
        }
        if self.sessions.len() >= self.max_sessions {
            return RegisterOutcome::AtCapacity;
        }
        let mut communities = BTreeSet::new();
        communities.insert(vtc);
        self.sessions.insert(
            persona,
            Session {
                listener_id: listener_id.to_string(),
                communities,
                status: SessionStatus::Connecting,
            },
        );
        RegisterOutcome::Created
    }

    /// Deregister `vtc` from `persona`'s session.
    ///
    /// Removes `vtc` from that persona's session. If the session now serves no
    /// communities, it is removed and returned so the caller can tear down its
    /// listener; otherwise (the persona still serves other communities) `None` is
    /// returned and the shared connection stays up. Taking the persona explicitly
    /// is required for multi-membership: two personas may both serve the same VTC,
    /// so the VTC alone no longer identifies the session.
    pub fn deregister(&mut self, persona: PersonaId, vtc: &str) -> Option<Session> {
        let session = self.sessions.get_mut(&persona)?;
        session.communities.remove(vtc);
        if session.communities.is_empty() {
            self.sessions.remove(&persona)
        } else {
            None
        }
    }

    /// Mark the session owning `listener_id` Connected. Returns `true` if a
    /// session matched and its status changed.
    pub fn mark_connected(&mut self, listener_id: &str) -> bool {
        self.set_status(listener_id, SessionStatus::Connected)
    }

    /// Mark the session owning `listener_id` Disconnected (clean teardown / drop;
    /// the SDK will retry per its restart policy). Returns `true` on a change.
    pub fn mark_disconnected(&mut self, listener_id: &str) -> bool {
        self.set_status(listener_id, SessionStatus::Disconnected)
    }

    /// Mark the session owning `listener_id` Failed with `reason`. The SDK keeps
    /// retrying; this records the reason for display. Returns `true` on a change.
    pub fn mark_failed(&mut self, listener_id: &str, reason: impl Into<String>) -> bool {
        self.set_status(listener_id, SessionStatus::Failed(reason.into()))
    }

    fn set_status(&mut self, listener_id: &str, status: SessionStatus) -> bool {
        if let Some(session) = self
            .sessions
            .values_mut()
            .find(|s| s.listener_id == listener_id)
            && session.status != status
        {
            session.status = status;
            return true;
        }
        false
    }

    /// Whether any session is currently connected — the aggregate that drives the
    /// global "messaging active" indicator while per-session status exists too.
    pub fn any_connected(&self) -> bool {
        self.sessions.values().any(|s| s.status.is_connected())
    }

    /// Number of live persona-sessions (≤ the bound).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// The bounded maximum number of concurrent sessions (D15).
    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PersonaId {
        PersonaId::new()
    }

    // Tests access the private `sessions` map directly (same module) to inspect
    // per-session status without a public accessor.
    #[test]
    fn register_creates_one_session_per_persona_and_shares_reused_personas() {
        let mut mgr = SessionManager::new(8);
        let a = pid();
        let b = pid();

        // Two distinct personas → two sessions, each needing its own listener.
        assert_eq!(
            mgr.register(a, "lid-a", "vtc-1".into()),
            RegisterOutcome::Created
        );
        assert_eq!(
            mgr.register(b, "lid-b", "vtc-2".into()),
            RegisterOutcome::Created
        );
        assert_eq!(mgr.session_count(), 2);

        // A third community presenting persona A reuses A's session (D1) — no new
        // listener, still two sessions.
        assert_eq!(
            mgr.register(a, "lid-a", "vtc-3".into()),
            RegisterOutcome::JoinedExisting
        );
        assert_eq!(mgr.session_count(), 2);
        assert_eq!(mgr.sessions[&a].communities.len(), 2);
    }

    #[test]
    fn bounded_concurrency_rejects_beyond_the_cap() {
        let mut mgr = SessionManager::new(2);
        assert_eq!(
            mgr.register(pid(), "lid-a", "vtc-1".into()),
            RegisterOutcome::Created
        );
        assert_eq!(
            mgr.register(pid(), "lid-b", "vtc-2".into()),
            RegisterOutcome::Created
        );
        // A third *distinct* persona exceeds the bound and is rejected.
        assert_eq!(
            mgr.register(pid(), "lid-c", "vtc-3".into()),
            RegisterOutcome::AtCapacity
        );
        assert_eq!(mgr.session_count(), 2);
    }

    #[test]
    fn status_is_isolated_per_session_recovery_and_failure_dont_cross() {
        let mut mgr = SessionManager::new(8);
        let a = pid();
        let b = pid();
        mgr.register(a, "lid-a", "vtc-1".into());
        mgr.register(b, "lid-b", "vtc-2".into());

        // Both start Connecting; nothing is connected yet.
        assert!(!mgr.any_connected());

        // A connects; B is untouched (isolation).
        assert!(mgr.mark_connected("lid-a"));
        assert!(mgr.sessions[&a].status.is_connected());
        assert_eq!(mgr.sessions[&b].status, SessionStatus::Connecting);
        assert!(mgr.any_connected());

        // B fails (its mediator is down); A stays connected — one failing session
        // does not affect another (D15).
        assert!(mgr.mark_failed("lid-b", "mediator down"));
        assert_eq!(
            mgr.sessions[&b].status,
            SessionStatus::Failed("mediator down".to_string())
        );
        assert!(mgr.sessions[&a].status.is_connected());
        assert!(mgr.any_connected());

        // B recovers on the SDK's next retry: drop → reconnect.
        assert!(mgr.mark_disconnected("lid-b"));
        assert!(mgr.mark_connected("lid-b"));
        assert!(mgr.sessions[&b].status.is_connected());
        // Idempotent: marking the same status again is not a change.
        assert!(!mgr.mark_connected("lid-b"));

        // An event for an unknown listener matches nothing.
        assert!(!mgr.mark_connected("lid-unknown"));
    }

    #[test]
    fn deregister_drops_listener_only_when_no_community_remains() {
        let mut mgr = SessionManager::new(8);
        let a = pid();
        // Persona A serves two communities over one shared session.
        mgr.register(a, "lid-a", "vtc-1".into());
        mgr.register(a, "lid-a", "vtc-2".into());
        mgr.mark_connected("lid-a");

        // Leaving the first community keeps the session up (still serves vtc-2).
        assert!(mgr.deregister(a, "vtc-1").is_none());
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.sessions[&a].status.is_connected());

        // Leaving the last one tears the session down — returned for listener
        // teardown by the caller.
        let removed = mgr.deregister(a, "vtc-2").expect("session removed");
        assert_eq!(removed.listener_id, "lid-a");
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.any_connected());

        // Deregistering something unknown is a harmless no-op.
        assert!(mgr.deregister(a, "vtc-unknown").is_none());
    }
}
