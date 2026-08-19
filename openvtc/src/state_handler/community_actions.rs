//! Community sends, off the loop thread (R14).
//!
//! Two verbs address a community directly: leaving it (`members/self-remove`)
//! and issuing it the reciprocal membership credential (`members/vmc`). Both
//! were awaited inline, and both send to a peer that may be exactly the thing
//! that has gone wrong — leaving a community whose VTC is unreachable is a
//! *likely* reason to leave it, and that is precisely when the send retries
//! longest.
//!
//! The post-send work differs in kind, which is why leaving needs more than the
//! shared apply path: a successful leave also tears down that community's
//! messaging session, and the session manager lives in the runtime loop. The
//! outcome therefore *reports* the teardown it needs — `apply` returns the
//! community to deregister — and the runtime loop performs it. The degraded
//! loop has no sessions to tear down and ignores the answer.

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;

/// Which document a job sends to the community.
pub(crate) enum Verb {
    /// `members/self-remove` — leave. On success the membership is marked Left
    /// and its session torn down; the community's receipt is advisory.
    Leave,
    /// `members/vmc` — issue the reciprocal membership credential, signed by the
    /// member.
    IssueVmc { signing_secret: Box<Secret> },
}

/// Everything the send needs, resolved on the loop thread.
pub(crate) struct CommunityJob {
    pub(crate) atm: ATM,
    pub(crate) profile: Arc<ATMProfile>,
    pub(crate) member_did: String,
    pub(crate) mediator: String,
    pub(crate) vtc_did: String,
    pub(crate) persona: PersonaId,
    pub(crate) verb: Verb,
}

impl CommunityJob {
    /// Do the send. I/O only.
    pub(crate) async fn run(self) -> CommunityOutcome {
        let leaving = matches!(self.verb, Verb::Leave);
        let result = match &self.verb {
            Verb::Leave => openvtc_core::join::submit_self_remove(
                &self.atm,
                &self.profile,
                &self.member_did,
                &self.vtc_did,
                &self.mediator,
                None,
            )
            .await
            .map(|_| ()),
            Verb::IssueVmc { signing_secret } => openvtc_core::members::issue_and_send_member_vmc(
                &self.atm,
                &self.profile,
                signing_secret,
                &self.member_did,
                &self.vtc_did,
                &self.mediator,
            )
            .await
            .map(|_| ()),
        };
        CommunityOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            leaving,
            error: result.err().map(|e| format!("{e}")),
        }
    }
}

/// What the send did. Data only; applied on the loop thread.
pub(crate) struct CommunityOutcome {
    vtc_did: String,
    persona: PersonaId,
    /// `true` for a leave, whose success also changes the membership record.
    leaving: bool,
    error: Option<String>,
}

impl CommunityOutcome {
    /// Apply the record change and the status line, and say whether the loop
    /// still owes this community a session teardown.
    ///
    /// The teardown is reported rather than done because the session manager and
    /// the messaging service belong to the runtime loop, and this runs from the
    /// shared apply path that both loops call.
    pub(crate) fn apply(
        self,
        state: &mut State,
        config: &mut Config,
        save: &mut SaveScheduler,
    ) -> Option<(String, PersonaId)> {
        // Set through a local rather than a long-lived `&mut` into `state`:
        // two of the arms also want to log, which needs `main_page` again.
        fn status(state: &mut State, msg: String) {
            state.main_page.content_panel.communities.status_message = Some(msg);
        }
        match (self.error, self.leaving) {
            (None, true) => {
                // The record moves on the send, not on a receipt: the community's
                // acknowledgement is advisory, and a member who has announced a
                // departure should not still be shown as a member if it never
                // answers.
                if let Some(c) = config.account.membership_mut(&self.vtc_did, self.persona) {
                    c.leave();
                }
                save.mark_dirty();
                status(state, "Left the community.".to_string());
                state.main_page.sync_from_config(config);
                return Some((self.vtc_did, self.persona));
            }
            (None, false) => {
                status(
                    state,
                    "Membership credential issued and sent to the community.".to_string(),
                );
            }
            (Some(e), true) => {
                state.main_page.log_error("Leave failed", e.as_str());
                status(state, format!("Couldn't leave: {e}"));
            }
            (Some(e), false) => {
                state
                    .main_page
                    .log_error("Issue membership credential failed", e.as_str());
                status(
                    state,
                    format!("Couldn't issue the membership credential: {e}"),
                );
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;

    const VTC: &str = "did:webvh:QmScidCommunity:example.com:acme";

    fn outcome(leaving: bool, error: Option<&str>) -> CommunityOutcome {
        CommunityOutcome {
            vtc_did: VTC.to_string(),
            persona: PersonaId(uuid::Uuid::nil()),
            leaving,
            error: error.map(ToString::to_string),
        }
    }

    /// A successful leave asks the loop to tear the session down. Nothing else
    /// can: the session manager is not reachable from the shared apply path.
    #[test]
    fn a_successful_leave_asks_for_a_session_teardown() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister = outcome(true, None).apply(&mut state, &mut config, &mut save);

        assert_eq!(deregister.map(|(v, _)| v).as_deref(), Some(VTC));
        assert!(save.is_pending(), "the record change must be persisted");
    }

    /// A *failed* leave must not tear anything down — the membership is still
    /// live, and the session is what would carry a retry.
    #[test]
    fn a_failed_leave_keeps_the_session() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister =
            outcome(true, Some("peer unreachable")).apply(&mut state, &mut config, &mut save);

        assert!(deregister.is_none());
        assert!(
            state
                .main_page
                .content_panel
                .communities
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("Couldn't leave")),
        );
    }

    /// Issuing a credential never touches the session or the record — it is a
    /// send with a status line.
    #[test]
    fn issuing_a_credential_touches_neither_session_nor_record() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister = outcome(false, None).apply(&mut state, &mut config, &mut save);

        assert!(deregister.is_none());
        assert!(!save.is_pending(), "nothing to persist");
        assert!(
            state
                .main_page
                .content_panel
                .communities
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("issued")),
        );
    }

    /// A failed issue reports why, and still changes nothing.
    #[test]
    fn a_failed_issue_reports_the_reason() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister =
            outcome(false, Some("vault refused")).apply(&mut state, &mut config, &mut save);

        assert!(deregister.is_none());
        assert!(
            state
                .main_page
                .activity_log
                .iter()
                .any(|e| e.summary.contains("vault refused")),
        );
    }
}
