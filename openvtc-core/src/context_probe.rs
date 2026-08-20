//! Ask a Trust Context what is already in it, before setup writes to it.
//!
//! # Why setup asks
//!
//! Setup takes a VTA DID and a context id, authenticates, and starts creating
//! things. It has never checked whether that context already contains an
//! account — so pointing a fresh install at a context you already use silently
//! mints a *second* set of personas alongside the first, and pointing it at a
//! colleague's context is indistinguishable from a typo until much later.
//!
//! The moment setup holds an authenticated client it can simply look. Three
//! list calls answer it, and all three already exist — no VTA change (D5, D6).
//!
//! # What it does not do
//!
//! It does not rebuild anything. Recovering an existing context needs the
//! rebuild path (§6 of the spec) and the application-state store behind it;
//! until those land, knowing the context is occupied is itself the useful
//! answer, because it is the difference between a deliberate choice and a
//! silent collision.
//!
//! Every call is best-effort. A VTA that refuses one of these listings, or a
//! context the caller cannot enumerate, yields an [`Unknown`](ProbeOutcome)
//! rather than blocking setup: the probe exists to inform a decision, and
//! failing to inform it must not prevent making it.

use serde::{Deserialize, Serialize};
use tracing::debug;
use vta_sdk::client::VtaClient;

/// What a probe found in a Trust Context.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextContents {
    /// `did:webvh` identities the VTA holds for this context — the personas of
    /// whatever account already lives here.
    pub persona_dids: Vec<String>,
    /// Credentials in the account's vault (VICs, VMCs, VRCs).
    pub credential_count: usize,
    /// Sub-contexts beneath this one — one per community joined, by convention.
    pub sub_context_count: usize,
}

impl ContextContents {
    /// True when the context holds nothing OpenVTC would recognise as an
    /// existing account.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.persona_dids.is_empty() && self.credential_count == 0 && self.sub_context_count == 0
    }

    /// A concrete one-line summary (D7).
    ///
    /// Deliberately counts rather than saying "existing content found": the
    /// user is deciding whether this is *their* account, and needs enough
    /// detail to tell. "3 personas and 14 credentials" is recognisable;
    /// "content found" is not.
    #[must_use]
    pub fn summary(&self) -> String {
        fn plural(n: usize, one: &str, many: &str) -> String {
            format!("{n} {}", if n == 1 { one } else { many })
        }

        let mut parts = Vec::new();
        if !self.persona_dids.is_empty() {
            parts.push(plural(self.persona_dids.len(), "persona", "personas"));
        }
        if self.sub_context_count > 0 {
            parts.push(plural(
                self.sub_context_count,
                "sub-context",
                "sub-contexts",
            ));
        }
        if self.credential_count > 0 {
            parts.push(plural(self.credential_count, "credential", "credentials"));
        }

        match parts.len() {
            0 => "nothing".to_string(),
            1 => parts.remove(0),
            _ => {
                let last = parts.pop().expect("len >= 2");
                format!("{} and {last}", parts.join(", "))
            }
        }
    }
}

/// The result of asking. Separate from `Result` because "we could not tell" is
/// a distinct answer from "it is empty", and conflating them is exactly how a
/// probe turns into a silent collision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The context is empty — a genuine first run. Setup continues unchanged.
    Empty,
    /// The context already holds an account.
    Occupied(Box<ContextContents>),
    /// The VTA would not say. The string is its own message.
    Unknown(String),
}

impl ProbeOutcome {
    /// The contents, if the context was occupied.
    #[must_use]
    pub fn contents(&self) -> Option<&ContextContents> {
        match self {
            ProbeOutcome::Occupied(c) => Some(c),
            _ => None,
        }
    }

    /// Whether setup should stop and ask before writing to this context.
    #[must_use]
    pub fn needs_confirmation(&self) -> bool {
        matches!(self, ProbeOutcome::Occupied(_))
    }
}

/// Ask `context_id` what it already contains.
///
/// Read-only, and cheap — three list calls against a context we have just
/// authenticated to (D6). Runs on every setup rather than behind a flag,
/// because a user who needs the answer is by definition not expecting to.
pub async fn probe(client: &VtaClient, context_id: &str) -> ProbeOutcome {
    let dids = match client.list_dids_webvh(Some(context_id), None).await {
        Ok(body) => body.dids,
        Err(e) => {
            // The listing OpenVTC most depends on. If this one is refused the
            // probe cannot claim the context is empty, so it says so.
            return ProbeOutcome::Unknown(format!("could not list DIDs in {context_id}: {e}"));
        }
    };

    // The other two are enrichment: they sharpen the summary but their absence
    // does not change whether the context is occupied, so a failure here is
    // logged and counted as zero rather than downgrading the whole answer.
    let credential_count = match client.cred_vault_query(serde_json::json!({})).await {
        Ok(v) => count_array(&v, &["credentials", "items", "results"]),
        Err(e) => {
            debug!("credential vault not enumerable during probe: {e}");
            0
        }
    };

    let sub_context_count = match client.list_contexts().await {
        Ok(resp) => resp
            .contexts
            .iter()
            .filter(|c| is_sub_context_of(&c.id, context_id))
            .count(),
        Err(e) => {
            debug!("contexts not enumerable during probe: {e}");
            0
        }
    };

    let contents = ContextContents {
        persona_dids: dids.into_iter().map(|d| d.did).collect(),
        credential_count,
        sub_context_count,
    };

    if contents.is_empty() {
        ProbeOutcome::Empty
    } else {
        ProbeOutcome::Occupied(Box::new(contents))
    }
}

/// Count the array under whichever of `keys` the response actually used.
///
/// The vault listing is returned untyped and the envelope key has moved before;
/// trying the plausible names beats hard-coding one and silently reporting zero
/// credentials on a full vault.
fn count_array(value: &serde_json::Value, keys: &[&str]) -> usize {
    if let Some(arr) = value.as_array() {
        return arr.len();
    }
    keys.iter()
        .find_map(|k| value.get(*k).and_then(|v| v.as_array()))
        .map_or(0, Vec::len)
}

/// Whether `candidate` is a context *beneath* `parent`, not `parent` itself.
///
/// Sub-contexts are `<parent>/<slug>` by convention, so a prefix test needs the
/// separator or `openvtc-2` would count as a child of `openvtc`.
fn is_sub_context_of(candidate: &str, parent: &str) -> bool {
    candidate
        .strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents(personas: usize, creds: usize, subs: usize) -> ContextContents {
        ContextContents {
            persona_dids: (0..personas)
                .map(|i| format!("did:webvh:Qm:example.com:p{i}"))
                .collect(),
            credential_count: creds,
            sub_context_count: subs,
        }
    }

    #[test]
    fn an_empty_context_is_empty() {
        assert!(ContextContents::default().is_empty());
    }

    #[test]
    fn any_single_signal_makes_it_occupied() {
        assert!(!contents(1, 0, 0).is_empty());
        assert!(!contents(0, 1, 0).is_empty());
        assert!(!contents(0, 0, 1).is_empty());
    }

    /// D7 — the summary must be concrete enough that a user can tell whether
    /// this is *their* account.
    #[test]
    fn the_summary_counts_rather_than_gesturing() {
        assert_eq!(
            contents(3, 14, 2).summary(),
            "3 personas, 2 sub-contexts and 14 credentials"
        );
    }

    #[test]
    fn the_summary_is_singular_when_it_should_be() {
        assert_eq!(
            contents(1, 1, 1).summary(),
            "1 persona, 1 sub-context and 1 credential"
        );
    }

    #[test]
    fn the_summary_omits_what_is_absent() {
        assert_eq!(contents(2, 0, 0).summary(), "2 personas");
        assert_eq!(contents(0, 5, 0).summary(), "5 credentials");
    }

    /// "We could not tell" must never read as "it is empty" — that conflation
    /// is exactly the silent collision the probe exists to prevent.
    #[test]
    fn unknown_is_not_empty_and_does_not_gate_setup() {
        let unknown = ProbeOutcome::Unknown("refused".to_string());
        assert!(!unknown.needs_confirmation());
        assert!(unknown.contents().is_none());
        assert_ne!(unknown, ProbeOutcome::Empty);
    }

    #[test]
    fn only_an_occupied_context_stops_setup() {
        assert!(!ProbeOutcome::Empty.needs_confirmation());
        assert!(ProbeOutcome::Occupied(Box::new(contents(1, 0, 0))).needs_confirmation());
    }

    /// A sibling context must not be counted as a child, or every account on a
    /// shared VTA would look occupied.
    #[test]
    fn sub_context_matching_requires_the_separator() {
        assert!(is_sub_context_of("openvtc/acme", "openvtc"));
        assert!(!is_sub_context_of("openvtc", "openvtc"));
        assert!(!is_sub_context_of("openvtc-2", "openvtc"));
        assert!(!is_sub_context_of("openvtc/", "openvtc"));
        assert!(!is_sub_context_of("other/acme", "openvtc"));
    }

    /// The vault envelope is untyped and its key has moved before. Reporting
    /// zero credentials on a full vault would make the summary lie.
    #[test]
    fn the_credential_count_tolerates_the_envelope_key_moving() {
        let keys = ["credentials", "items", "results"];
        for key in keys {
            let v = serde_json::json!({ key: [1, 2, 3] });
            assert_eq!(count_array(&v, &keys), 3, "key {key}");
        }
        // A bare array, and an envelope we do not recognise.
        assert_eq!(count_array(&serde_json::json!([1, 2]), &keys), 2);
        assert_eq!(count_array(&serde_json::json!({ "nope": [1] }), &keys), 0);
    }
}
