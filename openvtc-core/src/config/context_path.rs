/*!
 * Context-path hierarchy convention (D2 / D9).
 *
 * The single source of truth for the `<top>/<slug>` sub-context naming scheme.
 * A community's VTA sub-context id is derived from the account's top context and
 * the community's display name (slugged), with a collision-suffix rule and a
 * stable DID-derived fallback when no usable name is available.
 *
 * Isolating the convention here (D2) means a later move to a real VTA
 * `parent_id` API changes only this module and the `create_context` call sites,
 * not every consumer. Per `CLAUDE.md`, the no-name fallback derives its token
 * from the VTC `did:webvh` via `didwebvh-rs` rather than hand-rolled string
 * surgery.
 */

use crate::errors::OpenVTCError;
use didwebvh_rs::url::WebVHURL;

/// Maximum length of a slug component (D9).
const MAX_SLUG_LEN: usize = 32;
/// Number of leading SCID characters kept for the no-name fallback token.
const FALLBACK_TOKEN_LEN: usize = 12;

/// Slugify a community display name per D9.
///
/// Lowercases the name, keeps `[a-z0-9]`, collapses every run of other
/// characters (including spaces, punctuation, and `-`) to a single `-`, trims
/// leading/trailing `-`, and caps the result at [`MAX_SLUG_LEN`] characters.
/// Returns an empty string when nothing usable remains (e.g. a name with no
/// ASCII alphanumerics) — callers fall back to [`fallback_token`].
pub fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(MAX_SLUG_LEN));
    let mut pending_dash = false;
    for c in name.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_lowercase() || lc.is_ascii_digit() {
            // A separator was pending and we have real content on both sides —
            // emit a single joining dash.
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(lc);
            if out.len() >= MAX_SLUG_LEN {
                break;
            }
        } else {
            // Any non-alphanumeric (including `-`) collapses to one dash, but we
            // only commit it once we know real content follows (avoids leading
            // and trailing dashes).
            pending_dash = true;
        }
    }
    out
}

/// A short, stable token derived from a VTC `did:webvh` via `didwebvh-rs`.
///
/// Used as the slug when a community has no usable display name (D9). The token
/// is the lowercased, alphanumeric-only prefix of the DID's SCID — stable for a
/// given DID and safe as a context-path component.
///
/// # Errors
///
/// Returns an error if `vtc_did` is not a parseable `did:webvh` or its SCID
/// yields no usable characters.
pub fn fallback_token(vtc_did: &str) -> Result<String, OpenVTCError> {
    let parsed = WebVHURL::parse_did_url(vtc_did)
        .map_err(|e| OpenVTCError::Config(format!("Invalid VTC did:webvh ({vtc_did}): {e}")))?;
    let token: String = parsed
        .scid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .take(FALLBACK_TOKEN_LEN)
        .collect();
    if token.is_empty() {
        return Err(OpenVTCError::Config(format!(
            "VTC DID has no usable SCID for a context token: {vtc_did}"
        )));
    }
    Ok(token)
}

/// Build a `<top>/<slug>` sub-context id for a community (D9).
///
/// The slug is [`slugify`]'d from `display_name`, or [`fallback_token`]'d from
/// `vtc_did` when the name is absent/empty/unusable. `is_taken` reports whether
/// a candidate id already exists under the top context; on collision the slug
/// gains a `-2`, `-3`, … suffix until it is unique.
///
/// # Errors
///
/// Returns an error only when the fallback token is needed and `vtc_did` is not
/// a usable `did:webvh`.
pub fn build_sub_context_id(
    top_context_id: &str,
    display_name: Option<&str>,
    vtc_did: &str,
    is_taken: impl Fn(&str) -> bool,
) -> Result<String, OpenVTCError> {
    let base = match display_name.map(slugify) {
        Some(slug) if !slug.is_empty() => slug,
        _ => fallback_token(vtc_did)?,
    };

    let mut candidate = format!("{top_context_id}/{base}");
    let mut n = 2u32;
    while is_taken(&candidate) {
        candidate = format!("{top_context_id}/{base}-{n}");
        n += 1;
    }
    Ok(candidate)
}

/// Split a `<top>/<slug>` id into `(top, slug)`.
///
/// The top context may itself contain `/` (nested), so the split is on the last
/// `/`. Returns `None` for an id with no `/` (not a sub-context id).
pub fn parse_sub_context_id(id: &str) -> Option<(&str, &str)> {
    id.rsplit_once('/')
}

/// The display form of a sub-context id: its slug (the final path segment), or
/// the whole string when it has no `/`.
pub fn render_for_display(id: &str) -> &str {
    id.rsplit_once('/').map_or(id, |(_, slug)| slug)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn slugify_basic_lowercasing_and_separators() {
        assert_eq!(slugify("Acme Corp"), "acme-corp");
        assert_eq!(slugify("ACME"), "acme");
        assert_eq!(slugify("Foo123"), "foo123");
    }

    #[test]
    fn slugify_collapses_runs_and_trims() {
        assert_eq!(slugify("  Hello,   World!!  "), "hello-world");
        assert_eq!(slugify("a___b---c"), "a-b-c");
        assert_eq!(slugify("--leading and trailing--"), "leading-and-trailing");
        assert_eq!(slugify("a - b"), "a-b");
    }

    #[test]
    fn slugify_strips_non_ascii_and_handles_empty() {
        assert_eq!(slugify(""), "");
        assert_eq!(slugify("!!!"), "");
        // Non-ASCII letters are treated as separators (collapsed to dashes).
        assert_eq!(slugify("café münchen"), "caf-m-nchen");
    }

    #[test]
    fn slugify_caps_at_max_len() {
        let long = "a".repeat(100);
        assert_eq!(slugify(&long).len(), MAX_SLUG_LEN);
    }

    #[test]
    fn fallback_token_is_stable_and_clean() {
        let did = "did:webvh:zQmTestScidValue:example.com";
        let t1 = fallback_token(did).unwrap();
        let t2 = fallback_token(did).unwrap();
        assert_eq!(t1, t2, "fallback token must be stable for a given DID");
        assert!(!t1.is_empty());
        assert!(t1.len() <= FALLBACK_TOKEN_LEN);
        assert!(
            t1.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "token must be a clean slug component, got {t1}"
        );
    }

    #[test]
    fn fallback_token_rejects_non_webvh() {
        assert!(fallback_token("did:key:z6Mk").is_err());
        assert!(fallback_token("not-a-did").is_err());
    }

    #[test]
    fn build_uses_slug_under_top() {
        let taken = HashSet::<String>::new();
        let id = build_sub_context_id(
            "openvtc",
            Some("Acme Corp"),
            "did:webvh:zScid:example.com",
            |c| taken.contains(c),
        )
        .unwrap();
        assert_eq!(id, "openvtc/acme-corp");
    }

    #[test]
    fn build_falls_back_to_did_token_when_no_name() {
        let taken = HashSet::<String>::new();
        let did = "did:webvh:zQmTestScidValue:example.com";
        let expected = format!("openvtc/{}", fallback_token(did).unwrap());
        for name in [None, Some(""), Some("   "), Some("!!!")] {
            let id = build_sub_context_id("openvtc", name, did, |c| taken.contains(c)).unwrap();
            assert_eq!(id, expected, "name {name:?} should fall back to DID token");
        }
    }

    #[test]
    fn build_suffixes_on_collision() {
        let mut taken = HashSet::new();
        taken.insert("openvtc/acme".to_string());
        taken.insert("openvtc/acme-2".to_string());
        let id = build_sub_context_id(
            "openvtc",
            Some("ACME"),
            "did:webvh:zScid:example.com",
            |c| taken.contains(c),
        )
        .unwrap();
        assert_eq!(id, "openvtc/acme-3");
    }

    #[test]
    fn parse_and_render_round_trip() {
        assert_eq!(
            parse_sub_context_id("openvtc/acme"),
            Some(("openvtc", "acme"))
        );
        // Nested top context: split on the last slash.
        assert_eq!(
            parse_sub_context_id("org/openvtc/acme"),
            Some(("org/openvtc", "acme"))
        );
        assert_eq!(parse_sub_context_id("openvtc"), None);

        assert_eq!(render_for_display("openvtc/acme"), "acme");
        assert_eq!(render_for_display("org/openvtc/acme"), "acme");
        assert_eq!(render_for_display("openvtc"), "openvtc");
    }
}
