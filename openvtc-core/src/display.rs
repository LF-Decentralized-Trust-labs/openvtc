//! Display helpers for DIDs and other long identifiers shown in logs
//! and UI surfaces. Pure functions, no UI deps — both the TUI and any
//! future tooling can share these so we don't grow yet another local
//! "truncate this string" implementation per call site.

use std::borrow::Cow;

/// Tail-truncate `did` to at most `max_len` bytes, replacing the dropped
/// suffix with `...`. Returns the input borrowed when it already fits, so
/// the common no-truncation case avoids an allocation.
///
/// `max_len` is interpreted in bytes. DIDs are restricted to ASCII, so
/// byte-len matches char-len for any input we'll see in practice.
#[must_use]
pub fn truncate_did(did: &str, max_len: usize) -> Cow<'_, str> {
    if did.len() <= max_len {
        Cow::Borrowed(did)
    } else if max_len > 3 {
        Cow::Owned(format!("{}...", &did[..max_len - 3]))
    } else {
        Cow::Owned(did[..max_len].to_string())
    }
}

/// Middle-truncate `did` to at most `max_len` characters, keeping a
/// roughly equal slice from each end and inserting `...` in between.
/// Useful when the DID's distinguishing bits live in both the prefix
/// (method, host) and the suffix (key fragment).
#[must_use]
pub fn truncate_did_centered(did: &str, max_len: usize) -> Cow<'_, str> {
    let char_count = did.chars().count();
    if char_count <= max_len {
        return Cow::Borrowed(did);
    }
    let ellipsis = "...";
    let keep = (max_len.saturating_sub(ellipsis.len())) / 2;
    let start: String = did.chars().take(keep).collect();
    let end: String = did.chars().skip(char_count - keep).collect();
    Cow::Owned(format!("{start}...{end}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_did_passes_through_short_input() {
        let short = "did:web:example.com";
        let out = truncate_did(short, 60);
        assert_eq!(out, short);
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn truncate_did_appends_ellipsis() {
        let long = "did:webvh:abcdef0123456789:example.com:custom:path:here";
        let out = truncate_did(long, 20);
        assert_eq!(out.len(), 20);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn truncate_did_below_ellipsis_width_returns_raw_truncation() {
        let out = truncate_did("did:web:example.com", 2);
        assert_eq!(out, "di");
    }

    #[test]
    fn truncate_did_centered_passes_through_short() {
        let short = "did:web:x.io";
        let out = truncate_did_centered(short, 60);
        assert_eq!(out, short);
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn truncate_did_centered_keeps_both_ends() {
        let long = "did:webvh:abcdef0123456789:example.com:custom:path";
        let out = truncate_did_centered(long, 20);
        assert!(out.starts_with("did:web"));
        assert!(out.contains("..."));
        assert!(out.ends_with("path"));
    }
}
