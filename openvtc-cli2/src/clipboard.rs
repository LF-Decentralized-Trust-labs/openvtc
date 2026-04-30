//! Copy-to-clipboard helper with OSC 52 + `arboard` fallback.
//!
//! Ported from `affinidi-messaging-mediator-setup`. The wizard runs over
//! SSH about as often as it runs locally. The `arboard` crate talks
//! directly to the OS clipboard via X11 / Wayland / macOS APIs — that's
//! perfect for a local terminal but useless across an SSH session, where
//! the operator's machine is not the one running the wizard.
//!
//! OSC 52 is a terminal escape sequence (`\x1b]52;c;<base64>\x1b\\`)
//! that the *terminal emulator itself* interprets and writes to the
//! local clipboard. It travels through SSH transparently — the escape
//! bytes flow through the TTY just like any other output, and the
//! operator's terminal handles them.
//!
//! ## Dispatch strategy
//!
//! - On SSH (`SSH_CONNECTION` / `SSH_TTY` / `SSH_CLIENT` set in env):
//!   try OSC 52 first, fall back to `arboard` on failure. Operators on
//!   supporting terminals get clipboard support; the rare non-supporting
//!   case can still hit a local clipboard if the wizard machine
//!   happens to have one.
//! - Locally: try `arboard` first, fall back to OSC 52. `arboard` is
//!   the more reliable path on a local desktop; OSC 52 is the fallback
//!   for headless desktops where `arboard` finds no clipboard daemon.
//!
//! ## Honesty about confirmation
//!
//! Neither path can confirm the clipboard was *actually* set. OSC 52
//! emits to stdout and trusts the terminal; `arboard` opens a handle
//! and trusts the OS. The returned [`CopyMethod`] reports which path
//! was *attempted successfully* — an error from the underlying library
//! means we could not even attempt that path. Operators confirm by
//! pasting.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::io::Write;

/// Maximum payload accepted by [`copy_to_clipboard`]. Most terminals cap
/// OSC 52 payloads in the 75–100 KB range; 70 KB sits comfortably under
/// the conservative end. No current copyable surface in the wizard
/// approaches this — guard is defensive.
pub const MAX_PAYLOAD_BYTES: usize = 70 * 1024;

/// Which transport delivered the clipboard text to the operator's
/// machine. Surfaced in the wizard's "Copied!" status so operators can
/// tell which path took (helpful when "Copied!" lit up but the local
/// clipboard didn't change — usually a sign the SSH terminal dropped
/// OSC 52 silently).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMethod {
    /// Sent via the OSC 52 terminal escape sequence. SSH-friendly;
    /// requires terminal support (most modern terminals; `tmux` needs
    /// `set -g set-clipboard on`).
    Osc52,
    /// Sent via the `arboard` crate to the local OS clipboard. Works on
    /// local desktop terminals; fails over SSH when the wizard host has
    /// no clipboard daemon.
    Arboard,
}

impl CopyMethod {
    /// Operator-facing short label for the wizard's status footer.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Osc52 => "OSC 52 (terminal)",
            Self::Arboard => "system clipboard",
        }
    }
}

/// Copy `text` to the operator's clipboard, picking OSC 52 or `arboard`
/// based on whether the wizard appears to be running over SSH.
///
/// Returns the [`CopyMethod`] that successfully attempted the copy, or
/// an error string naming both failure reasons when neither path could
/// even be attempted.
pub fn copy_to_clipboard(text: &str) -> Result<CopyMethod, String> {
    copy_with(text, is_ssh_environment(), try_arboard, try_osc52_to_stdout)
}

/// Internal dispatch point — visible for tests so we can stub the two
/// transports independently and exercise both fallback paths without
/// touching the real OS clipboard or stdout.
fn copy_with<A, O>(text: &str, on_ssh: bool, arboard: A, osc52: O) -> Result<CopyMethod, String>
where
    A: FnOnce(&str) -> Result<(), String>,
    O: FnOnce(&str) -> Result<(), String>,
{
    if text.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "payload {} bytes exceeds OSC 52 cap of {} bytes — truncate before copying",
            text.len(),
            MAX_PAYLOAD_BYTES
        ));
    }
    if on_ssh {
        match osc52(text) {
            Ok(()) => Ok(CopyMethod::Osc52),
            Err(osc52_err) => match arboard(text) {
                Ok(()) => Ok(CopyMethod::Arboard),
                Err(arboard_err) => Err(format!("OSC 52: {osc52_err}; arboard: {arboard_err}")),
            },
        }
    } else {
        match arboard(text) {
            Ok(()) => Ok(CopyMethod::Arboard),
            Err(arboard_err) => match osc52(text) {
                Ok(()) => Ok(CopyMethod::Osc52),
                Err(osc52_err) => Err(format!("arboard: {arboard_err}; OSC 52: {osc52_err}")),
            },
        }
    }
}

/// Detect whether the wizard appears to be running over SSH by
/// inspecting standard environment variables.
///
/// `SSH_CONNECTION` is the most reliable signal (set by the SSH daemon
/// itself); `SSH_TTY` and `SSH_CLIENT` are commonly set in the same
/// context but can be filtered out by some shell configs. We OR all
/// three so a missing variable on one path doesn't suppress the
/// SSH-aware behaviour.
fn is_ssh_environment() -> bool {
    is_ssh_environment_with(|k| std::env::var(k).ok())
}

/// Pure, env-injectable variant for parallel-safe testing.
fn is_ssh_environment_with<F: Fn(&str) -> Option<String>>(getter: F) -> bool {
    ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"]
        .iter()
        .any(|k| getter(k).is_some_and(|v| !v.is_empty()))
}

/// Build the OSC 52 escape sequence for `text`. Pure — separated from
/// the IO so tests can inspect the exact bytes.
///
/// Format: `\x1b]52;c;<base64>\x1b\\`. The trailing `\x1b\\` is the
/// String Terminator (ST). We intentionally do not use the BEL
/// (`\x07`) terminator some implementations accept — `tmux` only
/// honours ST in passthrough mode, and modern terminals all accept ST.
fn format_osc52(text: &str) -> String {
    let encoded = B64.encode(text.as_bytes());
    format!("\x1b]52;c;{encoded}\x1b\\")
}

/// Write the OSC 52 sequence to `w` and flush.
fn emit_osc52_to<W: Write>(text: &str, w: &mut W) -> std::io::Result<()> {
    let seq = format_osc52(text);
    w.write_all(seq.as_bytes())?;
    w.flush()
}

/// Production OSC 52 emitter — writes to stdout. Errors from the
/// underlying write are stringified for the dispatcher.
fn try_osc52_to_stdout(text: &str) -> Result<(), String> {
    emit_osc52_to(text, &mut std::io::stdout()).map_err(|e| e.to_string())
}

/// Production arboard caller. Constructs a fresh clipboard handle each
/// call — `arboard::Clipboard` is not `Send` and we don't keep a
/// long-lived handle anywhere in the wizard.
fn try_arboard(text: &str) -> Result<(), String> {
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(text))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(map: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: HashMap<String, String> = map
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        move |k| owned.get(k).cloned()
    }

    #[test]
    fn ssh_env_detected_via_ssh_connection() {
        assert!(is_ssh_environment_with(env(&[(
            "SSH_CONNECTION",
            "10.0.0.1 22 10.0.0.2 5000",
        )])));
    }

    #[test]
    fn ssh_env_detected_via_ssh_tty() {
        assert!(is_ssh_environment_with(env(&[("SSH_TTY", "/dev/pts/3")])));
    }

    #[test]
    fn ssh_env_detected_via_ssh_client() {
        assert!(is_ssh_environment_with(env(&[(
            "SSH_CLIENT",
            "10.0.0.1 5000 22"
        )])));
    }

    #[test]
    fn ssh_env_returns_false_when_no_vars_set() {
        assert!(!is_ssh_environment_with(env(&[])));
    }

    #[test]
    fn ssh_env_ignores_empty_string_values() {
        // Some shells export the var as empty when not actually inside an
        // SSH session; treat that as "not SSH".
        assert!(!is_ssh_environment_with(env(&[("SSH_CONNECTION", "")])));
    }

    #[test]
    fn osc52_format_uses_st_terminator() {
        let s = format_osc52("hi");
        assert!(s.starts_with("\x1b]52;c;"));
        assert!(s.ends_with("\x1b\\"));
        // The base64 of "hi" is "aGk=".
        assert!(s.contains("aGk="));
    }

    #[test]
    fn osc52_emits_to_writer() {
        let mut buf: Vec<u8> = Vec::new();
        emit_osc52_to("hi", &mut buf).unwrap();
        let written = String::from_utf8(buf).unwrap();
        assert_eq!(written, format_osc52("hi"));
    }

    #[test]
    fn dispatch_on_ssh_tries_osc52_first() {
        let result = copy_with(
            "test",
            true,
            |_| Err("arboard would have been called".into()),
            |_| Ok(()),
        );
        assert_eq!(result, Ok(CopyMethod::Osc52));
    }

    #[test]
    fn dispatch_on_ssh_falls_back_to_arboard_when_osc52_fails() {
        let result = copy_with(
            "test",
            true,
            |_| Ok(()),
            |_| Err("terminal does not support OSC 52".into()),
        );
        assert_eq!(result, Ok(CopyMethod::Arboard));
    }

    #[test]
    fn dispatch_locally_tries_arboard_first() {
        let result = copy_with(
            "test",
            false,
            |_| Ok(()),
            |_| Err("osc52 would have been called".into()),
        );
        assert_eq!(result, Ok(CopyMethod::Arboard));
    }

    #[test]
    fn dispatch_locally_falls_back_to_osc52_when_arboard_fails() {
        let result = copy_with(
            "test",
            false,
            |_| Err("no clipboard daemon".into()),
            |_| Ok(()),
        );
        assert_eq!(result, Ok(CopyMethod::Osc52));
    }

    #[test]
    fn dispatch_returns_combined_err_when_both_methods_fail() {
        let err = copy_with(
            "test",
            true,
            |_| Err("no clipboard daemon".into()),
            |_| Err("OSC 52 not supported".into()),
        )
        .unwrap_err();
        assert!(err.contains("OSC 52: OSC 52 not supported"));
        assert!(err.contains("arboard: no clipboard daemon"));
    }

    #[test]
    fn dispatch_rejects_oversized_payload() {
        let huge = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        let err = copy_with(
            &huge,
            true,
            |_| panic!("arboard called despite oversized payload"),
            |_| panic!("osc52 called despite oversized payload"),
        )
        .unwrap_err();
        assert!(err.contains("exceeds"));
        assert!(err.contains(&MAX_PAYLOAD_BYTES.to_string()));
    }

    #[test]
    fn copy_method_label_is_operator_friendly() {
        assert_eq!(CopyMethod::Osc52.label(), "OSC 52 (terminal)");
        assert_eq!(CopyMethod::Arboard.label(), "system clipboard");
    }
}
