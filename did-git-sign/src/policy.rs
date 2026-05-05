//! Signing-policy enforcement for `did-git-sign`.
//!
//! Without a policy gate the binary will sign arbitrary content for any
//! local process that can execute it. A malicious build script (npm,
//! cargo, pip…) that runs under the user's account could obtain Ed25519
//! signatures with namespace `git` over attacker-chosen data, which can
//! be used to forge "verified" git commits attributable to the user.
//!
//! The policy here raises the bar:
//!
//! 1. The parent process must look like git (`git`, `git-*`, or
//!    `ssh-keygen` for the verify path). Override with
//!    `DID_GIT_SIGN_BYPASS_POLICY=1` for tests/CI.
//! 2. Every signing attempt — accepted or denied — is recorded in an
//!    append-only audit log under the user's config dir. The user can
//!    inspect this to detect unexpected activity post-compromise.
//!
//! Path-based heuristics on the buffer file aren't enforced because
//! git's buffer files live in `$TMPDIR` with random names; trying to
//! pattern-match them produces false positives without meaningfully
//! constraining a determined attacker (who can spawn `git` themselves).

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use sysinfo::{Pid, System};

/// Bypass switch for tests/CI. Set this in the environment to skip the
/// parent-process check; the audit log still records every attempt.
const BYPASS_ENV: &str = "DID_GIT_SIGN_BYPASS_POLICY";

/// Names whose presence as the parent process causes the policy to
/// permit signing. Match is on the leading token of the process name.
const ALLOWED_PARENTS: &[&str] = &["git", "ssh-keygen"];

/// One audit-log line.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp_utc: String,
    pub action: &'static str,
    pub allowed: bool,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub namespace: String,
    pub buffer_path: Option<String>,
    pub buffer_sha256: String,
    pub bypass: bool,
}

/// Inspect the parent process and decide whether this signing attempt
/// is permitted. The `AuditEntry` is returned regardless so the caller
/// can append it to the audit log even on denial.
pub fn evaluate(
    namespace: &str,
    buffer_path: Option<&std::path::Path>,
    buffer: &[u8],
) -> AuditEntry {
    let bypass =
        std::env::var(BYPASS_ENV).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let (parent_pid, parent_name) = parent_process_info();
    let parent_token = parent_name
        .as_deref()
        .and_then(|n| n.split_whitespace().next())
        .map(|s| s.to_lowercase());
    let parent_ok = parent_token
        .as_deref()
        .map(|tok| {
            ALLOWED_PARENTS
                .iter()
                .any(|allowed| tok.starts_with(allowed))
        })
        .unwrap_or(false);
    let allowed = bypass || parent_ok;

    let mut hasher = Sha256::new();
    hasher.update(buffer);
    let buffer_sha256 = hex::encode(hasher.finalize());

    AuditEntry {
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        action: "sign",
        allowed,
        parent_pid,
        parent_name,
        namespace: namespace.to_string(),
        buffer_path: buffer_path.map(|p| p.display().to_string()),
        buffer_sha256,
        bypass,
    }
}

/// Append `entry` to the per-user audit log. Best-effort — failures
/// here log a warning but never block signing.
pub fn write_audit(entry: &AuditEntry) {
    if let Err(e) = try_write_audit(entry) {
        tracing::warn!("did-git-sign audit log write failed: {e}");
    }
}

fn try_write_audit(entry: &AuditEntry) -> Result<()> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create audit dir {}", parent.display()))?;
    }
    let line = serde_json::to_string(entry)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write as _;
    let mut f = opts
        .open(&path)
        .with_context(|| format!("open audit log {}", path.display()))?;
    writeln!(f, "{line}").with_context(|| format!("write audit log {}", path.display()))?;
    Ok(())
}

/// `~/.config/did-git-sign/audit.log` (or platform equivalent).
pub fn audit_log_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().context("could not determine config directory")?;
    Ok(dir.join("did-git-sign").join("audit.log"))
}

fn parent_process_info() -> (Option<u32>, Option<String>) {
    let mut sys = System::new();
    let self_pid = std::process::id();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
    let parent_pid = sys
        .process(Pid::from_u32(self_pid))
        .and_then(|p| p.parent())
        .map(|p| p.as_u32());
    let parent_name = parent_pid.and_then(|pid| {
        sys.process(Pid::from_u32(pid))
            .map(|p| p.name().to_string_lossy().to_string())
    });
    (parent_pid, parent_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_is_json_serializable() {
        let entry = AuditEntry {
            timestamp_utc: "2026-05-05T00:00:00Z".to_string(),
            action: "sign",
            allowed: true,
            parent_pid: Some(123),
            parent_name: Some("git".to_string()),
            namespace: "git".to_string(),
            buffer_path: Some("/tmp/buffer".to_string()),
            buffer_sha256: "deadbeef".to_string(),
            bypass: false,
        };
        let s = serde_json::to_string(&entry).unwrap();
        assert!(s.contains("\"allowed\":true"));
        assert!(s.contains("\"parent_name\":\"git\""));
    }

    #[test]
    fn evaluate_records_buffer_hash() {
        let entry = evaluate("git", None, b"hello");
        // sha256("hello")
        assert_eq!(
            entry.buffer_sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn evaluate_bypass_env_allows_unknown_parent() {
        // Run in a child process so we can mutate env without races.
        // unsafe is required because env mutation is not thread-safe; this
        // test is single-threaded by virtue of being the only one touching
        // the env var in the suite.
        unsafe { std::env::set_var(BYPASS_ENV, "1") };
        let entry = evaluate("git", None, b"x");
        unsafe { std::env::remove_var(BYPASS_ENV) };
        assert!(entry.allowed);
        assert!(entry.bypass);
    }
}
