//! Single-instance enforcement via lock files.
//!
//! Both `openvtc-cli` and `openvtc-cli2` need identical logic to detect and
//! prevent duplicate instances of the application running against the same
//! profile.  Keeping the implementation here eliminates the maintenance burden
//! of two copies diverging over time.
//!
//! # Usage
//!
//! ```no_run
//! use openvtc::process_lock::{check_duplicate_instance, remove_lock_file};
//!
//! let lock_path = check_duplicate_instance("default").expect("already running");
//! // … run application …
//! remove_lock_file(&lock_path);
//! ```

use crate::errors::OpenVTCError;
use std::{fs, path::Path, process, str::FromStr};
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

/// Checks whether another instance of openvtc is already running for `profile`.
///
/// If no duplicate is found a lock file containing the current PID is created
/// and its path is returned so the caller can [`remove_lock_file`] it on exit.
///
/// # Errors
///
/// - [`OpenVTCError::DuplicateInstance`] — another live process holds the lock.
/// - [`OpenVTCError::LockFile`] — the lock file could not be read or created.
pub fn check_duplicate_instance(profile: &str) -> Result<String, OpenVTCError> {
    let lock_file = get_lock_file(profile)?;

    match fs::exists(&lock_file) {
        Ok(true) => {
            let pid_str = fs::read_to_string(&lock_file)
                .map_err(|e| OpenVTCError::LockFile(format!("couldn't read lock file: {e}")))?;
            let pid_str = pid_str.trim_end();

            let system = System::new_with_specifics(
                RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
            );
            let pid = Pid::from_str(pid_str)
                .map_err(|e| OpenVTCError::LockFile(format!("invalid PID in lock file: {e}")))?;

            if system.process(pid).is_some() {
                return Err(OpenVTCError::DuplicateInstance(profile.to_string()));
            }
            // Stale lock file — fall through to overwrite it.
        }
        Ok(false) => {}
        Err(e) => {
            return Err(OpenVTCError::LockFile(format!(
                "couldn't check for lock file: {e}"
            )));
        }
    }

    create_lock_file(&lock_file)?;
    Ok(lock_file)
}

/// Returns the canonical path to the lock file for `profile`.
///
/// Respects the `OPENVTC_CONFIG_PATH` environment variable if set, otherwise
/// defaults to `~/.config/openvtc/`.
///
/// # Errors
///
/// Returns [`OpenVTCError::LockFile`] if the home directory cannot be determined.
pub fn get_lock_file(profile: &str) -> Result<String, OpenVTCError> {
    let path = if let Ok(config_path) = std::env::var("OPENVTC_CONFIG_PATH") {
        if config_path.ends_with('/') {
            config_path
        } else {
            format!("{config_path}/")
        }
    } else if let Some(home) = dirs::home_dir()
        && let Some(home_str) = home.to_str()
    {
        format!("{home_str}/.config/openvtc/")
    } else {
        return Err(OpenVTCError::LockFile(
            "couldn't determine home directory".to_string(),
        ));
    };

    if profile == "default" {
        Ok(format!("{path}config.lock"))
    } else {
        Ok(format!("{path}config-{profile}.lock"))
    }
}

/// Writes a lock file at `lock_file` containing the current process PID.
///
/// Parent directories are created if they do not already exist.
///
/// # Errors
///
/// Returns [`OpenVTCError::LockFile`] on any I/O failure.
pub fn create_lock_file(lock_file: &str) -> Result<(), OpenVTCError> {
    let dir_path = Path::new(lock_file);
    if let Some(parent) = dir_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .map_err(|e| OpenVTCError::LockFile(format!("couldn't create lock directory: {e}")))?;
    }

    fs::write(lock_file, process::id().to_string()).map_err(|e| {
        OpenVTCError::LockFile(format!("couldn't write lock file '{lock_file}': {e}"))
    })?;
    Ok(())
}

/// Removes the lock file at `lock_file`, ignoring any errors.
///
/// Errors are silently discarded because this is always called during
/// application shutdown, where there is no meaningful recovery path.
pub fn remove_lock_file(lock_file: &str) {
    let _ = fs::remove_file(lock_file);
}
