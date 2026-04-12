//! Local audit log for OpenVTC operations.
//!
//! Provides a bounded FIFO log ([`Logs`]) that records timestamped messages
//! categorized by [`LogFamily`].

use std::{collections::VecDeque, fmt::Display};

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Category of a log message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum LogFamily {
    /// Relationship lifecycle events.
    Relationship,
    /// Contact management events.
    Contact,
    /// Task creation and completion events.
    Task,
    /// Configuration changes.
    Config,
}

impl Display for LogFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LogFamily::Relationship => "RELATIONSHIP",
            LogFamily::Contact => "CONTACT",
            LogFamily::Task => "TASK",
            LogFamily::Config => "CONFIG",
        };
        write!(f, "{}", s)
    }
}

/// A single timestamped log entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogMessage {
    /// When the log message was created.
    pub created: chrono::DateTime<Utc>,

    /// Category of this log entry.
    pub type_: LogFamily,

    /// Human-readable log message.
    pub message: String,
}

/// Bounded FIFO log that evicts the oldest entries when the limit is reached.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Logs {
    /// Log entries in insertion order (oldest first).
    pub messages: VecDeque<LogMessage>,
    /// Maximum number of entries to retain.
    pub limit: usize,
}

impl Default for Logs {
    fn default() -> Self {
        Self {
            messages: VecDeque::new(),
            limit: 100,
        }
    }
}

impl Logs {
    /// Appends a new log entry, evicting the oldest entry if the limit is exceeded.
    pub fn insert(&mut self, type_: LogFamily, message: String) {
        self.messages.push_back(LogMessage {
            created: Utc::now(),
            type_,
            message,
        });

        if self.messages.len() > self.limit {
            self.messages.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logs_default_empty() {
        let logs = Logs::default();
        assert!(
            logs.messages.is_empty(),
            "Default Logs should have no messages"
        );
        assert_eq!(logs.limit, 100, "Default limit should be 100");
    }

    #[test]
    fn test_logs_insert() {
        let mut logs = Logs::default();
        logs.insert(LogFamily::Config, "test message".to_string());

        assert_eq!(logs.messages.len(), 1);
        assert_eq!(logs.messages[0].message, "test message");
    }

    #[test]
    fn test_logs_fifo_limit() {
        let mut logs = Logs {
            messages: VecDeque::new(),
            limit: 3,
        };

        logs.insert(LogFamily::Task, "first".to_string());
        logs.insert(LogFamily::Task, "second".to_string());
        logs.insert(LogFamily::Task, "third".to_string());
        assert_eq!(logs.messages.len(), 3);

        // Inserting a fourth should evict the first (FIFO)
        logs.insert(LogFamily::Task, "fourth".to_string());
        assert_eq!(logs.messages.len(), 3, "Should not exceed limit");
        assert_eq!(
            logs.messages[0].message, "second",
            "Oldest message should have been removed"
        );
        assert_eq!(logs.messages[2].message, "fourth");
    }

    #[test]
    fn test_log_family_display() {
        assert_eq!(format!("{}", LogFamily::Relationship), "RELATIONSHIP");
        assert_eq!(format!("{}", LogFamily::Contact), "CONTACT");
        assert_eq!(format!("{}", LogFamily::Task), "TASK");
        assert_eq!(format!("{}", LogFamily::Config), "CONFIG");
    }
}
