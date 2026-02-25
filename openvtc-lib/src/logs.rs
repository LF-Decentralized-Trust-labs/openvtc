use std::{collections::VecDeque, fmt::Display};

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum LogFamily {
    Relationship,
    Contact,
    Task,
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

/// Log Messages
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogMessage {
    // When the log message was created
    pub created: chrono::DateTime<Utc>,

    // What type of log is this related to?
    pub type_: LogFamily,

    // Log Message
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Logs {
    pub messages: VecDeque<LogMessage>,
    /// Max number of entries to keep
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
    /// Insert a new log entry message to the log
    /// Handles keeping the log messages within the limit
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
