//! Task queue for tracking in-progress OpenVTC workflows.
//!
//! Tasks represent pending actions such as relationship handshakes, trust pings,
//! and VRC exchanges. Each task has a unique ID, a [`TaskType`], and a creation
//! timestamp.

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Utc};
use dtg_credentials::DTGCredential;
use serde::{Deserialize, Serialize};

use tracing::debug;

use crate::{
    relationships::{Relationship, RelationshipRequestBody},
    vrc::VrcRequest,
};

/// Defined Task Types for OpenVTC.
///
/// Each variant represents a discrete workflow step that the user may need to
/// act on or that is awaiting a remote response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaskType {
    /// We sent a relationship request to a remote party.
    RelationshipRequestOutbound { to: Arc<String> },
    /// A remote party sent us a relationship request awaiting our response.
    RelationshipRequestInbound {
        from: Arc<String>,
        to: Arc<String>,
        request: RelationshipRequestBody,
    },
    /// Our relationship request was rejected by the remote party.
    RelationshipRequestRejected,
    /// Our relationship request was accepted by the remote party.
    RelationshipRequestAccepted,
    /// The relationship handshake has been finalized (fully established).
    RelationshipRequestFinalized,
    /// A trust-ping was sent to verify connectivity with the remote party.
    TrustPing {
        from: Arc<String>,
        to: Arc<String>,
        relationship: Arc<Mutex<Relationship>>,
    },
    /// A trust-pong response was received from the remote party.
    TrustPong,
    /// We sent a VRC request to a remote party.
    VRCRequestOutbound {
        relationship: Arc<Mutex<Relationship>>,
    },
    /// A remote party sent us a VRC request awaiting our response.
    VRCRequestInbound {
        request: VrcRequest,
        relationship: Arc<Mutex<Relationship>>,
    },
    /// Our VRC request was rejected by the remote party.
    VRCRequestRejected,
    /// A VRC has been issued (either by us or received from a remote party).
    VRCIssued { vrc: Box<DTGCredential> },
}

impl Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let friendly_name = match self {
            TaskType::RelationshipRequestOutbound { .. } => "Relationship Request (Outbound)",
            TaskType::RelationshipRequestInbound { .. } => "Relationship Request (Inbound)",
            TaskType::RelationshipRequestRejected => "Relationship Request Rejected",
            TaskType::RelationshipRequestAccepted => "Relationship Request Accepted",
            TaskType::RelationshipRequestFinalized => "Relationship Request Finalized",
            TaskType::TrustPing { .. } => "Trust Ping Sent",
            TaskType::TrustPong => "Trust Pong Received",
            TaskType::VRCRequestOutbound { .. } => "VRC Request Sent",
            TaskType::VRCRequestInbound { .. } => "VRC Request Received",
            TaskType::VRCRequestRejected => "VRC Request Rejected",
            TaskType::VRCIssued { .. } => "VRC Issued",
        };
        write!(f, "{}", friendly_name)
    }
}

/// Collection of in-progress tasks, indexed by task ID.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Tasks {
    /// key: Task ID
    pub tasks: HashMap<Arc<String>, Arc<Mutex<Task>>>,
}

impl Tasks {
    /// Removes a task by ID. Returns `true` if the task was found and removed.
    pub fn remove(&mut self, id: &Arc<String>) -> bool {
        let removed = self.tasks.remove(id).is_some();
        if removed {
            debug!("task removed: id={}", id);
        }
        removed
    }

    /// Creates a new task with the given ID and type, inserts it, and returns a shared reference.
    pub fn new_task(&mut self, id: &Arc<String>, type_: TaskType) -> Arc<Mutex<Task>> {
        debug!("task created: type={:?}, id={}", type_, id);
        let task = Arc::new(Mutex::new(Task {
            id: id.clone(),
            type_,
            created: Utc::now(),
        }));
        self.tasks.insert(id.clone(), task.clone());
        task
    }

    /// Returns the task at the given iteration position, or `None` if out of bounds.
    ///
    /// Note: HashMap iteration order is not stable across insertions and removals.
    pub fn get_by_pos(&self, pos: usize) -> Option<Arc<Mutex<Task>>> {
        self.tasks.iter().nth(pos).map(|(_, task)| task.clone())
    }

    /// Retrieves a task by ID or returns None
    pub fn get_by_id(&self, id: &Arc<String>) -> Option<&Arc<Mutex<Task>>> {
        self.tasks.get(id)
    }

    /// Clears all tasks. Returns `true` if any tasks were removed.
    pub fn clear(&mut self) -> bool {
        let flag = !self.tasks.is_empty();
        self.tasks.clear();
        flag
    }
}

/// A single in-progress OpenVTC task.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Task {
    /// Unique task identifier.
    pub id: Arc<String>,

    /// The kind of workflow this task represents.
    pub type_: TaskType,

    /// Timestamp when this task was created.
    pub created: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tasks_default_empty() {
        let tasks = Tasks::default();
        assert!(tasks.tasks.is_empty(), "Default Tasks should have no tasks");
    }

    #[test]
    fn test_new_task_and_retrieve() {
        let mut tasks = Tasks::default();
        let id = Arc::new("task-1".to_string());
        tasks.new_task(&id, TaskType::RelationshipRequestRejected);

        assert_eq!(tasks.tasks.len(), 1);
        assert!(tasks.get_by_id(&id).is_some(), "Should find task by ID");
    }

    #[test]
    fn test_remove_task() {
        let mut tasks = Tasks::default();
        let id = Arc::new("task-1".to_string());
        tasks.new_task(&id, TaskType::RelationshipRequestAccepted);

        assert!(
            tasks.remove(&id),
            "remove should return true for existing task"
        );
        assert!(
            tasks.tasks.is_empty(),
            "Tasks should be empty after removal"
        );

        let missing = Arc::new("nonexistent".to_string());
        assert!(
            !tasks.remove(&missing),
            "remove should return false for missing task"
        );
    }

    #[test]
    fn test_get_by_position() {
        let mut tasks = Tasks::default();
        let id = Arc::new("task-pos".to_string());
        tasks.new_task(&id, TaskType::TrustPong);

        let found = tasks.get_by_pos(0);
        assert!(found.is_some(), "Should retrieve task at position 0");

        let out_of_bounds = tasks.get_by_pos(99);
        assert!(
            out_of_bounds.is_none(),
            "Should return None for out-of-bounds position"
        );
    }

    #[test]
    fn test_clear_tasks() {
        let mut tasks = Tasks::default();
        assert!(!tasks.clear(), "Clearing empty tasks should return false");

        let id = Arc::new("task-clear".to_string());
        tasks.new_task(&id, TaskType::RelationshipRequestFinalized);
        assert!(tasks.clear(), "Clearing non-empty tasks should return true");
        assert!(tasks.tasks.is_empty());
    }

    #[test]
    fn test_task_type_display() {
        let variants: Vec<(TaskType, &str)> = vec![
            (
                TaskType::RelationshipRequestOutbound {
                    to: Arc::new("did:example:1".to_string()),
                },
                "Relationship Request (Outbound)",
            ),
            (
                TaskType::RelationshipRequestRejected,
                "Relationship Request Rejected",
            ),
            (
                TaskType::RelationshipRequestAccepted,
                "Relationship Request Accepted",
            ),
            (
                TaskType::RelationshipRequestFinalized,
                "Relationship Request Finalized",
            ),
            (TaskType::TrustPong, "Trust Pong Received"),
            (TaskType::VRCRequestRejected, "VRC Request Rejected"),
        ];

        for (variant, expected) in variants {
            let display = format!("{}", variant);
            assert_eq!(
                display, expected,
                "TaskType display mismatch for {:?}",
                variant
            );
        }
    }
}
