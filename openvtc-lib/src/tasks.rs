//! Task queue for tracking in-progress OpenVTC workflows.
//!
//! Tasks represent pending actions such as relationship handshakes, trust pings,
//! and VRC exchanges. Each task has a unique ID, a [`TaskType`], and a creation
//! timestamp.

use std::{
    fmt::Display,
    sync::{Arc, Mutex},
};

use indexmap::IndexMap;

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

/// Collection of in-progress tasks, ordered by insertion time.
/// 
/// Uses IndexMap instead of HashMap to maintain insertion order.
/// This ensures that task positions are deterministic and stable
/// across insertions and removals.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Tasks {
    /// key: Task ID, values ordered by insertion time (stable)
    pub tasks: IndexMap<Arc<String>, Arc<Mutex<Task>>>,
}

impl Tasks {
    /// Removes a task by ID. Returns `true` if the task was found and removed.
    /// 
    /// Uses `shift_remove` to maintain insertion order of remaining tasks.
    pub fn remove(&mut self, id: &Arc<String>) -> bool {
        let removed = self.tasks.shift_remove(id).is_some();
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

    /// Returns the task at the given insertion position, or `None` if out of bounds.
    ///
    /// Note: IndexMap maintains insertion order, so this is stable across insertions/removals.
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

   



    // NEW TESTS: Deterministic Task Ordering with IndexMap
   
    #[test]
    fn test_task_position_stable_after_insertions() {
        let mut tasks = Tasks::default();
        let id1 = Arc::new("task-1".to_string());
        let id2 = Arc::new("task-2".to_string());
        let id3 = Arc::new("task-3".to_string());



        // Add tasks in order
        tasks.new_task(&id1, TaskType::TrustPong);
        tasks.new_task(&id2, TaskType::RelationshipRequestRejected);
        tasks.new_task(&id3, TaskType::RelationshipRequestAccepted);



        // Verify initial positions
        assert_eq!(
            tasks.get_by_pos(0).unwrap().lock().unwrap().id,
            id1,
            "Position 0 should be id1"
        );
        assert_eq!(
            tasks.get_by_pos(1).unwrap().lock().unwrap().id,
            id2,
            "Position 1 should be id2"
        );
        assert_eq!(
            tasks.get_by_pos(2).unwrap().lock().unwrap().id,
            id3,
            "Position 2 should be id3"
        );



        // Add more tasks - existing positions should NOT change
        let id4 = Arc::new("task-4".to_string());
        tasks.new_task(&id4, TaskType::TrustPong);



        // CRITICAL ASSERTION: Existing positions must remain stable
        assert_eq!(
            tasks.get_by_pos(0).unwrap().lock().unwrap().id,
            id1,
            "Position 0 should STILL be id1 after adding id4"
        );
        assert_eq!(
            tasks.get_by_pos(1).unwrap().lock().unwrap().id,
            id2,
            "Position 1 should STILL be id2 after adding id4"
        );
        assert_eq!(
            tasks.get_by_pos(2).unwrap().lock().unwrap().id,
            id3,
            "Position 2 should STILL be id3 after adding id4"
        );
        assert_eq!(
            tasks.get_by_pos(3).unwrap().lock().unwrap().id,
            id4,
            "Position 3 should be new task id4"
        );
    }



    #[test]
    fn test_removal_preserves_remaining_order() {
        let mut tasks = Tasks::default();
        let id1 = Arc::new("task-1".to_string());
        let id2 = Arc::new("task-2".to_string());
        let id3 = Arc::new("task-3".to_string());

        tasks.new_task(&id1, TaskType::TrustPong);
        tasks.new_task(&id2, TaskType::RelationshipRequestOutbound {
            to: Arc::new("did:example:test".to_string()),
        });
        tasks.new_task(&id3, TaskType::RelationshipRequestAccepted);

        // Remove middle task
        let was_removed = tasks.remove(&id2);
        assert!(was_removed, "Should successfully remove task");

        // Verify remaining tasks maintain relative order
        assert_eq!(
            tasks.get_by_pos(0).unwrap().lock().unwrap().id,
            id1,
            "First remaining task should be id1"
        );
        assert_eq!(
            tasks.get_by_pos(1).unwrap().lock().unwrap().id,
            id3,
            "Second remaining task should be id3"
        );
        assert!(tasks.get_by_pos(2).is_none(), "Should only be 2 tasks left");
    }



    #[test]
    fn test_serialization_preserves_insertion_order() {
        let mut tasks = Tasks::default();
        let ids = vec!["task-a", "task-b", "task-c"];

        for id_str in &ids {
            tasks.new_task(
                &Arc::new(id_str.to_string()),
                TaskType::TrustPong,
            );
        }

        // Serialize to JSON
        let json = serde_json::to_string(&tasks).expect("Should serialize");

        // Deserialize from JSON
        let deserialized: Tasks = serde_json::from_str(&json)
            .expect("Should deserialize");

        // Verify order is preserved in round-trip
        for (i, expected_id) in ids.iter().enumerate() {
            let retrieved = deserialized
                .get_by_pos(i)
                .expect(&format!("Task at position {} should exist", i))
                .lock()
                .unwrap()
                .id.clone();
            assert_eq!(
                retrieved.as_str(),
                *expected_id,
                "Serialization round-trip should preserve order at position {}",
                i
            );
        }
    }




    #[test]
    fn test_position_consistency_across_many_operations() {
        let mut tasks = Tasks::default();
        let mut added_ids = Vec::new();

        // Add 10 tasks
        for i in 0..10 {
            let id = Arc::new(format!("task-{:02}", i));
            added_ids.push(id.clone());
            tasks.new_task(&id, TaskType::TrustPong);
        }

        // Verify all positions match insertion order
        for (pos, expected_id) in added_ids.iter().enumerate() {
            let actual = tasks
                .get_by_pos(pos)
                .expect(&format!("Task at position {} should exist", pos))
                .lock()
                .unwrap()
                .id.clone();
            assert_eq!(&actual, expected_id);
        }

        // Remove some tasks (indices 2, 5, 8)
        tasks.remove(&added_ids[2]);
        tasks.remove(&added_ids[5]);
        tasks.remove(&added_ids[8]);

        // Verify remaining count
        let expected_remaining = 10 - 3;
        let actual_remaining = (0..100)
            .take_while(|&pos| tasks.get_by_pos(pos).is_some())
            .count();
        assert_eq!(
            actual_remaining, expected_remaining,
            "Should have {} tasks remaining after 3 removals",
            expected_remaining
        );
    }




    #[test]
    fn test_empty_and_single_task_positions() {
        let mut tasks = Tasks::default();

        // Empty case
        assert!(tasks.get_by_pos(0).is_none(), "Empty tasks should have no position 0");
        assert!(tasks.get_by_pos(1).is_none(), "Empty tasks should have no position 1");

        // Single task
        let id1 = Arc::new("only-task".to_string());
        tasks.new_task(&id1, TaskType::TrustPong);

        assert!(tasks.get_by_pos(0).is_some(), "Single task should be at position 0");
        assert!(tasks.get_by_pos(1).is_none(), "Single task should not have position 1");

        // After removal
        tasks.remove(&id1);
        assert!(tasks.get_by_pos(0).is_none(), "After removal, should be empty again");
    }




    #[test]
    fn test_multiple_additions_then_removal() {
        let mut tasks = Tasks::default();
        let ids: Vec<Arc<String>> = (0..10)
            .map(|i| Arc::new(format!("task-{}", i)))
            .collect();

        // Add all
        for id in &ids {
            tasks.new_task(id, TaskType::TrustPong);
        }

        // Verify order
        for (i, expected_id) in ids.iter().enumerate() {
            let actual = tasks.get_by_pos(i).unwrap().lock().unwrap().id.clone();
            assert_eq!(&actual, expected_id);
        }

        // Remove IDs at indices 2, 4, 6, 8 (task-2, task-4, task-6, task-8)
        // Do them in reverse order to avoid position shifts affecting our logic
        let indices_to_remove = vec![8, 6, 4, 2];
        for &idx in &indices_to_remove {
            tasks.remove(&ids[idx]);
        }

        // Verify remaining are: task-0, task-1, task-3, task-5, task-7, task-9
        let expected_remaining = vec![0, 1, 3, 5, 7, 9];
        for (pos, &expected_idx) in expected_remaining.iter().enumerate() {
            let actual = tasks
                .get_by_pos(pos)
                .expect(&format!("Position {} should have a task", pos))
                .lock()
                .unwrap()
                .id.clone();
            assert_eq!(actual, ids[expected_idx], "Position {} should be task-{}", pos, expected_idx);
        }
        
        // Verify no more tasks after position 5
        assert!(tasks.get_by_pos(6).is_none(), "Should only have 6 tasks remaining");
    }
}



