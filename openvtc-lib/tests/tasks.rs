//! Integration tests for the Tasks struct and TaskType.

use openvtc::tasks::{TaskType, Tasks};
use std::sync::Arc;

#[test]
fn default_tasks_is_empty() {
    let tasks = Tasks::default();
    assert!(tasks.tasks.is_empty());
}

#[test]
fn create_and_retrieve_task_by_id() {
    let mut tasks = Tasks::default();
    let id = Arc::new("task-1".to_string());
    tasks.new_task(&id, TaskType::RelationshipRequestRejected);

    assert_eq!(tasks.tasks.len(), 1);
    let found = tasks.get_by_id(&id);
    assert!(found.is_some());
}

#[test]
fn get_by_id_missing_returns_none() {
    let tasks = Tasks::default();
    let missing = Arc::new("nonexistent".to_string());
    assert!(tasks.get_by_id(&missing).is_none());
}

#[test]
fn remove_existing_task_returns_true() {
    let mut tasks = Tasks::default();
    let id = Arc::new("task-1".to_string());
    tasks.new_task(&id, TaskType::RelationshipRequestAccepted);

    assert!(tasks.remove(&id));
    assert!(tasks.tasks.is_empty());
}

#[test]
fn remove_missing_task_returns_false() {
    let mut tasks = Tasks::default();
    let missing = Arc::new("no-such-task".to_string());
    assert!(!tasks.remove(&missing));
}

#[test]
fn get_by_position_valid_and_out_of_bounds() {
    let mut tasks = Tasks::default();
    let id = Arc::new("task-pos".to_string());
    tasks.new_task(&id, TaskType::TrustPong);

    assert!(tasks.get_by_pos(0).is_some());
    assert!(tasks.get_by_pos(1).is_none());
    assert!(tasks.get_by_pos(999).is_none());
}

#[test]
fn clear_empty_returns_false() {
    let mut tasks = Tasks::default();
    assert!(!tasks.clear());
}

#[test]
fn clear_non_empty_returns_true_and_empties() {
    let mut tasks = Tasks::default();
    tasks.new_task(
        &Arc::new("t1".to_string()),
        TaskType::RelationshipRequestFinalized,
    );
    tasks.new_task(&Arc::new("t2".to_string()), TaskType::VRCRequestRejected);

    assert!(tasks.clear());
    assert!(tasks.tasks.is_empty());
}

#[test]
fn new_task_returns_arc_to_created_task() {
    let mut tasks = Tasks::default();
    let id = Arc::new("task-ret".to_string());
    let task_arc = tasks.new_task(&id, TaskType::TrustPong);

    let lock = task_arc.lock().unwrap();
    assert_eq!(*lock.id, "task-ret");
}

#[test]
fn task_type_display_variants() {
    let cases: Vec<(TaskType, &str)> = vec![
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

    for (variant, expected) in cases {
        assert_eq!(format!("{}", variant), expected);
    }
}

#[test]
fn inserting_duplicate_id_overwrites() {
    let mut tasks = Tasks::default();
    let id = Arc::new("dup-id".to_string());
    tasks.new_task(&id, TaskType::TrustPong);
    tasks.new_task(&id, TaskType::VRCRequestRejected);

    // Should still have one entry (same key)
    assert_eq!(tasks.tasks.len(), 1);

    let lock = tasks.get_by_id(&id).unwrap().lock().unwrap();
    // The second insert should have overwritten the first
    assert_eq!(format!("{}", lock.type_), "VRC Request Rejected");
}
