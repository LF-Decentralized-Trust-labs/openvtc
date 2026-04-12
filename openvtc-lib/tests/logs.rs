//! Integration tests for the Logs struct and LogFamily.

use openvtc::logs::{LogFamily, Logs};
use std::collections::VecDeque;

#[test]
fn default_logs_is_empty_with_limit_100() {
    let logs = Logs::default();
    assert!(logs.messages.is_empty());
    assert_eq!(logs.limit, 100);
}

#[test]
fn insert_single_entry() {
    let mut logs = Logs::default();
    logs.insert(LogFamily::Config, "first entry".to_string());

    assert_eq!(logs.messages.len(), 1);
    assert_eq!(logs.messages[0].message, "first entry");
}

#[test]
fn insert_multiple_entries_preserves_order() {
    let mut logs = Logs::default();
    logs.insert(LogFamily::Task, "alpha".to_string());
    logs.insert(LogFamily::Relationship, "beta".to_string());
    logs.insert(LogFamily::Contact, "gamma".to_string());

    assert_eq!(logs.messages.len(), 3);
    assert_eq!(logs.messages[0].message, "alpha");
    assert_eq!(logs.messages[1].message, "beta");
    assert_eq!(logs.messages[2].message, "gamma");
}

#[test]
fn fifo_eviction_at_limit() {
    let mut logs = Logs {
        messages: VecDeque::new(),
        limit: 3,
    };

    logs.insert(LogFamily::Task, "first".to_string());
    logs.insert(LogFamily::Task, "second".to_string());
    logs.insert(LogFamily::Task, "third".to_string());
    assert_eq!(logs.messages.len(), 3);

    // Fourth entry should evict the first
    logs.insert(LogFamily::Task, "fourth".to_string());
    assert_eq!(logs.messages.len(), 3);
    assert_eq!(logs.messages[0].message, "second");
    assert_eq!(logs.messages[1].message, "third");
    assert_eq!(logs.messages[2].message, "fourth");
}

#[test]
fn fifo_eviction_multiple_overflow() {
    let mut logs = Logs {
        messages: VecDeque::new(),
        limit: 2,
    };

    for i in 0..5 {
        logs.insert(LogFamily::Config, format!("msg-{}", i));
    }

    assert_eq!(logs.messages.len(), 2);
    assert_eq!(logs.messages[0].message, "msg-3");
    assert_eq!(logs.messages[1].message, "msg-4");
}

#[test]
fn limit_of_one_keeps_only_latest() {
    let mut logs = Logs {
        messages: VecDeque::new(),
        limit: 1,
    };

    logs.insert(LogFamily::Task, "old".to_string());
    logs.insert(LogFamily::Task, "new".to_string());

    assert_eq!(logs.messages.len(), 1);
    assert_eq!(logs.messages[0].message, "new");
}

#[test]
fn log_family_display() {
    assert_eq!(format!("{}", LogFamily::Relationship), "RELATIONSHIP");
    assert_eq!(format!("{}", LogFamily::Contact), "CONTACT");
    assert_eq!(format!("{}", LogFamily::Task), "TASK");
    assert_eq!(format!("{}", LogFamily::Config), "CONFIG");
}

#[test]
fn log_entry_has_timestamp() {
    let mut logs = Logs::default();
    let before = chrono::Utc::now();
    logs.insert(LogFamily::Config, "timed".to_string());
    let after = chrono::Utc::now();

    let entry = &logs.messages[0];
    assert!(entry.created >= before && entry.created <= after);
}

#[test]
fn log_entry_preserves_family() {
    let mut logs = Logs::default();
    logs.insert(LogFamily::Relationship, "rel msg".to_string());
    logs.insert(LogFamily::Contact, "contact msg".to_string());

    assert_eq!(format!("{}", logs.messages[0].type_), "RELATIONSHIP");
    assert_eq!(format!("{}", logs.messages[1].type_), "CONTACT");
}
