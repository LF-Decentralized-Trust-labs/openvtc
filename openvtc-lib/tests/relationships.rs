//! Integration tests for the Relationships struct and related types.

use openvtc::relationships::{Relationship, RelationshipState, Relationships};
use std::sync::{Arc, Mutex};

fn make_relationship(
    task_id: &str,
    our_did: &str,
    remote_did: &str,
    remote_p_did: &str,
    state: RelationshipState,
) -> Relationship {
    Relationship {
        task_id: Arc::new(task_id.to_string()),
        our_did: Arc::new(our_did.to_string()),
        remote_did: Arc::new(remote_did.to_string()),
        remote_p_did: Arc::new(remote_p_did.to_string()),
        created: chrono::Utc::now(),
        state,
    }
}

#[test]
fn default_relationships_is_empty() {
    let rels = Relationships::default();
    assert!(rels.relationships.is_empty());
    assert_eq!(rels.path_pointer, 0);
}

#[test]
fn add_relationship_and_find_by_did() {
    let mut rels = Relationships::default();
    let r = make_relationship(
        "task-1",
        "did:our:1",
        "did:remote:1",
        "did:remote-p:1",
        RelationshipState::Established,
    );
    let key = r.remote_p_did.clone();
    rels.relationships
        .insert(key.clone(), Arc::new(Mutex::new(r)));

    let found = rels.get(&key);
    assert!(found.is_some(), "Should find relationship by remote P-DID");

    let missing_key = Arc::new("did:nonexistent".to_string());
    assert!(rels.get(&missing_key).is_none(), "Missing key returns None");
}

#[test]
fn find_by_task_id() {
    let mut rels = Relationships::default();
    let r = make_relationship(
        "task-42",
        "did:our:1",
        "did:remote:1",
        "did:remote-p:1",
        RelationshipState::RequestSent,
    );
    rels.relationships
        .insert(r.remote_p_did.clone(), Arc::new(Mutex::new(r)));

    let found = rels.find_by_task_id(&Arc::new("task-42".to_string()));
    assert!(found.is_some());

    let missing = rels.find_by_task_id(&Arc::new("task-999".to_string()));
    assert!(missing.is_none());
}

#[test]
fn find_by_remote_did_matches_both_r_did_and_p_did() {
    let mut rels = Relationships::default();
    let r = make_relationship(
        "task-1",
        "did:our:1",
        "did:remote-r:1",
        "did:remote-p:1",
        RelationshipState::Established,
    );
    rels.relationships
        .insert(r.remote_p_did.clone(), Arc::new(Mutex::new(r)));

    // Find by R-DID
    let by_r = rels.find_by_remote_did(&Arc::new("did:remote-r:1".to_string()));
    assert!(by_r.is_some(), "Should match by remote R-DID");

    // Find by P-DID
    let by_p = rels.find_by_remote_did(&Arc::new("did:remote-p:1".to_string()));
    assert!(by_p.is_some(), "Should match by remote P-DID");

    // Miss
    let miss = rels.find_by_remote_did(&Arc::new("did:nobody".to_string()));
    assert!(miss.is_none());
}

#[test]
fn get_established_filters_correctly() {
    let mut rels = Relationships::default();

    let established = make_relationship(
        "t1",
        "did:our:1",
        "did:r:1",
        "did:rp:1",
        RelationshipState::Established,
    );
    let pending = make_relationship(
        "t2",
        "did:our:2",
        "did:r:2",
        "did:rp:2",
        RelationshipState::RequestSent,
    );
    let rejected = make_relationship(
        "t3",
        "did:our:3",
        "did:r:3",
        "did:rp:3",
        RelationshipState::RequestRejected,
    );

    rels.relationships.insert(
        established.remote_p_did.clone(),
        Arc::new(Mutex::new(established)),
    );
    rels.relationships
        .insert(pending.remote_p_did.clone(), Arc::new(Mutex::new(pending)));
    rels.relationships.insert(
        rejected.remote_p_did.clone(),
        Arc::new(Mutex::new(rejected)),
    );

    let established_list = rels.get_established_relationships();
    assert_eq!(established_list.len(), 1);
}

#[test]
fn remove_relationship_clears_entry() {
    let mut rels = Relationships::default();
    let mut vrcs_issued = openvtc::vrc::Vrcs::default();
    let mut vrcs_received = openvtc::vrc::Vrcs::default();

    let r = make_relationship(
        "t1",
        "did:our:1",
        "did:r:1",
        "did:rp:1",
        RelationshipState::Established,
    );
    let key = r.remote_p_did.clone();
    rels.relationships
        .insert(key.clone(), Arc::new(Mutex::new(r)));

    let removed = rels.remove(&key, &mut vrcs_issued, &mut vrcs_received);
    assert!(removed.is_some());
    assert!(rels.relationships.is_empty());

    // Removing again returns None
    let again = rels.remove(&key, &mut vrcs_issued, &mut vrcs_received);
    assert!(again.is_none());
}

#[test]
fn relationship_state_display() {
    assert_eq!(RelationshipState::RequestSent.to_string(), "Request Sent");
    assert_eq!(
        RelationshipState::RequestAccepted.to_string(),
        "Request Accepted"
    );
    assert_eq!(
        RelationshipState::RequestRejected.to_string(),
        "Request Rejected"
    );
    assert_eq!(RelationshipState::Established.to_string(), "Established");
    assert_eq!(RelationshipState::None.to_string(), "None");
}

#[test]
fn relationships_shadow_roundtrip() {
    let mut rels = Relationships {
        path_pointer: 7,
        ..Default::default()
    };
    let r = make_relationship(
        "t1",
        "did:our:1",
        "did:r:1",
        "did:rp:1",
        RelationshipState::Established,
    );
    rels.relationships
        .insert(r.remote_p_did.clone(), Arc::new(Mutex::new(r)));

    // Roundtrip via JSON serialization (uses RelationshipsShadow internally via serde)
    let json = serde_json::to_string(&rels).expect("serialize");
    let restored: Relationships = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.path_pointer, 7);
    assert_eq!(restored.relationships.len(), 1);
}

#[test]
fn relationship_state_equality_and_hash() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(RelationshipState::Established);
    set.insert(RelationshipState::Established); // duplicate
    set.insert(RelationshipState::RequestSent);

    assert_eq!(set.len(), 2, "HashSet should deduplicate equal states");
}
