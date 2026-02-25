use std::{
    collections::HashMap,
    fmt::Display,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Utc};
use dtg_credentials::DTGCredential;
use serde::{Deserialize, Serialize};

use crate::{
    relationships::{Relationship, RelationshipRequestBody},
    vrc::VrcRequest,
};

/// Defined Task Types for OpenVTC
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaskType {
    RelationshipRequestOutbound {
        to: Arc<String>,
    },
    RelationshipRequestInbound {
        from: Arc<String>,
        to: Arc<String>,
        request: RelationshipRequestBody,
    },
    RelationshipRequestRejected,
    RelationshipRequestAccepted,
    RelationshipRequestFinalized,
    TrustPing {
        from: Arc<String>,
        to: Arc<String>,
        relationship: Arc<Mutex<Relationship>>,
    },
    TrustPong,
    VRCRequestOutbound {
        relationship: Arc<Mutex<Relationship>>,
    },
    VRCRequestInbound {
        request: VrcRequest,
        relationship: Arc<Mutex<Relationship>>,
    },
    VRCRequestRejected,
    VRCIssued {
        vrc: Box<DTGCredential>,
    },
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

/// Known Tasks that are in progress
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Tasks {
    /// key: Task ID
    pub tasks: HashMap<Arc<String>, Arc<Mutex<Task>>>,
}

impl Tasks {
    /// Removes a task by ID
    pub fn remove(&mut self, id: &Arc<String>) -> bool {
        self.tasks.remove(id).is_some()
    }

    /// Creates and adds a new Task to list of tasks
    pub fn new_task(&mut self, id: &Arc<String>, type_: TaskType) -> Arc<Mutex<Task>> {
        let task = Arc::new(Mutex::new(Task {
            id: id.clone(),
            type_,
            created: Utc::now(),
        }));
        self.tasks.insert(id.clone(), task.clone());
        task
    }

    /// Returns task at position pos
    /// Be careful with this, as insertions/removals can change operation
    pub fn get_by_pos(&self, pos: usize) -> Option<Arc<Mutex<Task>>> {
        self.tasks.iter().nth(pos).map(|(_, task)| task.clone())
    }

    /// Retrieves a task by ID or returns None
    pub fn get_by_id(&self, id: &Arc<String>) -> Option<&Arc<Mutex<Task>>> {
        self.tasks.get(id)
    }

    /// Clears all tasks
    /// Returns true if any tasks were removed
    /// Returns false if no changes were made
    pub fn clear(&mut self) -> bool {
        let flag = !self.tasks.is_empty();
        self.tasks.clear();
        flag
    }
}

/// OpenVTC Task
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Task {
    /// ID of task
    pub id: Arc<String>,

    /// Type of Task
    pub type_: TaskType,

    /// When was this task created?
    pub created: DateTime<Utc>,
}
