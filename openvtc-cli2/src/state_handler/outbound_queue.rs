//! Outbound message queue for offline resilience.
//!
//! When `pack_and_send` fails (e.g., mediator unreachable), messages are
//! queued here for automatic retry when connectivity is restored.

use affinidi_tdk::didcomm::Message;
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use tracing::{info, warn};

/// Maximum queued messages before oldest are dropped.
const MAX_QUEUE_SIZE: usize = 1_000;

/// Maximum retry attempts per message before giving up.
const MAX_RETRIES: u32 = 5;

/// A message waiting to be sent.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PendingMessage {
    pub message: Message,
    pub from: String,
    pub to: String,
    pub mediator: String,
    pub retry_count: u32,
    pub created: DateTime<Utc>,
    pub description: String,
}

/// Queue of outbound messages that failed to send.
#[derive(Debug, Default)]
pub struct OutboundQueue {
    pending: VecDeque<PendingMessage>,
}

impl OutboundQueue {
    /// Add a message to the retry queue.
    pub fn enqueue(&mut self, msg: PendingMessage) {
        if self.pending.len() >= MAX_QUEUE_SIZE {
            let dropped = self.pending.pop_front();
            if let Some(d) = dropped {
                warn!(desc = %d.description, "outbound queue full — dropping oldest message");
            }
        }
        info!(desc = %msg.description, "message queued for retry");
        self.pending.push_back(msg);
    }

    /// Take all pending messages for a retry attempt.
    /// Returns messages that haven't exceeded MAX_RETRIES.
    pub fn drain_for_retry(&mut self) -> Vec<PendingMessage> {
        let mut to_retry = Vec::new();
        let mut to_drop = Vec::new();

        while let Some(mut msg) = self.pending.pop_front() {
            msg.retry_count += 1;
            if msg.retry_count <= MAX_RETRIES {
                to_retry.push(msg);
            } else {
                to_drop.push(msg);
            }
        }

        for d in &to_drop {
            warn!(desc = %d.description, retries = d.retry_count, "giving up on message after max retries");
        }

        to_retry
    }

    /// Number of pending messages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::didcomm::Message;
    use chrono::Utc;

    fn test_message() -> PendingMessage {
        PendingMessage {
            message: Message::build(
                "test-id".to_string(),
                "test-type".to_string(),
                serde_json::json!({}),
            )
            .finalize(),
            from: "did:test:from".into(),
            to: "did:test:to".into(),
            mediator: "did:test:mediator".into(),
            retry_count: 0,
            created: Utc::now(),
            description: "test message".into(),
        }
    }

    #[test]
    fn test_enqueue_and_len() {
        let mut queue = OutboundQueue::default();
        assert!(queue.is_empty());
        queue.enqueue(test_message());
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_drain_increments_retry() {
        let mut queue = OutboundQueue::default();
        queue.enqueue(test_message());
        let drained = queue.drain_for_retry();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].retry_count, 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_max_retries_drops_message() {
        let mut queue = OutboundQueue::default();
        let mut msg = test_message();
        msg.retry_count = MAX_RETRIES; // already at max
        queue.enqueue(msg);
        let drained = queue.drain_for_retry();
        assert!(drained.is_empty()); // dropped after max retries
    }

    #[test]
    fn test_queue_size_limit() {
        let mut queue = OutboundQueue::default();
        for i in 0..MAX_QUEUE_SIZE + 5 {
            let mut msg = test_message();
            msg.description = format!("msg-{}", i);
            queue.enqueue(msg);
        }
        assert_eq!(queue.len(), MAX_QUEUE_SIZE);
    }
}
