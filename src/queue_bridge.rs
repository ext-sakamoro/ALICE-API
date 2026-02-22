//! ALICE-API × ALICE-Queue Bridge
//!
//! Route API requests through a lock-free message queue for async processing.
//! Gateway → Queue (enqueue) → Worker (dequeue with idempotency).

use crate::gateway::GatewayRequest;
use alice_queue::{AliceQueue, GapResult, Message};

/// Queued API gateway that buffers requests through ALICE-Queue.
pub struct QueuedGateway<const N: usize> {
    queue: AliceQueue<N>,
    enqueued: u64,
    processed: u64,
    duplicates: u64,
}

impl<const N: usize> QueuedGateway<N> {
    /// Create a new queued gateway.
    pub fn new() -> Self {
        Self {
            queue: AliceQueue::new(),
            enqueued: 0,
            processed: 0,
            duplicates: 0,
        }
    }

    /// Enqueue an API request for async processing.
    ///
    /// Converts the request into a queue message using client_hash as sender
    /// and request_id as sequence number.
    pub fn enqueue_request(&mut self, request: &GatewayRequest) -> Result<u64, ()> {
        let mut sender = [0u8; 32];
        sender[0..8].copy_from_slice(&request.client_hash.to_le_bytes());

        let payload = request.path[..request.path_len].to_vec();
        let msg = Message::new(sender, request.request_id, payload);
        self.queue.enqueue(msg).map_err(|_| ())?;
        self.enqueued += 1;
        Ok(request.request_id)
    }

    /// Dequeue and process the next request.
    ///
    /// Returns the message payload and whether it was accepted, duplicate, or gap.
    pub fn process_next(&mut self) -> Option<(Vec<u8>, GapResult)> {
        let (msg, result) = self.queue.dequeue()?;
        match result {
            GapResult::Accept => self.processed += 1,
            GapResult::Duplicate => self.duplicates += 1,
            GapResult::Gap { .. } => self.processed += 1,
        }
        Some((msg.payload, result))
    }

    /// Queue depth.
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
    /// Total enqueued.
    pub fn total_enqueued(&self) -> u64 {
        self.enqueued
    }
    /// Total processed.
    pub fn total_processed(&self) -> u64 {
        self.processed
    }
    /// Total duplicates dropped.
    pub fn total_duplicates(&self) -> u64 {
        self.duplicates
    }
}

impl<const N: usize> Default for QueuedGateway<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::HttpMethod;

    fn make_request(client: u64, id: u64) -> GatewayRequest {
        let mut path = [0u8; 256];
        path[..4].copy_from_slice(b"/api");
        GatewayRequest {
            client_hash: client,
            request_id: id,
            method: HttpMethod::Get,
            path,
            path_len: 4,
            content_length: 0,
            header_size: 50,
            timestamp_ns: 0,
        }
    }

    #[test]
    fn test_queued_gateway() {
        let mut gw = QueuedGateway::<64>::new();
        gw.enqueue_request(&make_request(1, 1)).unwrap();
        gw.enqueue_request(&make_request(1, 2)).unwrap();

        assert_eq!(gw.pending(), 2);

        let (payload, result) = gw.process_next().unwrap();
        assert_eq!(result, GapResult::Accept);
        assert_eq!(&payload, b"/api");

        assert_eq!(gw.total_processed(), 1);
    }
}
