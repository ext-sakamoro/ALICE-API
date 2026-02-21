//! # ALICE-API
//!
//! **High-Performance API Gateway with Distributed Rate Limiting**
//!
//! A Rust library providing the core components for building an API gateway
//! with mathematical fairness guarantees and zero-copy performance.
//!
//! ## Features
//!
//! | Feature | Description | Complexity |
//! |---------|-------------|------------|
//! | **GCRA Rate Limiting** | Distributed, CRDT-mergeable rate limiting | O(1) |
//! | **Stochastic Fair Queuing** | Probabilistic fairness with DRR | O(1) |
//! | **Zero-Copy Routing** | splice/sendfile for body forwarding | O(n) bytes, 0 copies |
//!
//! ## Design Principles
//!
//! - **No External Dependencies**: No Redis, no distributed locks
//! - **CRDT State**: Rate limiter state merges with `max(TAT)`
//! - **Kernel Bypass**: Request bodies never touch userspace
//! - **Fixed Memory**: All structures have compile-time size bounds
//!
//! ## Quick Start
//!
//! ### Rate Limiting with GCRA
//!
//! ```rust
//! use alice_api::gcra::GcraCell;
//!
//! // 100 requests/sec with burst of 10
//! let cell = GcraCell::new(100.0, 10);
//!
//! // Check rate limit (now_ns = current time in nanoseconds)
//! let now_ns = 0; // In production, use monotonic clock
//! match cell.check(now_ns) {
//!     alice_api::gcra::GcraDecision::Allow { reset_after_ns } => {
//!         println!("Request allowed, resets in {}ns", reset_after_ns);
//!     }
//!     alice_api::gcra::GcraDecision::Deny { retry_after_ns } => {
//!         println!("Rate limited, retry in {}ns", retry_after_ns);
//!     }
//! }
//! ```
//!
//! ### Fair Queuing with SFQ
//!
//! ```rust
//! use alice_api::sfq::{StochasticFairQueue, QueuedRequest};
//!
//! // 16 queues, depth 64, quantum 1500 bytes
//! let mut sfq = StochasticFairQueue::<16, 64>::new(1500);
//!
//! // Enqueue requests from different clients
//! sfq.enqueue(QueuedRequest::new(0xAAAA, 512, 1, 0)); // Client A
//! sfq.enqueue(QueuedRequest::new(0xBBBB, 512, 2, 0)); // Client B
//!
//! // Dequeue fairly
//! while let Some(req) = sfq.dequeue() {
//!     println!("Processing request {} from flow {:x}", req.id, req.flow_hash);
//! }
//! ```
//!
//! ### Integrated Gateway
//!
//! ```rust
//! use alice_api::gateway::{GatewayConfig, Backend, Route, GatewayRequest, GatewayDecision};
//! use alice_api::routing::HttpMethod;
//!
//! // Create gateway
//! let config = GatewayConfig::default();
//! let mut gw = alice_api::gateway::EdgeGateway::new(config);
//!
//! // Add backend
//! gw.add_backend(Backend::new(1, b"127.0.0.1", 8080));
//!
//! // Add route
//! let mut route = Route::new(b"/api/");
//! route.add_backend(1);
//! gw.add_route(route);
//!
//! // Process request
//! let mut path = [0u8; 256];
//! path[..10].copy_from_slice(b"/api/users");
//!
//! let request = GatewayRequest {
//!     client_hash: 12345,
//!     request_id: 1,
//!     method: HttpMethod::Get,
//!     path,
//!     path_len: 10,
//!     content_length: 0,
//!     header_size: 100,
//!     timestamp_ns: 0,
//! };
//!
//! match gw.process(&request) {
//!     GatewayDecision::Forward { backend_id } => {
//!         println!("Forward to backend {}", backend_id);
//!     }
//!     GatewayDecision::RateLimited { retry_after_ns } => {
//!         println!("Rate limited, retry after {}ns", retry_after_ns);
//!     }
//!     _ => {}
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod gcra;
pub mod sfq;
pub mod routing;
pub mod gateway;
#[cfg(any(feature = "auth", feature = "crypto"))]
pub mod middleware;
#[cfg(feature = "queue")]
pub mod queue_bridge;
#[cfg(feature = "analytics")]
pub mod analytics_bridge;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::gcra::{GcraCell, GcraDecision, GcraRegistry};
    pub use crate::sfq::{
        StochasticFairQueue, QueuedRequest, SfqStats, WeightedSfq,
        ShardedSfq, SfqShard,
    };
    pub use crate::routing::{
        HttpMethod, RequestLine, SpliceError, ZeroCopyForwarder,
        BatchedForwarder, SpliceOp, SpliceBatchResult,
        parse_request_line, find_content_length, find_header_end,
    };
    pub use crate::gateway::{
        Gateway, GatewayConfig, GatewayDecision, GatewayRequest, GatewayStats,
        Backend, Route, DefaultGateway, EdgeGateway, TestGateway,
    };

    #[cfg(feature = "auth")]
    pub use crate::middleware::{AuthContext, AliceId, AliceSig};

    #[cfg(feature = "crypto")]
    pub use crate::middleware::{decrypt_body, decrypt_body_aead, Key, Nonce, CipherError, TAG_SIZE};

    #[cfg(all(feature = "auth", feature = "crypto"))]
    pub use crate::middleware::{
        SecureGateway, SecureStats,
        DefaultSecureGateway, EdgeSecureGateway, TestSecureGateway,
    };
}

// Re-export main types at crate root
pub use prelude::*;

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_gcra_basic_usage() {
        let cell = GcraCell::new(10.0, 5); // 10 req/s, burst 5

        // First 5 should pass
        for _ in 0..5 {
            assert!(matches!(cell.check(0), GcraDecision::Allow { .. }));
        }

        // 6th should fail at time 0
        assert!(matches!(cell.check(0), GcraDecision::Deny { .. }));
    }

    #[test]
    fn test_sfq_fair_dequeue() {
        let mut sfq = StochasticFairQueue::<8, 32>::new(1024);

        // Enqueue from two flows
        for i in 0..5 {
            sfq.enqueue(QueuedRequest::new(1, 100, i, 0));
            sfq.enqueue(QueuedRequest::new(2, 100, 10 + i, 0));
        }

        assert_eq!(sfq.len(), 10);

        // Dequeue all
        let mut count = 0;
        while sfq.dequeue().is_some() {
            count += 1;
        }
        assert_eq!(count, 10);
    }

    #[test]
    fn test_request_parsing() {
        let buf = b"POST /api/data HTTP/1.1\r\nContent-Length: 42\r\n\r\n{\"key\":\"value\"}";

        let (req, _) = parse_request_line(buf).unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.path, b"/api/data");

        let header_end = find_header_end(buf).unwrap();
        let headers = &buf[..header_end];
        assert_eq!(find_content_length(headers), Some(42));
    }

    #[test]
    fn test_gateway_integration() {
        let mut gw = TestGateway::new(GatewayConfig::default());

        // Setup
        gw.add_backend(Backend::new(1, b"localhost", 8080));
        let mut route = Route::new(b"/");
        route.add_backend(1);
        gw.add_route(route);

        // Process request
        let mut path = [0u8; 256];
        path[0] = b'/';

        let request = GatewayRequest {
            client_hash: 12345,
            request_id: gw.next_request_id(),
            method: HttpMethod::Get,
            path,
            path_len: 1,
            content_length: 0,
            header_size: 50,
            timestamp_ns: 0,
        };

        let decision = gw.process(&request);
        assert!(matches!(decision, GatewayDecision::Forward { backend_id: 1 }));

        // Check stats
        let stats = gw.stats();
        assert_eq!(stats.requests_total, 1);
        assert_eq!(stats.requests_forwarded, 1);
    }

    #[test]
    fn test_distributed_rate_limit_merge() {
        // Simulate two nodes
        let node1 = GcraCell::new(10.0, 5);
        let node2 = GcraCell::new(10.0, 5);

        // Node 1 processes requests
        for _ in 0..3 {
            node1.check(0);
        }

        // Node 2 processes requests
        for _ in 0..5 {
            node2.check(0);
        }

        // Merge: node1 learns about node2's state
        node1.merge(node2.tat());

        // node1 should now have the higher TAT (merged state)
        assert_eq!(node1.tat(), node2.tat());

        // Further requests should be limited based on merged state
        assert!(matches!(node1.check(0), GcraDecision::Deny { .. }));
    }
}
