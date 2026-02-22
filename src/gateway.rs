//! API Gateway - Integration Layer
//!
//! Combines GCRA rate limiting, SFQ fair queuing, and zero-copy routing
//! into a cohesive API gateway.
//!
//! ## Request Flow
//!
//! ```text
//! Client → [Parse Headers] → [Rate Limit (GCRA)]
//!                                   ↓
//!                          [Fair Queue (SFQ)]
//!                                   ↓
//!                          [Route Selection]
//!                                   ↓
//!                          [Zero-Copy Forward]
//!                                   ↓
//!                               Backend
//! ```

use crate::gcra::{GcraDecision, GcraRegistry};
use crate::routing::HttpMethod;
use crate::sfq::{QueuedRequest, SfqStats, StochasticFairQueue};

// ============================================================================
// Configuration
// ============================================================================

/// Gateway configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Rate limit: requests per second per client
    pub rate_limit: f64,
    /// Rate limit burst size
    pub rate_burst: u32,
    /// Queue quantum (bytes per DRR round)
    pub queue_quantum: usize,
    /// Maximum request body size
    pub max_body_size: usize,
    /// Request timeout in nanoseconds
    pub timeout_ns: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            rate_limit: 100.0,               // 100 req/s per client
            rate_burst: 20,                  // Burst of 20
            queue_quantum: 1500,             // MTU-sized quantum
            max_body_size: 10 * 1024 * 1024, // 10 MB
            timeout_ns: 30_000_000_000,      // 30 seconds
        }
    }
}

// ============================================================================
// Backend routing
// ============================================================================

/// Backend server definition
#[derive(Debug, Clone)]
pub struct Backend {
    /// Backend identifier
    pub id: u32,
    /// Host address
    pub host: [u8; 64],
    /// Host length
    pub host_len: usize,
    /// Port
    pub port: u16,
    /// Weight for load balancing
    pub weight: u32,
    /// Is backend healthy?
    pub healthy: bool,
}

impl Backend {
    pub fn new(id: u32, host: &[u8], port: u16) -> Self {
        let mut host_buf = [0u8; 64];
        let len = host.len().min(64);
        host_buf[..len].copy_from_slice(&host[..len]);

        Self {
            id,
            host: host_buf,
            host_len: len,
            port,
            weight: 1,
            healthy: true,
        }
    }

    pub fn host(&self) -> &[u8] {
        &self.host[..self.host_len]
    }
}

/// Route definition
#[derive(Debug, Clone)]
pub struct Route {
    /// Path prefix to match
    pub path_prefix: [u8; 128],
    /// Path prefix length
    pub prefix_len: usize,
    /// Allowed methods (bitmask)
    pub methods: u16,
    /// Backend IDs for this route
    pub backends: [u32; 8],
    /// Number of backends
    pub backend_count: usize,
    /// Current backend index (for round-robin)
    pub current_backend: usize,
}

impl Route {
    pub fn new(path_prefix: &[u8]) -> Self {
        let mut prefix_buf = [0u8; 128];
        let len = path_prefix.len().min(128);
        prefix_buf[..len].copy_from_slice(&path_prefix[..len]);

        Self {
            path_prefix: prefix_buf,
            prefix_len: len,
            methods: 0xFFFF, // All methods allowed
            backends: [0; 8],
            backend_count: 0,
            current_backend: 0,
        }
    }

    pub fn path_prefix(&self) -> &[u8] {
        &self.path_prefix[..self.prefix_len]
    }

    pub fn add_backend(&mut self, backend_id: u32) {
        if self.backend_count < 8 {
            self.backends[self.backend_count] = backend_id;
            self.backend_count += 1;
        }
    }

    pub fn matches(&self, path: &[u8], method: HttpMethod) -> bool {
        // Check path prefix
        if path.len() < self.prefix_len {
            return false;
        }
        if &path[..self.prefix_len] != self.path_prefix() {
            return false;
        }

        // Check method
        let method_bit = 1u16 << (method as u16);
        (self.methods & method_bit) != 0
    }

    /// Get next backend (round-robin)
    pub fn next_backend(&mut self) -> Option<u32> {
        if self.backend_count == 0 {
            return None;
        }
        let backend_id = self.backends[self.current_backend];
        self.current_backend = (self.current_backend + 1) % self.backend_count;
        Some(backend_id)
    }
}

// ============================================================================
// Gateway Request/Response
// ============================================================================

/// Incoming request (parsed headers)
#[derive(Debug)]
pub struct GatewayRequest {
    /// Client identifier hash (IP hash, API key hash, etc.)
    pub client_hash: u64,
    /// Request ID
    pub request_id: u64,
    /// HTTP method
    pub method: HttpMethod,
    /// Request path
    pub path: [u8; 256],
    /// Path length
    pub path_len: usize,
    /// Content length (body size)
    pub content_length: usize,
    /// Header size
    pub header_size: usize,
    /// Timestamp (nanoseconds)
    pub timestamp_ns: u64,
}

impl GatewayRequest {
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// Gateway response/decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayDecision {
    /// Forward to backend
    Forward { backend_id: u32 },
    /// Request queued for later processing
    Queued,
    /// Rate limited - retry after given nanoseconds
    RateLimited { retry_after_ns: u64 },
    /// No matching route
    NotFound,
    /// Method not allowed
    MethodNotAllowed,
    /// Request too large
    PayloadTooLarge,
    /// Authentication failed (Ed25519 signature invalid)
    Unauthorized,
    /// Body decryption failed (XChaCha20-Poly1305)
    DecryptFailed,
    /// Internal error
    InternalError,
}

// ============================================================================
// Gateway Core
// ============================================================================

/// FNV-1a hasher for client ID hashing
struct FnvHash(u64);

impl FnvHash {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    #[inline(always)]
    fn new() -> Self {
        Self(Self::OFFSET)
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        // Avalanche mixer
        let mut h = self.0;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        h
    }
}

/// API Gateway
///
/// # Type Parameters
/// * `RATE_SLOTS` - Number of rate limiter slots (LRU cache size)
/// * `SFQ_QUEUES` - Number of fair queue buckets
/// * `SFQ_DEPTH` - Depth of each fair queue
/// * `MAX_ROUTES` - Maximum number of routes
/// * `MAX_BACKENDS` - Maximum number of backends
pub struct Gateway<
    const RATE_SLOTS: usize,
    const SFQ_QUEUES: usize,
    const SFQ_DEPTH: usize,
    const MAX_ROUTES: usize,
    const MAX_BACKENDS: usize,
> {
    /// Configuration
    config: GatewayConfig,
    /// Rate limiter registry
    rate_limiter: GcraRegistry<RATE_SLOTS>,
    /// Fair queue
    queue: StochasticFairQueue<SFQ_QUEUES, SFQ_DEPTH>,
    /// Routes
    routes: [Option<Route>; MAX_ROUTES],
    /// Number of routes
    route_count: usize,
    /// Backends
    backends: [Option<Backend>; MAX_BACKENDS],
    /// Number of backends
    backend_count: usize,
    /// Request counter (for ID generation)
    request_counter: u64,
    /// Statistics
    stats: GatewayStats,
}

/// Gateway statistics
#[derive(Debug, Default, Clone, Copy)]
pub struct GatewayStats {
    pub requests_total: u64,
    pub requests_forwarded: u64,
    pub requests_rate_limited: u64,
    pub requests_queued: u64,
    pub requests_not_found: u64,
    pub bytes_forwarded: u64,
}

impl<
        const RATE_SLOTS: usize,
        const SFQ_QUEUES: usize,
        const SFQ_DEPTH: usize,
        const MAX_ROUTES: usize,
        const MAX_BACKENDS: usize,
    > Gateway<RATE_SLOTS, SFQ_QUEUES, SFQ_DEPTH, MAX_ROUTES, MAX_BACKENDS>
{
    const NONE_ROUTE: Option<Route> = None;
    const NONE_BACKEND: Option<Backend> = None;

    /// Create a new gateway with configuration
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            rate_limiter: GcraRegistry::new(config.rate_limit, config.rate_burst),
            queue: StochasticFairQueue::new(config.queue_quantum),
            config,
            routes: [Self::NONE_ROUTE; MAX_ROUTES],
            route_count: 0,
            backends: [Self::NONE_BACKEND; MAX_BACKENDS],
            backend_count: 0,
            request_counter: 0,
            stats: GatewayStats::default(),
        }
    }

    /// Add a backend
    pub fn add_backend(&mut self, backend: Backend) -> Option<u32> {
        if self.backend_count >= MAX_BACKENDS {
            return None;
        }
        let id = backend.id;
        self.backends[self.backend_count] = Some(backend);
        self.backend_count += 1;
        Some(id)
    }

    /// Add a route
    pub fn add_route(&mut self, route: Route) -> bool {
        if self.route_count >= MAX_ROUTES {
            return false;
        }
        self.routes[self.route_count] = Some(route);
        self.route_count += 1;
        true
    }

    /// Find backend by ID
    fn get_backend(&self, id: u32) -> Option<&Backend> {
        self.backends
            .iter()
            .filter_map(|b| b.as_ref())
            .find(|b| b.id == id && b.healthy)
    }

    /// Find matching route
    fn find_route(&mut self, path: &[u8], method: HttpMethod) -> Option<&mut Route> {
        self.routes[..self.route_count]
            .iter_mut()
            .flatten()
            .find(|r| r.matches(path, method))
    }

    /// Hash client identifier (IP, API key, etc.)
    #[inline(always)]
    pub fn hash_client(identifier: &[u8]) -> u64 {
        let mut h = FnvHash::new();
        h.write(identifier);
        h.finish()
    }

    /// Process an incoming request
    ///
    /// Returns a decision on how to handle the request
    pub fn process(&mut self, request: &GatewayRequest) -> GatewayDecision {
        self.stats.requests_total += 1;

        // 1. Check payload size
        if request.content_length > self.config.max_body_size {
            return GatewayDecision::PayloadTooLarge;
        }

        // 2. Rate limiting
        match self
            .rate_limiter
            .check(request.client_hash, request.timestamp_ns)
        {
            GcraDecision::Allow { .. } => {}
            GcraDecision::Deny { retry_after_ns } => {
                self.stats.requests_rate_limited += 1;
                return GatewayDecision::RateLimited { retry_after_ns };
            }
        }

        // 3. Route matching
        let route = match self.find_route(request.path(), request.method) {
            Some(r) => r,
            None => {
                self.stats.requests_not_found += 1;
                return GatewayDecision::NotFound;
            }
        };

        // 4. Select backend
        let backend_id = match route.next_backend() {
            Some(id) => id,
            None => return GatewayDecision::InternalError,
        };

        // Verify backend exists and is healthy
        if self.get_backend(backend_id).is_none() {
            return GatewayDecision::InternalError;
        }

        self.stats.requests_forwarded += 1;
        GatewayDecision::Forward { backend_id }
    }

    /// Enqueue request for deferred processing
    pub fn enqueue(&mut self, request: &GatewayRequest) -> bool {
        let queued = QueuedRequest::new(
            request.client_hash,
            request.content_length + request.header_size,
            request.request_id,
            request.timestamp_ns,
        );

        if self.queue.enqueue(queued) {
            self.stats.requests_queued += 1;
            true
        } else {
            false
        }
    }

    /// Dequeue next request for processing
    pub fn dequeue(&mut self) -> Option<QueuedRequest> {
        self.queue.dequeue()
    }

    /// Get gateway statistics
    pub fn stats(&self) -> GatewayStats {
        self.stats
    }

    /// Get queue statistics
    pub fn queue_stats(&self) -> SfqStats {
        self.queue.stats()
    }

    /// Get current queue length
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Generate next request ID
    pub fn next_request_id(&mut self) -> u64 {
        self.request_counter += 1;
        self.request_counter
    }

    /// Rotate SFQ hash seed (call periodically)
    pub fn rotate_queue_seed(&mut self, seed: u64) {
        self.queue.rotate_seed(seed);
    }

    /// Mark backend as unhealthy
    pub fn mark_unhealthy(&mut self, backend_id: u32) {
        for b in self.backends.iter_mut().flatten() {
            if b.id == backend_id {
                b.healthy = false;
                break;
            }
        }
    }

    /// Mark backend as healthy
    pub fn mark_healthy(&mut self, backend_id: u32) {
        for b in self.backends.iter_mut().flatten() {
            if b.id == backend_id {
                b.healthy = true;
                break;
            }
        }
    }
}

// ============================================================================
// Convenience type aliases
// ============================================================================

/// Default gateway configuration
/// - 1024 rate limiter slots
/// - 32 SFQ queues with depth 64
/// - 64 routes, 16 backends
pub type DefaultGateway = Gateway<1024, 32, 64, 64, 16>;

/// Lightweight gateway for edge deployments
/// - 256 rate limiter slots
/// - 16 SFQ queues with depth 32
/// - 16 routes, 8 backends
pub type EdgeGateway = Gateway<256, 16, 32, 16, 8>;

/// Minimal gateway for testing
/// - 64 rate limiter slots
/// - 8 SFQ queues with depth 16
/// - 8 routes, 4 backends
pub type TestGateway = Gateway<64, 8, 16, 8, 4>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_basic() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config);

        // Add backend
        let backend = Backend::new(1, b"127.0.0.1", 8080);
        gw.add_backend(backend);

        // Add route
        let mut route = Route::new(b"/api/");
        route.add_backend(1);
        gw.add_route(route);

        // Create request
        let mut path = [0u8; 256];
        path[..10].copy_from_slice(b"/api/users");

        let request = GatewayRequest {
            client_hash: Gateway::<1, 1, 1, 1, 1>::hash_client(b"192.168.1.1"),
            request_id: 1,
            method: HttpMethod::Get,
            path,
            path_len: 10,
            content_length: 0,
            header_size: 100,
            timestamp_ns: 0,
        };

        // Process
        let decision = gw.process(&request);
        assert!(matches!(
            decision,
            GatewayDecision::Forward { backend_id: 1 }
        ));
    }

    #[test]
    fn test_gateway_rate_limiting() {
        let mut config = GatewayConfig::default();
        config.rate_limit = 2.0; // 2 req/s
        config.rate_burst = 2; // Burst of 2

        let mut gw = TestGateway::new(config);

        // Add backend and route
        gw.add_backend(Backend::new(1, b"localhost", 8080));
        let mut route = Route::new(b"/");
        route.add_backend(1);
        gw.add_route(route);

        let client_hash = Gateway::<1, 1, 1, 1, 1>::hash_client(b"test-client");

        // First 2 requests should pass (burst)
        for i in 0..2 {
            let mut path = [0u8; 256];
            path[0] = b'/';
            let request = GatewayRequest {
                client_hash,
                request_id: i + 1,
                method: HttpMethod::Get,
                path,
                path_len: 1,
                content_length: 0,
                header_size: 100,
                timestamp_ns: 0,
            };
            let decision = gw.process(&request);
            assert!(
                matches!(decision, GatewayDecision::Forward { .. }),
                "Request {} should be forwarded",
                i
            );
        }

        // 3rd request should be rate limited
        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash,
            request_id: 3,
            method: HttpMethod::Get,
            path,
            path_len: 1,
            content_length: 0,
            header_size: 100,
            timestamp_ns: 0,
        };
        let decision = gw.process(&request);
        assert!(matches!(decision, GatewayDecision::RateLimited { .. }));
    }

    #[test]
    fn test_gateway_not_found() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config);

        // No routes configured
        let mut path = [0u8; 256];
        path[..8].copy_from_slice(b"/unknown");

        let request = GatewayRequest {
            client_hash: 12345,
            request_id: 1,
            method: HttpMethod::Get,
            path,
            path_len: 8,
            content_length: 0,
            header_size: 100,
            timestamp_ns: 0,
        };

        let decision = gw.process(&request);
        assert_eq!(decision, GatewayDecision::NotFound);
    }

    #[test]
    fn test_route_matching() {
        let route = Route::new(b"/api/v1/");

        assert!(route.matches(b"/api/v1/users", HttpMethod::Get));
        assert!(route.matches(b"/api/v1/", HttpMethod::Post));
        assert!(!route.matches(b"/api/v2/", HttpMethod::Get));
        assert!(!route.matches(b"/other", HttpMethod::Get));
    }

    #[test]
    fn test_gateway_config_default() {
        let config = GatewayConfig::default();
        assert_eq!(config.rate_limit, 100.0);
        assert_eq!(config.rate_burst, 20);
        assert_eq!(config.queue_quantum, 1500);
        assert_eq!(config.max_body_size, 10 * 1024 * 1024);
        assert_eq!(config.timeout_ns, 30_000_000_000);
    }

    #[test]
    fn test_backend_new() {
        let b = Backend::new(42, b"localhost", 9090);
        assert_eq!(b.id, 42);
        assert_eq!(b.host(), b"localhost");
        assert_eq!(b.port, 9090);
        assert_eq!(b.weight, 1);
        assert!(b.healthy);
    }

    #[test]
    fn test_backend_host_truncation() {
        // Host longer than 64 bytes should be truncated
        let long_host = [b'a'; 100];
        let b = Backend::new(1, &long_host, 8080);
        assert_eq!(b.host_len, 64);
    }

    #[test]
    fn test_route_new_and_prefix() {
        let route = Route::new(b"/healthz");
        assert_eq!(route.path_prefix(), b"/healthz");
        assert_eq!(route.prefix_len, 8);
        assert_eq!(route.backend_count, 0);
    }

    #[test]
    fn test_route_add_backend_limit() {
        let mut route = Route::new(b"/api/");

        // Can add up to 8 backends
        for i in 1u32..=8 {
            route.add_backend(i);
        }
        assert_eq!(route.backend_count, 8);

        // 9th add should be silently ignored
        route.add_backend(999);
        assert_eq!(route.backend_count, 8);
    }

    #[test]
    fn test_route_next_backend_round_robin() {
        let mut route = Route::new(b"/");
        route.add_backend(10);
        route.add_backend(20);
        route.add_backend(30);

        // Round-robin through backends
        assert_eq!(route.next_backend(), Some(10));
        assert_eq!(route.next_backend(), Some(20));
        assert_eq!(route.next_backend(), Some(30));
        assert_eq!(route.next_backend(), Some(10)); // wraps around
    }

    #[test]
    fn test_route_next_backend_empty() {
        let mut route = Route::new(b"/");
        assert_eq!(route.next_backend(), None);
    }

    #[test]
    fn test_route_path_prefix_truncation() {
        // Path prefix longer than 128 bytes should be truncated
        let long_prefix = [b'/'; 200];
        let route = Route::new(&long_prefix);
        assert_eq!(route.prefix_len, 128);
    }

    #[test]
    fn test_gateway_payload_too_large() {
        let mut config = GatewayConfig::default();
        config.max_body_size = 1024;

        let mut gw = TestGateway::new(config);
        gw.add_backend(Backend::new(1, b"localhost", 8080));
        let mut route = Route::new(b"/");
        route.add_backend(1);
        gw.add_route(route);

        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash: 1,
            request_id: 1,
            method: HttpMethod::Post,
            path,
            path_len: 1,
            content_length: 2048, // exceeds 1024 limit
            header_size: 100,
            timestamp_ns: 0,
        };

        assert_eq!(gw.process(&request), GatewayDecision::PayloadTooLarge);
    }

    #[test]
    fn test_gateway_unhealthy_backend() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config);

        gw.add_backend(Backend::new(1, b"localhost", 8080));
        let mut route = Route::new(b"/");
        route.add_backend(1);
        gw.add_route(route);

        // Mark backend unhealthy
        gw.mark_unhealthy(1);

        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash: 1,
            request_id: 1,
            method: HttpMethod::Get,
            path,
            path_len: 1,
            content_length: 0,
            header_size: 50,
            timestamp_ns: 0,
        };

        // Should fail because backend is unhealthy
        let decision = gw.process(&request);
        assert_eq!(decision, GatewayDecision::InternalError);

        // Mark healthy again
        gw.mark_healthy(1);
        let decision = gw.process(&request);
        assert!(matches!(
            decision,
            GatewayDecision::Forward { backend_id: 1 }
        ));
    }

    #[test]
    fn test_gateway_enqueue_dequeue() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config);

        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash: 42,
            request_id: 1,
            method: HttpMethod::Post,
            path,
            path_len: 1,
            content_length: 512,
            header_size: 100,
            timestamp_ns: 0,
        };

        // Enqueue
        assert!(gw.enqueue(&request));
        assert_eq!(gw.queue_len(), 1);

        // Dequeue
        let dequeued = gw.dequeue();
        assert!(dequeued.is_some());
        assert_eq!(gw.queue_len(), 0);

        // Next dequeue should be None
        assert!(gw.dequeue().is_none());
    }

    #[test]
    fn test_gateway_stats_tracking() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config);

        gw.add_backend(Backend::new(1, b"localhost", 8080));
        let mut route = Route::new(b"/api/");
        route.add_backend(1);
        gw.add_route(route);

        // Request to known route
        let mut path = [0u8; 256];
        path[..5].copy_from_slice(b"/api/");
        let req_fwd = GatewayRequest {
            client_hash: 1,
            request_id: 1,
            method: HttpMethod::Get,
            path,
            path_len: 5,
            content_length: 0,
            header_size: 50,
            timestamp_ns: 0,
        };
        gw.process(&req_fwd);

        // Request to unknown route
        let mut path2 = [0u8; 256];
        path2[..4].copy_from_slice(b"/nop");
        let req_404 = GatewayRequest {
            client_hash: 2,
            request_id: 2,
            method: HttpMethod::Get,
            path: path2,
            path_len: 4,
            content_length: 0,
            header_size: 50,
            timestamp_ns: 0,
        };
        gw.process(&req_404);

        let stats = gw.stats();
        assert_eq!(stats.requests_total, 2);
        assert_eq!(stats.requests_forwarded, 1);
        assert_eq!(stats.requests_not_found, 1);
    }

    #[test]
    fn test_gateway_next_request_id_monotonic() {
        let mut gw = TestGateway::new(GatewayConfig::default());
        let id1 = gw.next_request_id();
        let id2 = gw.next_request_id();
        let id3 = gw.next_request_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_gateway_rotate_queue_seed() {
        let mut gw = TestGateway::new(GatewayConfig::default());
        // Rotating seed should not panic
        gw.rotate_queue_seed(0xDEAD_BEEF_CAFE);
    }

    #[test]
    fn test_gateway_hash_client_determinism() {
        let h1 = TestGateway::hash_client(b"192.168.1.100");
        let h2 = TestGateway::hash_client(b"192.168.1.100");
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
    }

    #[test]
    fn test_gateway_hash_client_distinct() {
        let h1 = TestGateway::hash_client(b"10.0.0.1");
        let h2 = TestGateway::hash_client(b"10.0.0.2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_gateway_decision_equality() {
        assert_eq!(
            GatewayDecision::Forward { backend_id: 1 },
            GatewayDecision::Forward { backend_id: 1 },
        );
        assert_ne!(
            GatewayDecision::Forward { backend_id: 1 },
            GatewayDecision::Forward { backend_id: 2 },
        );
        assert_eq!(GatewayDecision::NotFound, GatewayDecision::NotFound);
        assert_ne!(GatewayDecision::NotFound, GatewayDecision::InternalError);
        assert_eq!(
            GatewayDecision::RateLimited {
                retry_after_ns: 100
            },
            GatewayDecision::RateLimited {
                retry_after_ns: 100
            },
        );
    }

    #[test]
    fn test_gateway_stats_default() {
        let stats = GatewayStats::default();
        assert_eq!(stats.requests_total, 0);
        assert_eq!(stats.requests_forwarded, 0);
        assert_eq!(stats.requests_rate_limited, 0);
        assert_eq!(stats.requests_queued, 0);
        assert_eq!(stats.requests_not_found, 0);
        assert_eq!(stats.bytes_forwarded, 0);
    }

    #[test]
    fn test_gateway_add_backend_limit() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config); // MAX_BACKENDS = 4

        // TestGateway has MAX_BACKENDS=4
        assert!(gw.add_backend(Backend::new(1, b"a", 1)).is_some());
        assert!(gw.add_backend(Backend::new(2, b"b", 2)).is_some());
        assert!(gw.add_backend(Backend::new(3, b"c", 3)).is_some());
        assert!(gw.add_backend(Backend::new(4, b"d", 4)).is_some());

        // 5th backend should fail
        assert!(gw.add_backend(Backend::new(5, b"e", 5)).is_none());
    }

    #[test]
    fn test_gateway_add_route_limit() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config); // MAX_ROUTES = 8

        for i in 0..8 {
            let prefix = [b'/', b'a' + i as u8];
            assert!(gw.add_route(Route::new(&prefix)));
        }

        // 9th route should fail
        assert!(!gw.add_route(Route::new(b"/z")));
    }

    #[test]
    fn test_gateway_queue_stats() {
        let config = GatewayConfig::default();
        let mut gw = TestGateway::new(config);

        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash: 1,
            request_id: 1,
            method: HttpMethod::Get,
            path,
            path_len: 1,
            content_length: 100,
            header_size: 50,
            timestamp_ns: 0,
        };

        gw.enqueue(&request);
        let qs = gw.queue_stats();
        assert_eq!(qs.enqueued, 1);
    }

    #[test]
    fn test_gateway_request_path_accessor() {
        let mut path_buf = [0u8; 256];
        path_buf[..7].copy_from_slice(b"/health");

        let request = GatewayRequest {
            client_hash: 0,
            request_id: 0,
            method: HttpMethod::Get,
            path: path_buf,
            path_len: 7,
            content_length: 0,
            header_size: 0,
            timestamp_ns: 0,
        };

        assert_eq!(request.path(), b"/health");
    }

    #[test]
    fn test_fnv_hash_nonzero() {
        // FnvHash of any non-empty input should produce non-zero output
        let mut h = FnvHash::new();
        h.write(b"test-client-ip");
        assert_ne!(h.finish(), 0);
    }

    #[test]
    fn test_fnv_hash_determinism() {
        let mut h1 = FnvHash::new();
        let mut h2 = FnvHash::new();
        h1.write(b"192.168.0.1");
        h2.write(b"192.168.0.1");
        assert_eq!(h1.finish(), h2.finish());
    }
}
