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
            rate_limit: 100.0,   // 100 req/s per client
            rate_burst: 20,      // Burst of 20
            queue_quantum: 1500, // MTU-sized quantum
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

    fn new() -> Self {
        Self(Self::OFFSET)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

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
        self.backends.iter().filter_map(|b| b.as_ref()).find(|b| b.id == id && b.healthy)
    }

    /// Find matching route
    fn find_route(&mut self, path: &[u8], method: HttpMethod) -> Option<&mut Route> {
        for route in &mut self.routes[..self.route_count] {
            if let Some(r) = route {
                if r.matches(path, method) {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Hash client identifier (IP, API key, etc.)
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
        match self.rate_limiter.check(request.client_hash, request.timestamp_ns) {
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
        for backend in &mut self.backends {
            if let Some(b) = backend {
                if b.id == backend_id {
                    b.healthy = false;
                    break;
                }
            }
        }
    }

    /// Mark backend as healthy
    pub fn mark_healthy(&mut self, backend_id: u32) {
        for backend in &mut self.backends {
            if let Some(b) = backend {
                if b.id == backend_id {
                    b.healthy = true;
                    break;
                }
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
        assert!(matches!(decision, GatewayDecision::Forward { backend_id: 1 }));
    }

    #[test]
    fn test_gateway_rate_limiting() {
        let mut config = GatewayConfig::default();
        config.rate_limit = 2.0; // 2 req/s
        config.rate_burst = 2;   // Burst of 2

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
}
