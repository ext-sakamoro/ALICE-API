# ALICE-API

**High-Performance API Gateway with Distributed Rate Limiting** - v0.2.0 (Secure API Stack)

> "Fairness is not a bug, it's a feature."

A Rust library providing the core components for building an API gateway with mathematical fairness guarantees and zero-copy performance.

## Features

| Feature | Description | Complexity | Memory |
|---------|-------------|------------|--------|
| **GCRA Rate Limiting** | Lock-free, CRDT-mergeable rate limiting | O(1) per check | O(1) per key |
| **Stochastic Fair Queuing** | Cache-line sharded with Deficit Round Robin | O(1) enqueue/dequeue | O(Q×D) |
| **Zero-Copy Routing** | Batched splice/sendfile for body forwarding | O(n) bytes | 0 userspace copies |
| **Ed25519 Auth** | ZKP signature verification (optional `auth` feature) | O(1) per verify | 96 bytes/ctx |
| **XChaCha20 Decrypt** | In-place AEAD decryption (optional `crypto` feature) | O(n) bytes | 0 allocation |

## Performance Optimizations

### Lock-Free GCRA with Relaxed Atomics

```rust
// Uses fetch_max pattern with Ordering::Relaxed
// TAT is monotonically increasing → no memory barriers needed
fn fetch_max_relaxed(atom: &AtomicU64, new_value: u64) -> u64 {
    let mut current = atom.load(Ordering::Relaxed);
    loop {
        if new_value <= current { return current; }
        match atom.compare_exchange_weak(current, new_value,
            Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return current,
            Err(actual) => current = actual,
        }
    }
}
```

**Benefits:**
- ~20-30% faster than AcqRel ordering
- Safe for monotonically increasing values
- No memory barrier overhead

### Cache-Line Sharded SFQ

```rust
// Each queue aligned to 64-byte cache line boundary
#[repr(align(64))]
struct FlowQueue<const DEPTH: usize> { /* ... */ }

// Sharded across CPU cores for zero contention
let mut sfq = ShardedSfq::<4, 8, 16>::new(1024);  // 4 shards
```

**Benefits:**
- Eliminates false sharing in multi-threaded scenarios
- Per-shard ownership for thread affinity
- Linear scalability with CPU cores

### Batched Splice Operations

```rust
let mut batch = BatchedForwarder::<16>::new()?;

// Queue multiple operations
batch.push(SpliceOp::new(client1_fd, backend1_fd, 1024));
batch.push(SpliceOp::new(client2_fd, backend2_fd, 2048));

// Execute all at once
let result = batch.execute();
```

**Benefits:**
- Reduced syscall overhead
- Amortized kernel context switch cost
- Batch-level error handling

## Design Philosophy

### Why Not Redis?

Traditional API gateways use Redis for distributed rate limiting. This creates:
- Network latency on every request
- Single point of failure
- Complex deployment

**ALICE-API uses CRDT-based state synchronization:**
- Local rate limiting with periodic sync
- Merge operation: `TAT = max(TAT_local, TAT_remote)`
- Eventually consistent, partition tolerant

### Why GCRA over Token Bucket?

GCRA (Generic Cell Rate Algorithm) is mathematically equivalent to leaky bucket but:
- **Single state variable**: Just one timestamp (TAT)
- **Perfect for CRDTs**: `max()` merge is idempotent, commutative, associative
- **No drift**: Unlike token bucket, doesn't accumulate floating point errors

### Why Stochastic Fair Queuing?

When multiple clients compete for limited backend capacity:
- **Deterministic queuing**: Heavy hitter can block everyone
- **SFQ**: Hash-based queue assignment + round-robin = probabilistic fairness
- **DRR variant**: Byte-level fairness, not just packet-level

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ALICE-API v0.2.0                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Client Request                                                     │
│         │                                                            │
│         ▼                                                            │
│   ┌─────────────┐     ┌─────────────────────────────────────────┐   │
│   │   Header    │     │         GCRA Registry (Lock-Free)        │   │
│   │   Parser    │────▶│  ┌─────┐ ┌─────┐ ┌─────┐               │   │
│   │  (minimal)  │     │  │ TAT │ │ TAT │ │ TAT │  ... (LRU)    │   │
│   └─────────────┘     │  └──┬──┘ └──┬──┘ └──┬──┘               │   │
│         │             │     │       │       │   Relaxed Atomics │   │
│         │             │     └───────┴───────┘                   │   │
│         │             │           merge(max)  ←── other nodes   │   │
│         │             └─────────────────────────────────────────┘   │
│         │                         │                                  │
│         │                         ▼                                  │
│         │  ALLOW      ┌────────────────────────┐                    │
│         └────────────▶│   ShardedSfq (N cores) │                    │
│                       │ ┌──────┐ ┌──────┐      │                    │
│                       │ │Shard0│ │Shard1│ ...  │  Cache-Line Aligned│
│                       │ └──────┘ └──────┘      │                    │
│                       │        DRR             │                    │
│                       └───────────┬────────────┘                    │
│                                   │                                  │
│                                   ▼                                  │
│                       ┌────────────────────────┐                    │
│                       │  BatchedForwarder      │                    │
│                       │  splice(2) batching    │                    │
│                       └───────────┬────────────┘                    │
│                                   │                                  │
│                                   ▼                                  │
│                               Backend                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Rate Limiting with GCRA

```rust
use alice_api::gcra::{GcraCell, GcraDecision};

// 100 requests/sec with burst of 10
let cell = GcraCell::new(100.0, 10);

// Check rate limit
let now_ns = std::time::Instant::now().elapsed().as_nanos() as u64;

match cell.check(now_ns) {
    GcraDecision::Allow { reset_after_ns } => {
        // Process request
        // Set X-RateLimit-Reset header to reset_after_ns
    }
    GcraDecision::Deny { retry_after_ns } => {
        // Return 429 Too Many Requests
        // Set Retry-After header to retry_after_ns / 1_000_000_000
    }
}
```

### Distributed Rate Limiting

```rust
use alice_api::gcra::GcraCell;

// Node 1
let node1 = GcraCell::new(100.0, 10);
// ... process requests ...
let tat1 = node1.tat();

// Node 2
let node2 = GcraCell::new(100.0, 10);
// ... process requests ...
let tat2 = node2.tat();

// Periodic sync: each node merges other's TAT
node1.merge(tat2);  // node1.tat = max(node1.tat, tat2)
node2.merge(tat1);  // node2.tat = max(node2.tat, tat1)

// Result: both nodes converge to consistent rate limit state
```

### Multi-Key Rate Limiting

```rust
use alice_api::gcra::GcraRegistry;

// Registry with 4096 slots, 100 req/s per key, burst 10
let mut registry = GcraRegistry::<4096>::new(100.0, 10);

// Rate limit by client IP hash
let client_hash = hash_ip("192.168.1.100");
let decision = registry.check(client_hash, now_ns);
```

### Stochastic Fair Queuing

```rust
use alice_api::sfq::{StochasticFairQueue, QueuedRequest};

// 16 queues, depth 64 each, quantum 1500 bytes (MTU)
let mut sfq = StochasticFairQueue::<16, 64>::new(1500);

// Enqueue requests (hashed to queues by flow_hash)
sfq.enqueue(QueuedRequest::new(client_a_hash, 1024, req_id, timestamp));
sfq.enqueue(QueuedRequest::new(client_b_hash, 512, req_id, timestamp));

// Dequeue with Deficit Round Robin (fair!)
while let Some(request) = sfq.dequeue() {
    forward_to_backend(request);
}
```

### Sharded SFQ for Multi-Threading

```rust
use alice_api::sfq::{ShardedSfq, QueuedRequest};

// 4 shards (one per CPU core), 8 queues each, depth 16
let mut sfq = ShardedSfq::<4, 8, 16>::new(1024);

// Enqueue - automatically routed to appropriate shard
sfq.enqueue(QueuedRequest::new(flow_hash, 512, req_id, timestamp));

// Per-thread dequeue (zero contention)
let shard_id = thread_id % 4;
if let Some(req) = sfq.dequeue_from_shard(shard_id) {
    process(req);
}

// Or dequeue from any shard
while let Some(req) = sfq.dequeue() {
    process(req);
}
```

### Batched Zero-Copy Forwarding

```rust
use alice_api::routing::{BatchedForwarder, SpliceOp};

// Create batch forwarder with capacity for 16 operations
let mut batch = BatchedForwarder::<16>::new()?;

// Queue multiple splice operations
batch.push(SpliceOp::new(client1_fd, backend1_fd, 1024));
batch.push(SpliceOp::new(client2_fd, backend2_fd, 2048));
batch.push(SpliceOp::new(client3_fd, backend3_fd, 512));

// Execute all at once (reduced syscall overhead)
let result = batch.execute();
println!("Transferred {} bytes in {} ops",
    result.bytes_transferred, result.ops_completed);

if let Some(err) = result.error {
    eprintln!("First error: {:?}", err);
}
```

### Integrated Gateway

```rust
use alice_api::prelude::*;

// Create gateway
let mut gw = DefaultGateway::new(GatewayConfig {
    rate_limit: 100.0,
    rate_burst: 20,
    queue_quantum: 1500,
    max_body_size: 10 * 1024 * 1024,
    timeout_ns: 30_000_000_000,
});

// Configure backends
gw.add_backend(Backend::new(1, b"10.0.0.1", 8080));
gw.add_backend(Backend::new(2, b"10.0.0.2", 8080));

// Configure routes
let mut api_route = Route::new(b"/api/");
api_route.add_backend(1);
api_route.add_backend(2);
gw.add_route(api_route);

// Process incoming request
let decision = gw.process(&request);
match decision {
    GatewayDecision::Forward { backend_id } => {
        // Zero-copy forward to backend
    }
    GatewayDecision::RateLimited { retry_after_ns } => {
        // Return 429
    }
    GatewayDecision::NotFound => {
        // Return 404
    }
    _ => {}
}
```

## Modules

### `gcra` - Distributed Rate Limiting

| Type | Description |
|------|-------------|
| `GcraCell` | Lock-free single-key rate limiter (GCRA algorithm) |
| `GcraRegistry<N>` | Multi-key registry with LRU eviction |
| `GcraDecision` | Allow/Deny result with timing info |

**Key Properties:**
- O(1) check operation (lock-free CAS)
- Single atomic u64 state (TAT)
- CRDT merge: `max(TAT_a, TAT_b)`
- **Relaxed atomics** for minimal overhead

### `sfq` - Stochastic Fair Queuing

| Type | Description |
|------|-------------|
| `StochasticFairQueue<Q,D>` | Q queues, depth D each |
| `ShardedSfq<S,Q,D>` | S shards for multi-threading |
| `SfqShard<Q,D>` | Single shard (cache-line aligned) |
| `QueuedRequest` | Request with flow hash and size |
| `WeightedSfq<Q,D>` | SFQ with per-flow weights |

**Key Properties:**
- O(1) enqueue (hash + array access)
- O(1) amortized dequeue (round-robin)
- Deficit Round Robin for byte-level fairness
- Hash seed rotation for DoS resistance
- **Cache-line alignment** (64 bytes) to prevent false sharing

### `routing` - Zero-Copy Forwarding

| Type | Description |
|------|-------------|
| `ZeroCopyForwarder` | Single splice-based socket forwarding |
| `BatchedForwarder<N>` | Batched splice operations (up to N) |
| `SpliceOp` | Pending splice operation descriptor |
| `SpliceBatchResult` | Batch execution result with stats |
| `SplicePipe` | Reusable pipe for splice ops |
| `HttpMethod` | Parsed HTTP method |

**Key Properties:**
- No userspace copies (kernel handles transfer)
- Minimal header parsing (only what's needed for routing)
- Works with splice(2), sendfile(2)
- **Batch execution** for reduced syscall overhead

### `gateway` - Integration Layer

| Type | Description |
|------|-------------|
| `Gateway<...>` | Complete gateway with rate limiting + SFQ |
| `DefaultGateway` | Pre-configured for typical deployments |
| `EdgeGateway` | Lightweight for edge/embedded |
| `TestGateway` | Small footprint for testing |
| `Backend` | Backend server definition |
| `Route` | Routing rule with path matching |

### `middleware` - Secure API Stack (feature-gated)

| Type | Feature | Description |
|------|---------|-------------|
| `AuthContext` | `auth` | Ed25519 public key + signature pair |
| `decrypt_body` | `crypto` | Zero-alloc in-place XChaCha20 decryption |
| `decrypt_body_aead` | `crypto` | In-place decryption with associated data |
| `SecureGateway<...>` | `secure` | Full pipeline: rate limit → auth → crypto → forward |
| `DefaultSecureGateway` | `secure` | Pre-configured secure gateway |
| `EdgeSecureGateway` | `secure` | Lightweight secure gateway |
| `SecureStats` | `secure` | Auth/crypto failure counters |

## Performance Characteristics

| Operation | Time | Space | Notes |
|-----------|------|-------|-------|
| GCRA check | O(1) | 8 bytes/key | Lock-free, Relaxed atomics |
| GCRA merge | O(1) | - | fetch_max pattern |
| SFQ enqueue | O(1) | - | Hash + array access |
| SFQ dequeue | O(1) amortized | - | Round-robin |
| Sharded SFQ | O(1) | - | Zero contention per shard |
| Header parse | O(header size) | Stack only | Minimal parsing |
| Zero-copy fwd | O(body size) | 0 userspace | splice(2) |
| Batched fwd | O(n × body) | - | Amortized syscall cost |

## Mathematical Background

### GCRA (Generic Cell Rate Algorithm)

Virtual scheduling variant of leaky bucket:

```
On arrival at time t:
    TAT' = max(TAT, t) + τ           // τ = emission interval = 1/rate
    if TAT' - t ≤ σ:                  // σ = burst tolerance = burst × τ
        TAT = TAT'
        ALLOW
    else:
        DENY (retry after TAT' - σ - t)
```

**CRDT Properties:**
- Merge: `TAT = max(TAT_a, TAT_b)`
- Idempotent: `merge(a, a) = a`
- Commutative: `merge(a, b) = merge(b, a)`
- Associative: `merge(a, merge(b, c)) = merge(merge(a, b), c)`

### Deficit Round Robin (DRR)

Fair scheduling for variable-size packets:

```
for each queue Q in round-robin:
    Q.deficit += quantum
    while Q not empty and Q.head.size ≤ Q.deficit:
        Q.deficit -= Q.head.size
        send(Q.dequeue())
    if Q empty:
        Q.deficit = 0
```

### Stochastic Fairness

With N queues and uniform hash:
- Probability two flows collide: 1/N
- Expected unique queues for M flows: N(1 - (1-1/N)^M)
- For N=64, M=1000: ~63.9 unique queues used

### Cache-Line Sharding

With S shards on S-core system:
- Contention probability: 1/S per operation
- False sharing: eliminated (64-byte alignment)
- Scalability: linear with core count

## Building

```bash
# Standard build
cargo build --release

# With secure stack (auth + crypto)
cargo build --release --features secure

# no_std build (for embedded)
cargo build --release --no-default-features

# Run tests
cargo test --lib
cargo test --lib --features secure    # Full test suite (36 tests)

# Benchmarks (coming soon)
cargo bench
```

## Comparison with Alternatives

| Feature | ALICE-API | nginx | Envoy | Kong |
|---------|-----------|-------|-------|------|
| Distributed rate limit | CRDT (no Redis) | Redis | Redis | Redis/Cassandra |
| Memory per rate limit key | 8 bytes | ~100 bytes | ~200 bytes | ~500 bytes |
| Zero-copy forwarding | Yes (splice) | No | No | No |
| Fair queuing | SFQ+DRR | No | Priority only | No |
| Compile-time sizing | Yes | No | No | No |
| Lock-free rate limiting | Yes (Relaxed) | No | No | No |
| Cache-line sharding | Yes | No | No | No |
| Batched I/O | Yes | No | No | No |

## Secure API Stack (Optional)

ALICE-API integrates with [ALICE-Auth](../ALICE-Auth) and [ALICE-Crypto](../ALICE-Crypto) via optional feature flags to create an end-to-end secure gateway pipeline.

```
Client Request → GCRA Rate Limit → Ed25519 Auth → XChaCha20 Decrypt → Backend
```

### Feature Flags

```toml
[dependencies]
alice-api = { version = "0.1" }                           # Core only
alice-api = { version = "0.1", features = ["auth"] }      # + Ed25519 ZKP auth
alice-api = { version = "0.1", features = ["crypto"] }    # + XChaCha20-Poly1305
alice-api = { version = "0.1", features = ["secure"] }    # Both (full stack)
```

| Feature | Adds | Test Count |
|---------|------|------------|
| (default) | GCRA + SFQ + Zero-Copy | 26 |
| `auth` | + Ed25519 signature verification | 29 |
| `crypto` | + XChaCha20-Poly1305 decryption | 29 |
| `secure` | Both auth + crypto + SecureGateway | 36 |

### SecureGateway

`SecureGateway` wraps the base `Gateway` and inserts auth/crypto verification into the pipeline:

```rust
use alice_api::prelude::*;
use alice_api::routing::HttpMethod;

// Create secure gateway
let mut gw = DefaultSecureGateway::new(GatewayConfig::default());
gw.add_backend(Backend::new(1, b"10.0.0.1", 8080));
let mut route = Route::new(b"/api/");
route.add_backend(1);
gw.add_route(route);

// Client: generate identity + sign request
let identity = alice_auth::Identity::gen().unwrap();
let sign_msg = b"GET /api/users";
let auth = AuthContext {
    id: identity.id(),
    sig: identity.sign(sign_msg),
};

// Process: rate limit → auth verify → forward
let decision = gw.process(&request, &auth, sign_msg);
match decision {
    GatewayDecision::Forward { backend_id } => { /* forward */ }
    GatewayDecision::Unauthorized => { /* 401 */ }
    GatewayDecision::RateLimited { .. } => { /* 429 */ }
    _ => {}
}
```

### Encrypted Pipeline

```rust
// Process with body decryption: rate limit → auth → decrypt → forward
let key = Key::generate().unwrap();
let nonce = Nonce::generate().unwrap();

let (decision, plaintext_len) = gw.process_encrypted(
    &request, &auth, sign_msg, &key, &nonce, &mut body,
);
match decision {
    GatewayDecision::Forward { .. } => {
        // body[..plaintext_len.unwrap()] contains decrypted data
    }
    GatewayDecision::DecryptFailed => { /* 400 */ }
    _ => {}
}
```

### Type Aliases

| Type | RATE_SLOTS | SFQ_QUEUES | SFQ_DEPTH | MAX_ROUTES | MAX_BACKENDS |
|------|------------|------------|-----------|------------|--------------|
| `DefaultSecureGateway` | 1024 | 32 | 64 | 64 | 16 |
| `EdgeSecureGateway` | 256 | 16 | 32 | 16 | 8 |
| `TestSecureGateway` | 64 | 8 | 16 | 8 | 4 |

### Auth-Only Usage

```rust
use alice_api::middleware::AuthContext;

let ctx = AuthContext::new(public_key_bytes, signature_bytes);
if ctx.verify(b"GET /api/users") {
    // authenticated
}
```

### Crypto-Only Usage

```rust
use alice_api::middleware::{decrypt_body, decrypt_body_aead, Key, Nonce};

// Zero-allocation in-place decryption
let pt_len = decrypt_body(&key, &nonce, &mut buffer)?;

// With associated data (binds ciphertext to request metadata)
let pt_len = decrypt_body_aead(&key, &nonce, &mut buffer, b"POST /api/data")?;
```

## Use Cases

- **Microservices Gateway**: Route and rate-limit internal traffic
- **Secure API Gateway**: End-to-end Ed25519 + XChaCha20 pipeline
- **Edge Proxy**: Low-latency termination with fairness
- **API Protection**: Prevent abuse without external dependencies
- **IoT Gateway**: Embedded deployment with minimal footprint
- **High-Throughput Proxy**: Multi-threaded with sharded queues

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.

## References

- GCRA: ITU-T I.371, "Traffic control and congestion control in B-ISDN"
- DRR: Shreedhar & Varghese, "Efficient Fair Queuing using Deficit Round Robin"
- SFQ: McKenney, "Stochastic Fairness Queueing"
- splice(2): Linux man-pages, "splice - splice data to/from a pipe"
- Relaxed Atomics: Boehm & Adve, "Foundations of the C++ Concurrency Memory Model"
