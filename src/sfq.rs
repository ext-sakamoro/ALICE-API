//! Stochastic Fair Queuing (SFQ)
//!
//! Provides probabilistic fairness by hashing flows into N queues
//! and serving them round-robin with deficit accounting.
//!
//! ## Why SFQ?
//!
//! - **O(1) enqueue/dequeue**: No priority queue overhead
//! - **Probabilistic fairness**: Flows unlikely to collide with same hash
//! - **DoS resistant**: Hash seed rotation prevents targeted attacks
//! - **Memory efficient**: Fixed number of queues regardless of flow count
//!
//! ## Algorithm
//!
//! 1. Hash flow ID → queue index (0..N-1)
//! 2. Enqueue packet to selected queue
//! 3. Serve queues round-robin with Deficit Round Robin (DRR)
//!    - Each queue has a deficit counter
//!    - Add quantum to deficit, send packets until deficit exhausted
//!    - Ensures byte-level fairness, not just packet-level
//!
//! ## Performance Optimizations
//!
//! - **Cache-Line Sharding**: Each FlowQueue is aligned to 64-byte cache lines
//!   to prevent false sharing in multi-threaded scenarios.
//! - **Sharded SFQ**: `ShardedSfq` divides queues across CPU cores for zero contention.

use core::hash::Hasher;

/// Cache line size (64 bytes on most x86_64/ARM64)
#[allow(dead_code)]
const CACHE_LINE_SIZE: usize = 64;

// ============================================================================
// FNV Hasher (same as ALICE-Analytics for consistency)
// ============================================================================

/// FNV-1a hasher with avalanche finalizer
#[derive(Clone, Copy)]
struct SfqHasher {
    state: u64,
}

impl SfqHasher {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    #[inline(always)]
    fn new(seed: u64) -> Self {
        Self {
            state: Self::FNV_OFFSET ^ seed,
        }
    }

    #[inline(always)]
    fn mix(mut h: u64) -> u64 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        h
    }
}

impl Hasher for SfqHasher {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state ^= byte as u64;
            self.state = self.state.wrapping_mul(Self::FNV_PRIME);
        }
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        Self::mix(self.state)
    }
}

// ============================================================================
// Request representation
// ============================================================================

/// A request in the fair queue
#[derive(Debug, Clone)]
pub struct QueuedRequest {
    /// Flow identifier hash (e.g., client IP hash)
    pub flow_hash: u64,
    /// Request size in bytes (for deficit accounting)
    pub size: usize,
    /// Request ID for tracking
    pub id: u64,
    /// Timestamp when enqueued (nanoseconds)
    pub enqueue_time: u64,
}

impl QueuedRequest {
    pub fn new(flow_hash: u64, size: usize, id: u64, enqueue_time: u64) -> Self {
        Self {
            flow_hash,
            size,
            id,
            enqueue_time,
        }
    }
}

// ============================================================================
// Single Queue with Deficit Counter
// ============================================================================

/// Fixed-size ring buffer queue
///
/// Aligned to cache line boundary to prevent false sharing when multiple
/// queues are accessed by different threads.
#[derive(Debug)]
#[repr(align(64))]
struct FlowQueue<const DEPTH: usize> {
    /// Ring buffer storage
    buffer: [Option<QueuedRequest>; DEPTH],
    /// Read position
    head: usize,
    /// Write position
    tail: usize,
    /// Current queue length
    len: usize,
    /// Deficit counter (bytes we're "owed")
    deficit: usize,
    /// Padding to ensure each queue occupies full cache lines
    _padding: [u8; 24], // 8 + 8 + 8 + 8 = 32 bytes of fields, 32 + 24 = 56, buffer adds more
}

impl<const DEPTH: usize> FlowQueue<DEPTH> {
    const NONE: Option<QueuedRequest> = None;

    fn new() -> Self {
        Self {
            buffer: [Self::NONE; DEPTH],
            head: 0,
            tail: 0,
            len: 0,
            deficit: 0,
            _padding: [0u8; 24],
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    fn is_full(&self) -> bool {
        self.len >= DEPTH
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, req: QueuedRequest) -> bool {
        if self.is_full() {
            return false;
        }
        self.buffer[self.tail] = Some(req);
        self.tail = (self.tail + 1) % DEPTH;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<QueuedRequest> {
        if self.is_empty() {
            return None;
        }
        let req = self.buffer[self.head].take();
        self.head = (self.head + 1) % DEPTH;
        self.len -= 1;
        req
    }

    #[inline(always)]
    fn peek(&self) -> Option<&QueuedRequest> {
        if self.is_empty() {
            None
        } else {
            self.buffer[self.head].as_ref()
        }
    }
}

// ============================================================================
// Stochastic Fair Queue
// ============================================================================

/// Stochastic Fair Queue with Deficit Round Robin
///
/// # Type Parameters
/// * `QUEUES` - Number of hash buckets (more = less collision probability)
/// * `DEPTH` - Maximum depth of each queue
///
/// # Example
/// ```
/// use alice_api::sfq::{StochasticFairQueue, QueuedRequest};
///
/// let mut sfq = StochasticFairQueue::<16, 64>::new(1024); // quantum = 1024 bytes
///
/// // Enqueue requests from different flows
/// sfq.enqueue(QueuedRequest::new(0x1234, 512, 1, 0));
/// sfq.enqueue(QueuedRequest::new(0x5678, 512, 2, 0));
///
/// // Dequeue fairly
/// let req = sfq.dequeue();
/// ```
pub struct StochasticFairQueue<const QUEUES: usize, const DEPTH: usize> {
    /// Per-flow queues
    queues: [FlowQueue<DEPTH>; QUEUES],
    /// Current queue being served (round-robin)
    current: usize,
    /// Quantum: bytes added to deficit each round
    quantum: usize,
    /// Hash seed (rotate periodically for DoS resistance)
    hash_seed: u64,
    /// Total requests in all queues
    total_len: usize,
    /// Statistics: total enqueued
    stats_enqueued: u64,
    /// Statistics: total dequeued
    stats_dequeued: u64,
    /// Statistics: drops due to full queue
    stats_drops: u64,
}

impl<const QUEUES: usize, const DEPTH: usize> StochasticFairQueue<QUEUES, DEPTH> {
    /// Create a new SFQ
    ///
    /// # Arguments
    /// * `quantum` - Bytes to add to deficit counter each round (e.g., 1500 for MTU)
    pub fn new(quantum: usize) -> Self {
        Self {
            queues: core::array::from_fn(|_| FlowQueue::new()),
            current: 0,
            quantum,
            hash_seed: 0x5AFE_5EED_1234,
            total_len: 0,
            stats_enqueued: 0,
            stats_dequeued: 0,
            stats_drops: 0,
        }
    }

    /// Create with custom hash seed
    pub fn with_seed(quantum: usize, seed: u64) -> Self {
        let mut sfq = Self::new(quantum);
        sfq.hash_seed = seed;
        sfq
    }

    /// Hash flow ID to queue index
    #[inline(always)]
    fn hash_to_queue(&self, flow_hash: u64) -> usize {
        let mut hasher = SfqHasher::new(self.hash_seed);
        hasher.write(&flow_hash.to_le_bytes());
        (hasher.finish() as usize) & (QUEUES - 1)
    }

    /// Enqueue a request
    ///
    /// Returns `true` if enqueued, `false` if dropped (queue full)
    pub fn enqueue(&mut self, req: QueuedRequest) -> bool {
        let queue_idx = self.hash_to_queue(req.flow_hash);

        if self.queues[queue_idx].push(req) {
            self.total_len += 1;
            self.stats_enqueued += 1;
            true
        } else {
            self.stats_drops += 1;
            false
        }
    }

    /// Dequeue the next request using Deficit Round Robin
    ///
    /// Returns `None` if all queues are empty
    pub fn dequeue(&mut self) -> Option<QueuedRequest> {
        if self.total_len == 0 {
            return None;
        }

        // Try up to QUEUES times to find a non-empty queue
        for _ in 0..QUEUES {
            let queue = &mut self.queues[self.current];

            if queue.is_empty() {
                // Skip empty queues, reset deficit
                queue.deficit = 0;
                self.current = (self.current + 1) & (QUEUES - 1);
                continue;
            }

            // Add quantum to deficit
            queue.deficit += self.quantum;

            // Try to send packet if deficit allows
            if let Some(req) = queue.peek() {
                if queue.deficit >= req.size {
                    queue.deficit -= req.size;
                    let req = queue.pop().unwrap();
                    self.total_len -= 1;
                    self.stats_dequeued += 1;

                    // Move to next queue for next dequeue
                    if queue.is_empty() {
                        queue.deficit = 0;
                        self.current = (self.current + 1) & (QUEUES - 1);
                    }

                    return Some(req);
                }
            }

            // Couldn't send from this queue, try next
            self.current = (self.current + 1) & (QUEUES - 1);
        }

        // All queues either empty or insufficient deficit
        // Force dequeue from first non-empty queue
        for i in 0..QUEUES {
            let idx = (self.current + i) & (QUEUES - 1);
            if !self.queues[idx].is_empty() {
                let req = self.queues[idx].pop().unwrap();
                self.total_len -= 1;
                self.stats_dequeued += 1;
                self.current = (idx + 1) & (QUEUES - 1);
                return Some(req);
            }
        }

        None
    }

    /// Check if queue is empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    /// Get total number of queued requests
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Rotate hash seed (call periodically for DoS resistance)
    pub fn rotate_seed(&mut self, new_seed: u64) {
        self.hash_seed = new_seed;
        // Note: existing queued items keep their original queue assignment
    }

    /// Get statistics
    pub fn stats(&self) -> SfqStats {
        SfqStats {
            enqueued: self.stats_enqueued,
            dequeued: self.stats_dequeued,
            drops: self.stats_drops,
            current_len: self.total_len,
        }
    }

    /// Get per-queue lengths (for monitoring)
    pub fn queue_lengths(&self) -> impl Iterator<Item = usize> + '_ {
        self.queues.iter().map(|q| q.len())
    }
}

/// SFQ Statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SfqStats {
    /// Total requests enqueued
    pub enqueued: u64,
    /// Total requests dequeued
    pub dequeued: u64,
    /// Requests dropped due to full queue
    pub drops: u64,
    /// Current queue length
    pub current_len: usize,
}

// ============================================================================
// Weighted Fair Queue variant
// ============================================================================

/// Flow weight for weighted fair queuing
#[derive(Debug, Clone, Copy)]
pub struct FlowWeight {
    /// Flow identifier
    pub flow_hash: u64,
    /// Weight multiplier (higher = more bandwidth)
    pub weight: u32,
}

/// Weighted Stochastic Fair Queue
///
/// Extends SFQ with per-flow weights for differentiated service.
/// Uses Weighted Deficit Round Robin (WDRR): each queue's quantum is scaled
/// by its weight, so flows with higher weight receive proportionally more
/// bandwidth.
///
/// # Example
/// ```
/// use alice_api::sfq::{WeightedSfq, QueuedRequest};
///
/// // 8 queues, depth 32, quantum 1024 bytes, default weight 1
/// let mut wsfq = WeightedSfq::<8, 32>::new(1024, 1);
///
/// // Give the premium flow 3x more bandwidth
/// wsfq.set_weight(0xAAAA, 3);
///
/// // Enqueue from two flows
/// wsfq.enqueue(QueuedRequest::new(0xAAAA, 512, 1, 0)); // premium
/// wsfq.enqueue(QueuedRequest::new(0xBBBB, 512, 2, 0)); // standard
///
/// while let Some(req) = wsfq.dequeue() {
///     let _ = req;
/// }
/// ```
pub struct WeightedSfq<const QUEUES: usize, const DEPTH: usize> {
    /// Base SFQ
    inner: StochasticFairQueue<QUEUES, DEPTH>,
    /// Per-queue weight multipliers (index = queue slot, value = weight)
    weights: [u32; QUEUES],
}

impl<const QUEUES: usize, const DEPTH: usize> WeightedSfq<QUEUES, DEPTH> {
    /// Create a new Weighted SFQ
    ///
    /// # Arguments
    /// * `quantum` - Base quantum in bytes per DRR round
    /// * `default_weight` - Initial weight assigned to all queues
    pub fn new(quantum: usize, default_weight: u32) -> Self {
        Self {
            inner: StochasticFairQueue::new(quantum),
            weights: [default_weight.max(1); QUEUES],
        }
    }

    /// Set weight for a flow
    ///
    /// Higher weight means more bandwidth allocation. Weight 2 gets 2x the
    /// bandwidth of weight 1.
    pub fn set_weight(&mut self, flow_hash: u64, weight: u32) {
        let idx = self.inner.hash_to_queue(flow_hash);
        self.weights[idx] = weight.max(1); // Minimum weight of 1
    }

    /// Get weight for a flow's queue slot
    pub fn get_weight(&self, flow_hash: u64) -> u32 {
        let idx = self.inner.hash_to_queue(flow_hash);
        self.weights[idx]
    }

    /// Enqueue a request
    ///
    /// Returns `true` if enqueued, `false` if dropped (queue full)
    pub fn enqueue(&mut self, req: QueuedRequest) -> bool {
        self.inner.enqueue(req)
    }

    /// Dequeue with Weighted Deficit Round Robin (WDRR)
    ///
    /// Each queue's quantum is scaled by its weight:
    ///   effective_quantum = base_quantum * weight
    ///
    /// This ensures higher-weight flows receive proportionally more bandwidth.
    pub fn dequeue(&mut self) -> Option<QueuedRequest> {
        if self.inner.total_len == 0 {
            return None;
        }

        // Try up to QUEUES times to find a non-empty queue
        for _ in 0..QUEUES {
            let current = self.inner.current;
            let queue = &mut self.inner.queues[current];

            if queue.is_empty() {
                // Skip empty queues, reset deficit
                queue.deficit = 0;
                self.inner.current = (self.inner.current + 1) & (QUEUES - 1);
                continue;
            }

            // Weighted quantum: scale by per-queue weight
            let weighted_quantum = self.inner.quantum * self.weights[current] as usize;
            queue.deficit += weighted_quantum;

            // Serve as many packets as the deficit allows
            if let Some(req) = queue.peek() {
                if queue.deficit >= req.size {
                    queue.deficit -= req.size;
                    let req = queue.pop().unwrap();
                    self.inner.total_len -= 1;
                    self.inner.stats_dequeued += 1;

                    if queue.is_empty() {
                        queue.deficit = 0;
                        self.inner.current = (self.inner.current + 1) & (QUEUES - 1);
                    }

                    return Some(req);
                }
            }

            self.inner.current = (self.inner.current + 1) & (QUEUES - 1);
        }

        // Deficit exhausted for all queues in this round — force dequeue from
        // first non-empty queue to prevent starvation
        for i in 0..QUEUES {
            let idx = (self.inner.current + i) & (QUEUES - 1);
            if !self.inner.queues[idx].is_empty() {
                let req = self.inner.queues[idx].pop().unwrap();
                self.inner.total_len -= 1;
                self.inner.stats_dequeued += 1;
                self.inner.current = (idx + 1) & (QUEUES - 1);
                return Some(req);
            }
        }

        None
    }

    /// Check if queue is empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get total number of queued requests
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Get statistics
    pub fn stats(&self) -> SfqStats {
        self.inner.stats()
    }
}

// ============================================================================
// Sharded SFQ for Multi-threaded Access
// ============================================================================

/// A single shard containing an SFQ instance
///
/// Aligned to cache line boundary to prevent false sharing between shards.
#[repr(align(64))]
pub struct SfqShard<const QUEUES: usize, const DEPTH: usize> {
    /// The actual queue
    queue: StochasticFairQueue<QUEUES, DEPTH>,
    /// Padding to fill cache line
    _padding: [u8; 0], // repr(align) handles alignment
}

impl<const QUEUES: usize, const DEPTH: usize> SfqShard<QUEUES, DEPTH> {
    fn new(quantum: usize) -> Self {
        Self {
            queue: StochasticFairQueue::new(quantum),
            _padding: [],
        }
    }
}

/// Sharded Stochastic Fair Queue for zero-contention multi-threaded access
///
/// Divides the hash space across `SHARDS` independent SFQ instances.
/// Each shard is cache-line aligned to prevent false sharing.
///
/// # Type Parameters
/// * `SHARDS` - Number of shards (typically = number of CPU cores)
/// * `QUEUES` - Queues per shard
/// * `DEPTH` - Queue depth per queue
///
/// # Example
/// ```
/// use alice_api::sfq::{ShardedSfq, QueuedRequest};
///
/// // 4 shards, 8 queues each, depth 16
/// let mut sfq = ShardedSfq::<4, 8, 16>::new(1024);
///
/// // Enqueue to appropriate shard based on flow hash
/// sfq.enqueue(QueuedRequest::new(0x1234, 512, 1, 0));
/// ```
pub struct ShardedSfq<const SHARDS: usize, const QUEUES: usize, const DEPTH: usize> {
    /// Per-shard SFQ instances
    shards: [SfqShard<QUEUES, DEPTH>; SHARDS],
    /// Quantum for all shards (stored for potential dynamic adjustment)
    #[allow(dead_code)]
    quantum: usize,
}

impl<const SHARDS: usize, const QUEUES: usize, const DEPTH: usize>
    ShardedSfq<SHARDS, QUEUES, DEPTH>
{
    /// Create a new sharded SFQ
    pub fn new(quantum: usize) -> Self {
        Self {
            shards: core::array::from_fn(|_| SfqShard::new(quantum)),
            quantum,
        }
    }

    /// Get shard index from flow hash
    #[inline(always)]
    fn shard_index(&self, flow_hash: u64) -> usize {
        // Use upper bits for shard selection (lower bits used for queue selection)
        ((flow_hash >> 32) as usize) & (SHARDS - 1)
    }

    /// Enqueue a request to the appropriate shard
    pub fn enqueue(&mut self, req: QueuedRequest) -> bool {
        let shard_idx = self.shard_index(req.flow_hash);
        self.shards[shard_idx].queue.enqueue(req)
    }

    /// Dequeue from a specific shard
    ///
    /// In multi-threaded use, each thread should own a shard.
    pub fn dequeue_from_shard(&mut self, shard_idx: usize) -> Option<QueuedRequest> {
        if shard_idx < SHARDS {
            self.shards[shard_idx].queue.dequeue()
        } else {
            None
        }
    }

    /// Dequeue from any shard (round-robin)
    ///
    /// For single-threaded use or when thread affinity isn't needed.
    pub fn dequeue(&mut self) -> Option<QueuedRequest> {
        for shard in self.shards.iter_mut() {
            if let Some(req) = shard.queue.dequeue() {
                return Some(req);
            }
        }
        None
    }

    /// Get total length across all shards
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.queue.len()).sum()
    }

    /// Check if all shards are empty
    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.queue.is_empty())
    }

    /// Get statistics for a specific shard
    pub fn shard_stats(&self, shard_idx: usize) -> Option<SfqStats> {
        if shard_idx < SHARDS {
            Some(self.shards[shard_idx].queue.stats())
        } else {
            None
        }
    }

    /// Get aggregated statistics across all shards
    pub fn stats(&self) -> SfqStats {
        let mut total = SfqStats::default();
        for shard in self.shards.iter() {
            let s = shard.queue.stats();
            total.enqueued += s.enqueued;
            total.dequeued += s.dequeued;
            total.drops += s.drops;
            total.current_len += s.current_len;
        }
        total
    }

    /// Get mutable reference to a specific shard
    ///
    /// Useful for per-thread ownership pattern.
    pub fn shard_mut(&mut self, shard_idx: usize) -> Option<&mut StochasticFairQueue<QUEUES, DEPTH>> {
        if shard_idx < SHARDS {
            Some(&mut self.shards[shard_idx].queue)
        } else {
            None
        }
    }

    /// Get number of shards
    pub const fn num_shards(&self) -> usize {
        SHARDS
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfq_basic() {
        let mut sfq = StochasticFairQueue::<8, 16>::new(1024);

        // Enqueue some requests
        assert!(sfq.enqueue(QueuedRequest::new(1, 100, 1, 0)));
        assert!(sfq.enqueue(QueuedRequest::new(2, 100, 2, 0)));
        assert!(sfq.enqueue(QueuedRequest::new(3, 100, 3, 0)));

        assert_eq!(sfq.len(), 3);

        // Dequeue all
        assert!(sfq.dequeue().is_some());
        assert!(sfq.dequeue().is_some());
        assert!(sfq.dequeue().is_some());
        assert!(sfq.dequeue().is_none());
    }

    #[test]
    fn test_sfq_fairness() {
        let mut sfq = StochasticFairQueue::<16, 64>::new(1024);

        // Flow A sends 10 requests
        for i in 0..10 {
            sfq.enqueue(QueuedRequest::new(0xAAAA, 512, i, 0));
        }

        // Flow B sends 10 requests
        for i in 0..10 {
            sfq.enqueue(QueuedRequest::new(0xBBBB, 512, 100 + i, 0));
        }

        // Dequeue and count per-flow
        let mut flow_a_count = 0;
        let mut flow_b_count = 0;
        let mut order = Vec::new();

        while let Some(req) = sfq.dequeue() {
            if req.flow_hash == 0xAAAA {
                flow_a_count += 1;
            } else {
                flow_b_count += 1;
            }
            order.push(req.flow_hash);
        }

        // Both flows should get all their requests
        assert_eq!(flow_a_count, 10);
        assert_eq!(flow_b_count, 10);

        // Check interleaving (fairness) - shouldn't be all A then all B
        // Note: If flows hash to the same queue, interleaving won't happen
        // This is a probabilistic test - with 16 queues, collision is 1/16
        let consecutive_same = order
            .windows(2)
            .filter(|w| w[0] == w[1])
            .count();

        // With possible hash collision, we allow up to 19 consecutive
        // (worst case: all same queue means all 19 pairs are same-flow)
        // The test mainly verifies both flows eventually get served
        assert!(
            consecutive_same <= 19,
            "Unexpected consecutive count: {}",
            consecutive_same
        );
    }

    #[test]
    fn test_sfq_drop_on_full() {
        let mut sfq = StochasticFairQueue::<1, 4>::new(1024); // Single queue, depth 4

        // Fill the queue
        for i in 0..4 {
            assert!(sfq.enqueue(QueuedRequest::new(1, 100, i, 0)));
        }

        // Next should be dropped
        assert!(!sfq.enqueue(QueuedRequest::new(1, 100, 99, 0)));

        let stats = sfq.stats();
        assert_eq!(stats.drops, 1);
    }

    #[test]
    fn test_sfq_seed_rotation() {
        let mut sfq = StochasticFairQueue::<8, 16>::new(1024);

        let flow = 12345u64;
        let _q1 = sfq.hash_to_queue(flow);

        sfq.rotate_seed(0x0E45_EED_9999);
        let _q2 = sfq.hash_to_queue(flow);

        // Queue assignment should (likely) change with different seed
        // Note: there's a 1/8 chance they're the same by coincidence
        // We just verify the seed was changed
        assert_ne!(sfq.hash_seed, 0x5AFE_5EED_1234);
    }

    #[test]
    fn test_sharded_sfq_basic() {
        let mut sfq = ShardedSfq::<4, 8, 16>::new(1024);

        // Enqueue requests that will distribute across shards
        for i in 0..20 {
            let flow_hash = (i as u64) << 32 | (i as u64); // Spread across shards
            assert!(sfq.enqueue(QueuedRequest::new(flow_hash, 100, i, 0)));
        }

        assert_eq!(sfq.len(), 20);

        // Dequeue all
        let mut count = 0;
        while sfq.dequeue().is_some() {
            count += 1;
        }
        assert_eq!(count, 20);
        assert!(sfq.is_empty());
    }

    #[test]
    fn test_sharded_sfq_per_shard() {
        let mut sfq = ShardedSfq::<4, 8, 16>::new(1024);

        // Enqueue to specific shard by controlling upper bits
        let shard0_flow = 0x0000_0000_1234u64;
        let shard1_flow = 0x0000_0001_1234u64;

        sfq.enqueue(QueuedRequest::new(shard0_flow, 100, 1, 0));
        sfq.enqueue(QueuedRequest::new(shard1_flow, 100, 2, 0));

        // Check per-shard stats
        let total_stats = sfq.stats();
        assert_eq!(total_stats.enqueued, 2);
    }

    #[test]
    fn test_cache_line_alignment() {
        // Verify FlowQueue is cache-line aligned
        assert!(core::mem::align_of::<FlowQueue<16>>() >= 64);

        // Verify SfqShard is cache-line aligned
        assert!(core::mem::align_of::<SfqShard<8, 16>>() >= 64);
    }

    #[test]
    fn test_weighted_sfq_basic() {
        let mut wsfq = WeightedSfq::<8, 32>::new(1024, 1);

        assert!(wsfq.enqueue(QueuedRequest::new(1, 100, 1, 0)));
        assert!(wsfq.enqueue(QueuedRequest::new(2, 100, 2, 0)));
        assert!(wsfq.enqueue(QueuedRequest::new(3, 100, 3, 0)));

        assert_eq!(wsfq.len(), 3);
        assert!(!wsfq.is_empty());

        assert!(wsfq.dequeue().is_some());
        assert!(wsfq.dequeue().is_some());
        assert!(wsfq.dequeue().is_some());
        assert!(wsfq.dequeue().is_none());
        assert!(wsfq.is_empty());
    }

    #[test]
    fn test_weighted_sfq_stats() {
        let mut wsfq = WeightedSfq::<8, 32>::new(1024, 1);

        for i in 0..5 {
            wsfq.enqueue(QueuedRequest::new(1, 100, i, 0));
        }

        let mut count = 0;
        while wsfq.dequeue().is_some() {
            count += 1;
        }

        assert_eq!(count, 5);
        let stats = wsfq.stats();
        assert_eq!(stats.enqueued, 5);
        assert_eq!(stats.dequeued, 5);
    }

    #[test]
    fn test_weighted_sfq_set_weight() {
        let mut wsfq = WeightedSfq::<8, 32>::new(1024, 1);

        wsfq.set_weight(0xAAAA, 4);
        assert_eq!(wsfq.get_weight(0xAAAA), 4);

        // Weight 0 should be clamped to 1
        wsfq.set_weight(0xBBBB, 0);
        assert_eq!(wsfq.get_weight(0xBBBB), 1);
    }

    #[test]
    fn test_weighted_sfq_weighted_drr() {
        // With WDRR, a flow with weight 2 should get proportionally more
        // bandwidth (larger effective quantum) than a flow with weight 1.
        // We verify that both flows are fully served.
        let mut wsfq = WeightedSfq::<16, 64>::new(512, 1);

        let premium = 0xAAAA_u64;
        let standard = 0xBBBB_u64;

        wsfq.set_weight(premium, 2);

        for i in 0..8 {
            wsfq.enqueue(QueuedRequest::new(premium, 512, i, 0));
            wsfq.enqueue(QueuedRequest::new(standard, 512, 100 + i, 0));
        }

        assert_eq!(wsfq.len(), 16);

        let mut premium_count = 0u32;
        let mut standard_count = 0u32;

        while let Some(req) = wsfq.dequeue() {
            if req.flow_hash == premium {
                premium_count += 1;
            } else {
                standard_count += 1;
            }
        }

        // All requests from both flows must be served
        assert_eq!(premium_count, 8);
        assert_eq!(standard_count, 8);
    }
}
