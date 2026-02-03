//! Distributed GCRA (Generic Cell Rate Algorithm)
//!
//! A mathematically precise rate limiter based on the Virtual Scheduling algorithm.
//! Unlike token buckets, GCRA uses a single timestamp (TAT - Theoretical Arrival Time)
//! making it trivially mergeable across distributed nodes.
//!
//! ## Algorithm
//!
//! ```text
//! TAT = max(TAT, now) + emission_interval
//! Allow if: TAT - now <= burst_tolerance
//! ```
//!
//! ## CRDT Properties
//!
//! - State: single timestamp (TAT)
//! - Merge: max(TAT_a, TAT_b)
//! - Monotonic: TAT only increases
//! - Convergent: all replicas converge to same max
//!
//! ## Performance Optimizations
//!
//! - **Relaxed Atomics**: Since TAT is monotonically increasing, we use `Ordering::Relaxed`
//!   for most operations. This eliminates memory barrier overhead while maintaining correctness.
//! - **Fetch-Max Pattern**: Uses optimized CAS loop with early exit for merge operations.
//! - **Speculative Check**: Avoids CAS when request would be denied.

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Atomic Fetch-Max Helper (Lock-Free)
// ============================================================================

/// Atomically update value to max(current, new_value) using Relaxed ordering.
/// Returns the previous value.
///
/// This is safe for monotonically increasing values like TAT.
#[inline]
fn fetch_max_relaxed(atom: &AtomicU64, new_value: u64) -> u64 {
    let mut current = atom.load(Ordering::Relaxed);
    loop {
        if new_value <= current {
            // Already at or above target, no update needed
            return current;
        }
        match atom.compare_exchange_weak(
            current,
            new_value,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return current,
            Err(actual) => current = actual,
        }
    }
}

/// Nanoseconds per second
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// A single GCRA cell for rate limiting one key
///
/// The cell tracks the Theoretical Arrival Time (TAT) which represents
/// when the next request would be allowed if requests arrived at exactly
/// the rate limit.
#[derive(Debug)]
pub struct GcraCell {
    /// Theoretical Arrival Time in nanoseconds since epoch
    /// This is the only mutable state - makes CRDT merge trivial
    tat: AtomicU64,
    /// Time between tokens: τ = 1/rate (nanoseconds)
    emission_interval: u64,
    /// Burst tolerance: σ = burst_size * emission_interval
    burst_tolerance: u64,
}

/// Result of a rate limit check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcraDecision {
    /// Request allowed, includes time until bucket is full again
    Allow {
        /// Nanoseconds until rate limit resets (bucket refills)
        reset_after_ns: u64,
    },
    /// Request denied, includes retry-after duration
    Deny {
        /// Nanoseconds until a request would be allowed
        retry_after_ns: u64,
    },
}

impl GcraCell {
    /// Create a new GCRA cell
    ///
    /// # Arguments
    /// * `rate` - Requests per second allowed
    /// * `burst` - Maximum burst size (requests that can be made instantly)
    ///
    /// # Example
    /// ```
    /// use alice_api::gcra::GcraCell;
    ///
    /// // 100 requests/sec with burst of 10
    /// let cell = GcraCell::new(100.0, 10);
    /// ```
    pub fn new(rate: f64, burst: u32) -> Self {
        let emission_interval = (NANOS_PER_SEC as f64 / rate) as u64;
        let burst_tolerance = emission_interval * burst as u64;

        Self {
            tat: AtomicU64::new(0),
            emission_interval,
            burst_tolerance,
        }
    }

    /// Create with explicit timing parameters
    ///
    /// # Arguments
    /// * `emission_interval_ns` - Nanoseconds between tokens
    /// * `burst_tolerance_ns` - Maximum burst tolerance in nanoseconds
    pub fn with_params(emission_interval_ns: u64, burst_tolerance_ns: u64) -> Self {
        Self {
            tat: AtomicU64::new(0),
            emission_interval: emission_interval_ns,
            burst_tolerance: burst_tolerance_ns,
        }
    }

    /// Check if a request should be allowed and update state atomically
    ///
    /// This is the core GCRA algorithm:
    /// 1. new_tat = max(tat, now) + emission_interval
    /// 2. allow_at = new_tat - burst_tolerance
    /// 3. if now >= allow_at: allow and update tat = new_tat
    ///    else: deny
    ///
    /// Uses Relaxed atomics for performance - safe because TAT is monotonically increasing.
    #[inline]
    pub fn check(&self, now_ns: u64) -> GcraDecision {
        loop {
            // Relaxed load is safe: TAT only increases, so stale reads
            // just mean we might allow a request that would be allowed anyway
            let tat = self.tat.load(Ordering::Relaxed);

            // Calculate new TAT: max(current_tat, now) + emission_interval
            let new_tat = tat.max(now_ns).saturating_add(self.emission_interval);

            // Calculate when this request would be allowed
            let allow_at = new_tat.saturating_sub(self.burst_tolerance);

            if now_ns >= allow_at {
                // Request is allowed - try to update TAT atomically
                // Use Relaxed ordering: TAT monotonically increases, so concurrent
                // updates are safe (worst case: we retry with higher value)
                match self.tat.compare_exchange_weak(
                    tat,
                    new_tat,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Success! Calculate reset time
                        let reset_after = new_tat.saturating_sub(now_ns);
                        return GcraDecision::Allow {
                            reset_after_ns: reset_after,
                        };
                    }
                    Err(_) => {
                        // Another thread updated TAT, retry with new value
                        continue;
                    }
                }
            } else {
                // Request denied - no state update needed
                let retry_after = allow_at.saturating_sub(now_ns);
                return GcraDecision::Deny {
                    retry_after_ns: retry_after,
                };
            }
        }
    }

    /// Check without updating state (peek)
    #[inline]
    pub fn would_allow(&self, now_ns: u64) -> bool {
        let tat = self.tat.load(Ordering::Relaxed);
        let new_tat = tat.max(now_ns).saturating_add(self.emission_interval);
        let allow_at = new_tat.saturating_sub(self.burst_tolerance);
        now_ns >= allow_at
    }

    /// Get current TAT (for debugging/monitoring)
    #[inline]
    pub fn tat(&self) -> u64 {
        self.tat.load(Ordering::Relaxed)
    }

    /// Merge with another cell's state (CRDT max operation)
    ///
    /// This is the key to distributed rate limiting:
    /// - Each node maintains local TAT
    /// - Periodically, nodes exchange and merge TATs
    /// - max() ensures convergence and consistency
    ///
    /// Uses the optimized fetch_max pattern with Relaxed ordering.
    #[inline]
    pub fn merge(&self, other_tat: u64) {
        fetch_max_relaxed(&self.tat, other_tat);
    }

    /// Reset the cell (allow burst again)
    #[inline]
    pub fn reset(&self) {
        self.tat.store(0, Ordering::Relaxed);
    }

    /// Get rate limit parameters
    #[inline]
    pub fn params(&self) -> (u64, u64) {
        (self.emission_interval, self.burst_tolerance)
    }
}

// ============================================================================
// GCRA Registry - Multi-key rate limiting with LRU eviction
// ============================================================================

/// Entry in the GCRA registry
#[derive(Debug)]
struct GcraEntry {
    /// The rate limiter cell
    cell: GcraCell,
    /// Last access time (for LRU)
    last_access: AtomicU64,
    /// Key hash (for verification)
    key_hash: u64,
}

/// Registry for managing multiple GCRA cells with LRU eviction
///
/// Uses open addressing with linear probing for cache-friendly access.
pub struct GcraRegistry<const CAPACITY: usize> {
    /// Slots for entries
    slots: [Option<GcraEntry>; CAPACITY],
    /// Default rate (requests/sec)
    default_rate: f64,
    /// Default burst size
    default_burst: u32,
    /// Number of entries
    count: usize,
}

impl<const CAPACITY: usize> GcraRegistry<CAPACITY> {
    /// Create a new registry with default rate limit parameters
    pub fn new(default_rate: f64, default_burst: u32) -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            default_rate,
            default_burst,
            count: 0,
        }
    }

    /// Check rate limit for a key
    pub fn check(&mut self, key_hash: u64, now_ns: u64) -> GcraDecision {
        let idx = self.find_or_create(key_hash, now_ns);
        if let Some(entry) = &self.slots[idx] {
            entry.last_access.store(now_ns, Ordering::Relaxed);
            entry.cell.check(now_ns)
        } else {
            // Should not happen, but allow if it does
            GcraDecision::Allow { reset_after_ns: 0 }
        }
    }

    /// Find existing entry or create new one
    fn find_or_create(&mut self, key_hash: u64, now_ns: u64) -> usize {
        let start_idx = (key_hash as usize) % CAPACITY;
        let mut idx = start_idx;

        // Linear probing to find existing or empty slot
        loop {
            match &self.slots[idx] {
                Some(entry) if entry.key_hash == key_hash => {
                    return idx;
                }
                None => {
                    // Empty slot - create new entry
                    self.slots[idx] = Some(GcraEntry {
                        cell: GcraCell::new(self.default_rate, self.default_burst),
                        last_access: AtomicU64::new(now_ns),
                        key_hash,
                    });
                    self.count += 1;
                    return idx;
                }
                Some(_) => {
                    // Different key, continue probing
                    idx = (idx + 1) % CAPACITY;
                    if idx == start_idx {
                        // Table full - evict LRU entry
                        let evict_idx = self.find_lru();
                        self.slots[evict_idx] = Some(GcraEntry {
                            cell: GcraCell::new(self.default_rate, self.default_burst),
                            last_access: AtomicU64::new(now_ns),
                            key_hash,
                        });
                        return evict_idx;
                    }
                }
            }
        }
    }

    /// Find least recently used entry
    fn find_lru(&self) -> usize {
        let mut min_time = u64::MAX;
        let mut min_idx = 0;

        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(entry) = slot {
                let access = entry.last_access.load(Ordering::Relaxed);
                if access < min_time {
                    min_time = access;
                    min_idx = i;
                }
            }
        }

        min_idx
    }

    /// Get current entry count
    pub fn count(&self) -> usize {
        self.count
    }

    /// Merge TAT from another node for a specific key
    pub fn merge(&mut self, key_hash: u64, other_tat: u64, now_ns: u64) {
        let idx = self.find_or_create(key_hash, now_ns);
        if let Some(entry) = &self.slots[idx] {
            entry.cell.merge(other_tat);
        }
    }

    /// Export all TATs for synchronization
    pub fn export_tats(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.slots.iter().filter_map(|slot| {
            slot.as_ref().map(|e| (e.key_hash, e.cell.tat()))
        })
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Get current time in nanoseconds (monotonic clock)
#[cfg(feature = "std")]
pub fn now_ns() -> u64 {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}

/// Get current time in nanoseconds (no_std - requires platform-specific impl)
#[cfg(not(feature = "std"))]
pub fn now_ns() -> u64 {
    // Platform-specific implementation needed
    0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcra_basic() {
        let cell = GcraCell::new(10.0, 5); // 10 req/s, burst of 5
        let _emission = NANOS_PER_SEC / 10; // 100ms

        // Should allow burst of 5
        for i in 0..5 {
            let result = cell.check(0);
            assert!(
                matches!(result, GcraDecision::Allow { .. }),
                "Request {} should be allowed",
                i
            );
        }

        // 6th request at time 0 should be denied
        let result = cell.check(0);
        assert!(matches!(result, GcraDecision::Deny { .. }));
    }

    #[test]
    fn test_gcra_steady_rate() {
        let cell = GcraCell::new(10.0, 1); // 10 req/s, burst of 1
        let interval = NANOS_PER_SEC / 10; // 100ms

        // Requests at exactly the rate limit should all pass
        for i in 0..10 {
            let now = i * interval;
            let result = cell.check(now);
            assert!(
                matches!(result, GcraDecision::Allow { .. }),
                "Request at {} should be allowed",
                now
            );
        }
    }

    #[test]
    fn test_gcra_merge() {
        let cell1 = GcraCell::new(10.0, 5);
        let cell2 = GcraCell::new(10.0, 5);

        // Consume some tokens on cell1
        for _ in 0..3 {
            cell1.check(0);
        }

        // Consume more tokens on cell2
        for _ in 0..5 {
            cell2.check(0);
        }

        // Get TATs
        let tat1 = cell1.tat();
        let tat2 = cell2.tat();

        // cell2 should have higher TAT (more consumed)
        assert!(tat2 > tat1);

        // Merge cell2's state into cell1
        cell1.merge(tat2);

        // cell1 should now have the higher TAT
        assert_eq!(cell1.tat(), tat2);
    }

    #[test]
    fn test_gcra_registry() {
        let mut registry = GcraRegistry::<64>::new(100.0, 10);

        let key1 = 12345u64;
        let key2 = 67890u64;

        // Both keys should initially allow
        assert!(matches!(
            registry.check(key1, 0),
            GcraDecision::Allow { .. }
        ));
        assert!(matches!(
            registry.check(key2, 0),
            GcraDecision::Allow { .. }
        ));

        // Count should be 2
        assert_eq!(registry.count(), 2);
    }

    #[test]
    fn test_gcra_retry_after() {
        let cell = GcraCell::new(1.0, 1); // 1 req/s, burst of 1

        // First request allowed
        let result = cell.check(0);
        assert!(matches!(result, GcraDecision::Allow { .. }));

        // Second request denied with retry_after
        let result = cell.check(0);
        match result {
            GcraDecision::Deny { retry_after_ns } => {
                // Should be close to 1 second
                assert!(retry_after_ns > NANOS_PER_SEC / 2);
                assert!(retry_after_ns <= NANOS_PER_SEC);
            }
            _ => panic!("Expected Deny"),
        }
    }
}
