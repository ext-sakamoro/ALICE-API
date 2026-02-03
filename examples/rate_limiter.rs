//! GCRA Rate Limiter Example
//!
//! Demonstrates distributed rate limiting with CRDT merge.
//!
//! ```bash
//! cargo run --example rate_limiter
//! ```

use alice_api::prelude::*;

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn main() {
    println!("=== GCRA Rate Limiter Demo ===\n");

    // 10 requests/sec, burst of 3
    let cell = GcraCell::new(10.0, 3);

    println!("Config: 10 req/s, burst=3\n");

    // Send 5 rapid requests
    for i in 1..=5 {
        let decision = cell.check(now_ns());
        match decision {
            GcraDecision::Allow { .. } => {
                println!("Request {}: ALLOWED", i);
            }
            GcraDecision::Deny { retry_after_ns } => {
                println!(
                    "Request {}: DENIED (retry after {:.1}ms)",
                    i,
                    retry_after_ns as f64 / 1_000_000.0
                );
            }
        }
    }

    // --- Distributed merge ---
    println!("\n=== Distributed CRDT Merge ===\n");

    let node_a = GcraCell::new(100.0, 10);
    let node_b = GcraCell::new(100.0, 10);

    // Simulate traffic on both nodes
    let t = now_ns();
    for _ in 0..5 {
        node_a.check(t);
    }
    for _ in 0..3 {
        node_b.check(t);
    }

    println!("Node A TAT: {}", node_a.tat());
    println!("Node B TAT: {}", node_b.tat());

    // Merge: max(TAT_a, TAT_b)
    node_a.merge(node_b.tat());
    node_b.merge(node_a.tat());

    println!("After merge:");
    println!("  Node A TAT: {}", node_a.tat());
    println!("  Node B TAT: {}", node_b.tat());
    println!("  Converged: {}", node_a.tat() == node_b.tat());

    // --- Multi-key registry ---
    println!("\n=== Multi-Key Registry ===\n");

    let mut registry = GcraRegistry::<4096>::new(100.0, 10);

    let clients = [0x1234u64, 0x5678, 0x9ABC];
    let t = now_ns();

    for &client in &clients {
        let decision = registry.check(client, t);
        match decision {
            GcraDecision::Allow { .. } => println!("Client 0x{:X}: ALLOWED", client),
            GcraDecision::Deny { .. } => println!("Client 0x{:X}: DENIED", client),
        }
    }
}
