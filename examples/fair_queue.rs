//! Stochastic Fair Queuing Example
//!
//! Demonstrates fair bandwidth sharing across multiple flows.
//!
//! ```bash
//! cargo run --example fair_queue
//! ```

use alice_api::prelude::*;

fn main() {
    println!("=== Stochastic Fair Queuing Demo ===\n");

    // 16 queues, depth 64, quantum 1500 bytes (MTU)
    let mut sfq = StochasticFairQueue::<16, 64>::new(1500);

    // Simulate 3 clients with different request sizes
    let flows = [
        (0xAAAA_u64, "Heavy Client", 4096_usize),
        (0xBBBB_u64, "Medium Client", 1024),
        (0xCCCC_u64, "Light Client", 256),
    ];

    println!("Enqueuing requests:");
    for &(hash, name, size) in &flows {
        for i in 0..5 {
            sfq.enqueue(QueuedRequest {
                flow_hash: hash,
                size: size as u32,
                request_id: (hash + i) as u32,
                timestamp_ns: 0,
            });
            println!("  {} -> req {} ({} bytes)", name, i, size);
        }
    }

    println!("\nDequeuing (DRR fair order):");
    let mut dequeued = 0;
    while let Some(req) = sfq.dequeue() {
        let name = match req.flow_hash {
            0xAAAA => "Heavy",
            0xBBBB => "Medium",
            0xCCCC => "Light",
            _ => "Unknown",
        };
        println!(
            "  [{}] flow=0x{:X} size={} bytes",
            dequeued, req.flow_hash, req.size
        );
        let _ = name;
        dequeued += 1;
    }

    println!("\nTotal dequeued: {}", dequeued);

    // --- Sharded SFQ for multi-threading ---
    println!("\n=== Sharded SFQ (4 cores) ===\n");

    let mut sharded = ShardedSfq::<4, 8, 16>::new(1024);

    for i in 0..20u64 {
        sharded.enqueue(QueuedRequest {
            flow_hash: i * 7919,
            size: 512,
            request_id: i as u32,
            timestamp_ns: 0,
        });
    }

    // Per-shard dequeue (zero contention)
    for shard in 0..4 {
        let mut count = 0;
        while let Some(_) = sharded.dequeue_from_shard(shard) {
            count += 1;
        }
        println!("  Shard {}: {} requests", shard, count);
    }
}
