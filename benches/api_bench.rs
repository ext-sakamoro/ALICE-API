use alice_api::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn bench_gcra_check(c: &mut Criterion) {
    let cell = GcraCell::new(1_000_000.0, 1000);

    c.bench_function("gcra_check_allow", |b| {
        b.iter(|| {
            let t = black_box(now_ns());
            cell.check(t)
        })
    });
}

fn bench_gcra_registry(c: &mut Criterion) {
    let mut registry = GcraRegistry::<4096>::new(100_000.0, 100);
    let t = now_ns();

    c.bench_function("gcra_registry_check", |b| {
        let mut key = 0u64;
        b.iter(|| {
            key = key.wrapping_add(1);
            registry.check(black_box(key % 1000), t)
        })
    });
}

fn bench_sfq_enqueue_dequeue(c: &mut Criterion) {
    let mut group = c.benchmark_group("sfq");

    for queues in [8, 16, 32] {
        group.bench_with_input(
            BenchmarkId::new("enqueue_dequeue", queues),
            &queues,
            |b, _| {
                let mut sfq = StochasticFairQueue::<32, 64>::new(1500);
                let mut i = 0u64;
                b.iter(|| {
                    i = i.wrapping_add(1);
                    sfq.enqueue(QueuedRequest {
                        flow_hash: i,
                        size: 512,
                        request_id: i as u32,
                        timestamp_ns: 0,
                    });
                    sfq.dequeue()
                })
            },
        );
    }
    group.finish();
}

fn bench_sharded_sfq(c: &mut Criterion) {
    let mut sfq = ShardedSfq::<4, 8, 16>::new(1024);

    c.bench_function("sharded_sfq_enqueue", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i = i.wrapping_add(1);
            sfq.enqueue(QueuedRequest {
                flow_hash: black_box(i),
                size: 512,
                request_id: i as u32,
                timestamp_ns: 0,
            });
        })
    });
}

fn bench_gcra_merge(c: &mut Criterion) {
    let cell = GcraCell::new(100.0, 10);
    let t = now_ns();
    cell.check(t);

    c.bench_function("gcra_merge", |b| {
        b.iter(|| {
            cell.merge(black_box(t + 1_000_000));
        })
    });
}

criterion_group!(
    benches,
    bench_gcra_check,
    bench_gcra_registry,
    bench_sfq_enqueue_dequeue,
    bench_sharded_sfq,
    bench_gcra_merge,
);
criterion_main!(benches);
