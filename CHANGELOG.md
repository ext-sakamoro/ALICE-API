# Changelog

All notable changes to ALICE-API will be documented in this file.

## [0.1.0] - 2026-02-23

### Added
- `GcraCell` / `GcraRegistry` — GCRA (Generic Cell Rate Algorithm) distributed rate limiting with CRDT merge
- `StochasticFairQueue` / `WeightedSfq` / `ShardedSfq` — stochastic fair queuing with deficit round-robin
- `ZeroCopyForwarder` / `BatchedForwarder` — zero-copy body forwarding via `splice` / `sendfile`
- `EdgeGateway` / `TestGateway` — integrated API gateway with routing, rate limiting and fair queuing
- `Backend` / `Route` — backend and route configuration
- `HttpMethod` / `RequestLine` — HTTP request line parsing
- `middleware` module — ALICE-Auth + ALICE-Crypto integration (feature `secure`)
- `queue_bridge` — ALICE-Queue message queueing bridge (feature `queue`)
- `analytics_bridge` — ALICE-Analytics API metrics bridge (feature `analytics`)
- `prelude` — convenient re-exports of all public types
- `no_std` compatible core
- 109 tests (102 unit + 7 doc-test)
