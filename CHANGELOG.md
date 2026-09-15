# Changelog

All notable changes to ALICE-API will be documented in this file.

## [Unreleased]

### Fixed
- **`no_std` の `gcra::now_ns()` が常に `0` を返す stub だった** — 内部の呼び出しは無く (全 API が `now_ns` を引数で受ける)、silent に rate limit を無効化する公開 stub だったので削除 (`no_std` は caller が monotonic clock を渡す、doc 明記)
- clippy pedantic 9 件を 0 化し CI を `-W pedantic -D warnings` gate に (`# Errors` doc 2 / 同一 arm 統合 2 / `--fix` 5)
- **`analytics` / `queue` bridge が現 sibling で compile 不能だった** — `alice_analytics::prelude` (存在しない) → `sketch::` / `anomaly::` path、`AliceQueue::dequeue` の `Result<Option<..>>` 追従 CI が stub でしか回っておらず未検出
- **`ffi` の test が compile 不能だった** (`ptr` 未 import 16 error)
- `QueueGateway::enqueue_request` の `Result<u64, ()>` を `QueueBridgeError::QueueFull` に (clippy `result_unit_err`)
- **`no_std` build が bare-metal で偽だった** — `routing` (libc / splice / sendfile) を `std` 専用に gate、HTTP parsing (`HttpMethod` / `parse_request_line` / `find_content_length` / `find_header_end`) を新 module `http` に分離 (`routing::` からは re-export で互換維持)、`libc` を `std` 限定 optional に `gcra` の `AtomicU64` のため 64-bit target (`aarch64-unknown-none`) が前提 (README)

### Added
- `ci.yml`: fmt + actionlint のみ → test / clippy (default / `std,ffi` / 全 bridge = real sibling 4 crate を `alice-siblings` action で clone) / `no_std` job (host + `aarch64-unknown-none` + clippy) / `feature-powerset` (std 固定 depth 2) / doc `-D warnings`、rust-cache、`rust-toolchain.toml` に aarch64-unknown-none target

## [0.1.1] - 2026-03-04

### Added
- `ffi` — 20 `extern "C"` FFI functions (GcraCell, Gateway, SFQ)
- Unity C# bindings (`bindings/unity/AliceApi.cs`) — 20 DllImport + RAII classes
- UE5 C++ header (`bindings/ue5/AliceApi.h`) — 20 extern C + RAII wrappers

### Fixed
- `cargo fmt` trailing whitespace in source files

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
