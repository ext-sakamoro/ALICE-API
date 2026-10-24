# Changelog

All notable changes to ALICE-API will be documented in this file.

## [Unreleased]

### Changed
- 依存: alice-auth / alice-crypto / alice-queue / alice-analytics (feature `auth` / `crypto` / `queue` / `analytics`) を隣の checkout の path でなく git の rev で引く (Auth 2f71a23 0.6 / Crypto 4ab0f0e 0.6 / Queue 46b3d5e 0.2 / Analytics f3a58e3 0.7、各 main) `deny.toml` の `allow-git` にこの 4 つと、それらが git で引く ALICE-DetMath / ALICE-Sign を足した CI と preflight から sibling を clone する step と空の stub を作る step を外し、`.github/alice-siblings` と 2 つの composite action を削除した stub で解決していた job (no_std / feature-powerset / unused-deps / coverage / semver-checks / fuzz) も実物の crate で解決する `scripts/deny_graph_guard.py` は `--pins` / `--siblings-dir` の代わりに `--manifest` を取り、Cargo.toml が git の rev で引く `alice-*` が cargo deny の graph にあり、解決がその rev から取ったことを確かめる (試験に 2 件: 別の commit から解決した / rev の無い git 依存)
- Licence: `AGPL-3.0 OR LicenseRef-Commercial` → `LicenseRef-Proprietary`
- CI: ci.yml / fuzz.yml を `ci/**` の branch でも走らせ、ci.yml に手動実行を足し、main の run は打ち切らない concurrency にした (main に入れる前に branch で全 workflow を通すため)
- CI: cargo deny の検査の前に、cargo deny が解いた crate の graph (json) がこの crate と固定した sibling を全て含み、解決した package 数を超えないことを `scripts/deny_graph_guard.py` で確かめる (試験 `scripts/test_deny_graph_guard.py`: 空の graph・この crate や sibling の欠け・解決より多い・空の解決は失敗) 以前は license ごとの行数を数えていた
- CI: advisory の検査 (cargo audit / cargo deny --all-features) を空の stub でなく `.github/alice-siblings` の commit に固定した実物の sibling (Analytics / Auth / Crypto / Queue、Auth は今の API で build できないため 2026-09 時点の commit に固定) で毎回新しく解決して行う sibling 経由で入る依存 (alice-crypto → blake3 → digest → ctutils 等) の advisory も見える 解決した package 数と sibling の包含、cargo audit の走査数が 0 なら失敗 週次は火曜 03:17 UTC (repo ごとに時刻をずらす)、変更の判定は changes job が main との merge base から取る (ci/ の初回も見る) build / test の sibling も固定の commit になり、不要になった非公開 sibling の clone と token を外した
- License: `AGPL-3.0` → `AGPL-3.0 OR LicenseRef-Commercial` (2026-09-27)

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
