# Changelog

All notable changes to ALICE-API will be documented in this file.

## [Unreleased]

## [0.2.0] - 2026-11-06

### Security
- **`http::find_content_length` が桁あふれする値で誤った長さを返していた** — `value * 10 + digit` は overflow check の無い release で wrap し、`Content-Length: 18446744073709551617` を 1 と読んだ (check のある build では panic) body の長さを誤ると 1 つの接続の中で message の区切りが相手とずれる この crate の中に呼び出し元は無い 値の検査に加え、次も RFC 9110 / 9112 どおりに直した: 行頭の field 名だけを見る (他の値や body の中を読まない) / 大文字小文字を問わない / 値は `1*DIGIT` のみ (`12abc` `-5` `+5` 空を読まない) / 重複は値が同じでも拒否 / CRLF 以外の改行・折り返し・colon の前の空白・field 行の形でない行・先頭の空行を拒否 (`\r\n` だけの入力は field 0 本) 入力は field section だけで、request line を推測しない (request line の行は field 行でないので拒否) `parse_request_line` が返す offset は request line の行末で、doc の名前を直した

### Changed
- CI: `security-audit.yml` の semver-checks が 1 度も比較できていなかった (空の sibling で rustdoc の build が失敗し、`|| true` と job の `continue-on-error` で success) 本物の sibling で、repo の隣に置いた baseline と比べ、比較した check が 0 件なら fail にし、`continue-on-error` と `|| true` を外した
- **Breaking**: `find_content_length` の戻り値を `Result<Option<usize>, ContentLengthError>` に変えた `Ok(None)` は field が無い場合だけで、不正・桁あふれ・重複・ヘッダ未完は `Err` (`None` のままだと呼び出し側が「body なし」と読むため) `Transfer-Encoding` はこの関数の外で扱う cargo-semver-checks はこの変更を検出しないので版は手で上げた
- CI: `fuzz.yml` の `Run fuzz target` の `continue-on-error` を外し、crash で job を red にする artifact は残す
- CI: `ci.yml` に `cargo test --release --test content_length` を足した
- 追加: `http::split_message_head` は message head を RFC 9112 の文法で request line と field section に分ける
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

`Cargo.toml` の version は 0.1.0 のままで、0.1.1 になった commit も tag も無い この節は e37cc00 の FFI と binding の記録

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
