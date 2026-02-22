# Contributing to ALICE-API

## Build

```bash
cargo build
cargo build --no-default-features   # no_std check
```

## Test

```bash
cargo test
```

## Lint

```bash
cargo clippy -- -W clippy::all
cargo fmt -- --check
cargo doc --no-deps 2>&1 | grep warning
```

## Design Constraints

- **no_std core**: gateway, GCRA, SFQ must compile without `std`. Use fixed-size arrays.
- **O(1) rate limiting**: GCRA cell operations are constant-time with CRDT merge via `max(TAT)`.
- **Fixed memory**: all queue depths and route tables are compile-time const generics.
- **Zero-copy forwarding**: request bodies bypass userspace via `splice` / `sendfile` syscalls.
- **No external state**: no Redis, no distributed locks — all state is local + CRDT-mergeable.
