#!/usr/bin/env python3
"""Tests of scripts/deny_graph_guard.py: the guard must fail whenever cargo deny's crate graph
could not have compared anything real (empty, missing this crate or a pinned sibling, or
larger than the resolve it came from), and pass a graph that holds them all.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

GUARD = pathlib.Path(__file__).with_name("deny_graph_guard.py")


def entry(name, version="1.0.0", src="registry+https://github.com/rust-lang/crates.io-index"):
    return f"{name} {version} {src}", {"licenses": ["MIT"]}


def run(graph, lock_names, pins, own="alice-api"):
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "graph.json").write_text(json.dumps(dict(graph)), encoding="utf-8")
        lock = "".join(f'[[package]]\nname = "{n}"\nversion = "1.0.0"\n\n' for n in lock_names)
        (d / "Cargo.lock").write_text(lock, encoding="utf-8")
        pin_lines = ["# comment"] + [f"ALICE-{p.split('-', 1)[1].capitalize()} {'a' * 40}" for p in pins]
        (d / "alice-siblings").write_text("\n".join(pin_lines) + "\n", encoding="utf-8")
        for p in pins:
            repo = d / f"ALICE-{p.split('-', 1)[1].capitalize()}"
            repo.mkdir()
            (repo / "Cargo.toml").write_text(f'[package]\nname = "{p}"\n', encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(GUARD), "--graph", str(d / "graph.json"), "--lock", str(d / "Cargo.lock"),
             "--pins", str(d / "alice-siblings"), "--siblings-dir", str(d), "--crate", own],
            capture_output=True, text=True,
        )
        return r.returncode, r.stdout + r.stderr


def main():
    failures = []
    pins = ["alice-auth", "alice-crypto"]
    good = [entry("alice-api", "0.1.0", "path+file:///x"), entry("alice-auth", "0.5.1", "path+file:///y"),
            entry("alice-crypto", "0.5.0", "path+file:///z"), entry("blake3")]
    lock = ["alice-api", "alice-auth", "alice-crypto", "blake3", "only-on-windows"]

    cases = [
        ("a full graph passes", good, lock, pins, 0),
        ("an empty graph fails (compared nothing)", [], lock, pins, 1),
        ("a graph without this crate fails", good[1:], lock, pins, 1),
        ("a graph without a pinned sibling fails", [g for g in good if not g[0].startswith("alice-crypto")], lock, pins, 1),
        ("a graph larger than the resolve fails", good + [entry("ghost")], ["alice-api", "alice-auth", "alice-crypto"], pins, 1),
        ("an empty resolve fails", good, [], pins, 1),
        ("no pins at all is still checked (this crate and a nonzero graph)", good, lock, [], 0),
    ]
    for name, graph, lock_names, p, want in cases:
        rc, out = run(graph, lock_names, p)
        if rc != want:
            failures.append(f"{name}: rc {rc}, want {want}\n{out}")
    if failures:
        print("test_deny_graph_guard FAIL:", *failures, sep="\n  ")
        return 1
    print(f"test_deny_graph_guard: {len(cases)}/{len(cases)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
