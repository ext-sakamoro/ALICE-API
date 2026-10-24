#!/usr/bin/env python3
"""Tests of scripts/deny_graph_guard.py: the guard must fail whenever cargo deny's crate graph
could not have compared anything real (empty, missing this crate or an ALICE crate the manifest takes by
git rev, larger than the resolve it came from, the resolve taking that crate from another commit, or no
ALICE crate taken by git rev at all), and pass a graph that holds them all.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

GUARD = pathlib.Path(__file__).with_name("deny_graph_guard.py")


def entry(name, version="1.0.0", src="registry+https://github.com/rust-lang/crates.io-index"):
    return f"{name} {version} {src}", {"licenses": ["MIT"]}


REV = "a" * 40


def git_url(name):
    return f"https://github.com/ext-sakamoro/ALICE-{name.split('-', 1)[1].capitalize()}"


def run(graph, lock_names, pins, own="alice-api", lock_rev=REV, manifest_rev=REV):
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "graph.json").write_text(json.dumps(dict(graph)), encoding="utf-8")
        lock = ""
        for n in lock_names:
            lock += f'[[package]]\nname = "{n}"\nversion = "1.0.0"\n'
            if n in pins:
                lock += f'source = "git+{git_url(n)}?rev={lock_rev}#{lock_rev}"\n'
            lock += "\n"
        (d / "Cargo.lock").write_text(lock, encoding="utf-8")
        deps = ['log = "0.4"', 'alice-local = { path = "../ALICE-Local" }']
        rev = f', rev = "{manifest_rev}"' if manifest_rev else ""
        deps += [f'{p} = {{ git = "{git_url(p)}"{rev}, version = "1", optional = true }}' for p in pins]
        (d / "Cargo.toml").write_text(f'[package]\nname = "{own}"\n\n[dependencies]\n' + "\n".join(deps) + "\n",
                                      encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(GUARD), "--graph", str(d / "graph.json"), "--lock", str(d / "Cargo.lock"),
             "--manifest", str(d / "Cargo.toml"), "--crate", own],
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
        ("the resolve taking a pinned crate from another commit fails", good, lock, pins, 1, {"lock_rev": "b" * 40}),
        ("a git dependency without a rev fails", good, lock, pins, 1, {"manifest_rev": None}),
        ("an empty graph fails (compared nothing)", [], lock, pins, 1),
        ("a graph without this crate fails", good[1:], lock, pins, 1),
        ("a graph without a pinned sibling fails", [g for g in good if not g[0].startswith("alice-crypto")], lock, pins, 1),
        ("a graph larger than the resolve fails", good + [entry("ghost")], ["alice-api", "alice-auth", "alice-crypto"], pins, 1),
        ("an empty resolve fails", good, [], pins, 1),
        ("no git-pinned alice crate fails (none compared)", good, lock, [], 1),
    ]
    for name, graph, lock_names, p, want, *kw in cases:
        rc, out = run(graph, lock_names, p, **(kw[0] if kw else {}))
        if rc != want:
            failures.append(f"{name}: rc {rc}, want {want}\n{out}")
    if failures:
        print("test_deny_graph_guard FAIL:", *failures, sep="\n  ")
        return 1
    print(f"test_deny_graph_guard: {len(cases)}/{len(cases)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
