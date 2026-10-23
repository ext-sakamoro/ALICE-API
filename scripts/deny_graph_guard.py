#!/usr/bin/env python3
"""Check that cargo deny's crate graph actually holds what the advisory check is meant to cover.

`cargo deny check` passes on an empty or partial graph, so before trusting it this compares the
crate list cargo deny resolved (`cargo deny --all-features list --format json --layout crate`)
with the fresh resolve (Cargo.lock) and the pinned siblings:

  - the graph names at least one crate, and this crate itself;
  - at least one sibling is pinned in `.github/alice-siblings`, and every one (its package name read from
    <siblings-dir>/<Repo>/Cargo.toml) is in the graph, so a dependency that enters through a
    sibling is covered;
  - the graph has no more crates than the resolve has packages (it came from that resolve; the
    graph is smaller, since it keeps only the features and targets that are built), and the
    resolve is not empty.

Prints the counts; exit 1 on any failed check.

usage: deny_graph_guard.py --graph <json> --lock <Cargo.lock> --pins <alice-siblings>
                           --siblings-dir <dir> --crate <name>
"""
import argparse
import json
import pathlib
import re
import sys


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True)
    ap.add_argument("--lock", required=True)
    ap.add_argument("--pins", required=True)
    ap.add_argument("--siblings-dir", required=True)
    ap.add_argument("--crate", required=True)
    a = ap.parse_args(argv)

    graph = json.loads(pathlib.Path(a.graph).read_text(encoding="utf-8"))
    names = {key.split(" ", 1)[0] for key in graph}
    lock = pathlib.Path(a.lock).read_text(encoding="utf-8")
    resolved = len(re.findall(r'^name = "', lock, flags=re.M))

    errors = []
    # an empty graph fails here too (it cannot hold this crate)
    if a.crate not in names:
        errors.append(f"{a.crate} is not in cargo deny's graph (an empty graph compared nothing)")
    # an empty resolve fails here too (any graph that holds this crate is larger)
    if len(graph) > resolved:
        errors.append(f"cargo deny's graph has {len(graph)} crates, more than the {resolved} resolved packages")

    pinned = 0
    for line in pathlib.Path(a.pins).read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts or parts[0].startswith("#"):
            continue
        manifest = pathlib.Path(a.siblings_dir) / parts[0] / "Cargo.toml"
        m = re.search(r'^name\s*=\s*"([^"]+)"', manifest.read_text(encoding="utf-8"), flags=re.M)
        if not m:
            errors.append(f"{manifest}: no package name")
            continue
        pinned += 1
        if m.group(1) not in names:
            errors.append(f"pinned sibling {m.group(1)} ({parts[0]}) is not in cargo deny's graph")

    # no pin at all means no sibling was compared; the guard does not rely on another step for that
    if pinned == 0:
        errors.append(f"{a.pins} pins no sibling (compared none)")

    print(f"deny_graph_guard: graph {len(graph)} crates, resolve {resolved} packages, {pinned} pinned siblings present")
    for e in errors:
        print(f"::error::{e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
