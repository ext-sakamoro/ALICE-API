#!/usr/bin/env python3
"""Check that cargo deny's crate graph actually holds what the advisory check is meant to cover.

`cargo deny check` passes on an empty or partial graph, so before trusting it this compares the
crate list cargo deny resolved (`cargo deny --all-features list --format json --layout crate`)
with the fresh resolve (Cargo.lock) and the ALICE crates the manifest takes by git rev:

  - the graph names at least one crate, and this crate itself;
  - the manifest takes at least one `alice-*` crate by `git` + `rev`, every one is in the graph (so a
    dependency that enters through it is covered), and the resolve took it from that commit;
  - the graph has no more crates than the resolve has packages (it came from that resolve; the
    graph is smaller, since it keeps only the features and targets that are built), and the
    resolve is not empty.

Prints the counts; exit 1 on any failed check.

usage: deny_graph_guard.py --graph <json> --lock <Cargo.lock> --manifest <Cargo.toml> --crate <name>
"""
import argparse
import json
import pathlib
import re
import sys
import tomllib


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True)
    ap.add_argument("--lock", required=True)
    ap.add_argument("--manifest", required=True)
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

    deps = tomllib.loads(pathlib.Path(a.manifest).read_text(encoding="utf-8")).get("dependencies", {})
    pinned = 0
    for name, spec in deps.items():
        if not name.startswith("alice-") or not isinstance(spec, dict) or "git" not in spec:
            continue
        pinned += 1
        if "rev" not in spec:
            errors.append(f"{name} is taken by git without a rev")
            continue
        if name not in names:
            errors.append(f"{name} (git rev {spec['rev'][:12]}) is not in cargo deny's graph")
        source = f'source = "git+{spec["git"]}?rev={spec["rev"]}#{spec["rev"]}"'
        if not re.search(rf'^name = "{re.escape(name)}"\nversion = "[^"]+"\n{re.escape(source)}$', lock, flags=re.M):
            errors.append(f"{name}: the resolve did not take it from {spec['git']} at {spec['rev'][:12]}")

    # no git pin at all means no ALICE crate was compared; the guard does not rely on another step for that
    if pinned == 0:
        errors.append(f"{a.manifest} takes no alice-* crate by git rev (compared none)")

    print(f"deny_graph_guard: graph {len(graph)} crates, resolve {resolved} packages, {pinned} git-pinned alice crates present")
    for e in errors:
        print(f"::error::{e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
