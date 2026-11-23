#!/usr/bin/env python3
"""check_retained.py [repo]: the retained-dependency half of
tests/fixtures/runtime-composition-consumer/src/dependency.rs, without running the test.

Every non-dev `zeroclaw-*` dependency of zeroclaw-runtime must have an entry with an owner
file that exists and a reason of at least 50 characters, and the list must name nothing else.
Uses `cargo metadata --no-deps`, which builds nothing.
"""
import json, os, subprocess, sys
repo = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
meta = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--format-version=1", "--no-deps", "--offline", "--locked"], cwd=repo))
def _reject(token):   # serde_json refuses NaN and Infinity; so does this
    raise ValueError("not valid JSON: %s" % token)


policy = json.load(open(os.path.join(repo, "tests/fixtures/runtime-composition-consumer/retained-dependencies.json")),
                   parse_constant=_reject)
runtime = next(p for p in meta["packages"] if p["name"] == "zeroclaw-runtime")
observed, errors = {"normal": set(), "build": set()}, []
for dep in runtime["dependencies"]:
    name, kind = dep["name"], dep.get("kind") or "normal"
    if not name.startswith("zeroclaw-") or kind == "dev":
        continue
    table = policy.get(kind)
    entry = table.get(name) if isinstance(table, dict) else None
    if not isinstance(entry, dict):
        errors.append("unapproved runtime %s dependency %s" % (kind, name)); continue
    owner, reason = entry.get("owner"), entry.get("reason")
    if not isinstance(owner, str) or not os.path.isfile(os.path.join(repo, owner)):
        errors.append("retained owner is not a file: %s" % owner)
    # The Rust test calls as_str().unwrap() and compares the UTF-8 byte length.
    if not isinstance(reason, str) or len(reason.encode("utf-8")) < 50:
        errors.append("retained edge %s has no concrete explanation" % name)
    observed[kind].add(name)
for kind in ("normal", "build"):
    table = policy.get(kind)
    if not isinstance(table, dict):     # the Rust test unwraps as_object() for both kinds
        errors.append("policy has no %s object" % kind); continue
    if observed[kind] != set(table):
        errors.append("retained %s policy drift: %s" % (kind, sorted(observed[kind] ^ set(table))))
print("retained-dependency list: %s" % ("ok (%d entries)" % len(observed["normal"]) if not errors else "FAILED: " + "; ".join(errors)))
sys.exit(1 if errors else 0)
