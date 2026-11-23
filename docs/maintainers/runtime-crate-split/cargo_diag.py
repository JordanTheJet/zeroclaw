#!/usr/bin/env python3
"""cargo_diag.py <cargo json stdout> [<cargo stderr>]: one line saying whether a cargo run was clean.

    errors: none  warnings: none  finished: ok  cargo warnings: 0

That exact line is the only clean result (CLEAN below; the driver compares against it).

- errors / warnings: compiler diagnostics from `--message-format=json`, counted by code.
- finished: cargo's closing `build-finished` message. `no` means the stream was empty or cut
  short, so a missing warning proves nothing. A line that looks like JSON but does not parse
  also makes this `no`.
- cargo warnings: lines on cargo's own stderr that start with `warning:` or `warning[`, after
  colour codes and indentation are removed (a manifest problem, for example). Without the
  second argument this is reported as `unknown`, which is not clean.
"""
import collections
import json
import re
import sys

CLEAN = "errors: none  warnings: none  finished: ok  cargo warnings: 0"
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def main(argv):
    err, warn = collections.Counter(), collections.Counter()
    finished, broken = "no", False
    for line in open(argv[1], encoding="utf-8", errors="replace"):
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except ValueError:
            broken = True
            continue
        if o.get("reason") == "build-finished":
            finished = "ok" if o.get("success") else "failed"
        m = o.get("message") if o.get("reason") == "compiler-message" else None
        if not m:
            continue
        code = (m.get("code") or {}).get("code") or "(no code)"
        if m.get("level") == "error":
            err[code] += 1
        elif m.get("level") == "warning":
            warn[code] += 1
    if broken:
        finished = "no"
    cargo = "unknown"
    if len(argv) > 2:
        text = ANSI.sub("", open(argv[2], encoding="utf-8", errors="replace").read())
        cargo = sum(1 for line in text.split("\n") if re.match(r"\s*warning(:|\[)", line))
    print("errors: %s  warnings: %s  finished: %s  cargo warnings: %s" % (
        dict(err) or "none", dict(warn) or "none", finished, cargo))


if __name__ == "__main__":
    main(sys.argv)
