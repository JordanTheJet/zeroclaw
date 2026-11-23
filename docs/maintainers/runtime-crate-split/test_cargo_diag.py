#!/usr/bin/env python3
"""test_cargo_diag.py: what the driver treats as a clean cargo run. Needs python3 only.

    python3 test_cargo_diag.py

The driver accepts a check only when cargo_diag.py prints exactly its CLEAN line, so these
cases pin down everything that must NOT read as clean: a compiler warning, a stream that was
cut short or is empty, and a warning on cargo's own stderr however it is decorated.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cargo_diag import CLEAN  # noqa: E402

FINISHED = json.dumps({"reason": "build-finished", "success": True})
ARTIFACT = json.dumps({"reason": "compiler-artifact", "target": {"name": "x"}})


def msg(level, code):
    return json.dumps({"reason": "compiler-message",
                       "message": {"level": level, "code": {"code": code} if code else None, "spans": []}})


def diag(stdout, stderr=None):
    d = tempfile.mkdtemp(prefix="diag-test-")
    j = os.path.join(d, "out.json")
    open(j, "w").write(stdout)
    args = [sys.executable, os.path.join(HERE, "cargo_diag.py"), j]
    if stderr is not None:
        e = os.path.join(d, "err.txt")
        open(e, "w").write(stderr)
        args.append(e)
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()


CASES = [
    ("a finished run with quiet stderr is clean", (ARTIFACT + "\n" + FINISHED + "\n", "    Finished `dev` profile\n"), True),
    ("a compiler warning is not clean", (msg("warning", "unused_imports") + "\n" + FINISHED + "\n", ""), False),
    ("a compiler error is not clean", (msg("error", "E0425") + "\n" + json.dumps({"reason": "build-finished", "success": False}) + "\n", ""), False),
    ("an empty stream is not clean", ("", ""), False),
    ("a stream cut before build-finished is not clean", (ARTIFACT + "\n", ""), False),
    ("a truncated JSON line is not clean", (ARTIFACT + "\n" + FINISHED + "\n" + '{"reason":"compiler-mess', ""), False),
    ("a plain cargo warning is not clean", (FINISHED + "\n", "warning: unused manifest key: package.foo\n"), False),
    ("an indented cargo warning is not clean", (FINISHED + "\n", "   warning: unused manifest key\n"), False),
    ("a coloured cargo warning is not clean", (FINISHED + "\n", "\x1b[1m\x1b[33mwarning\x1b[0m\x1b[1m:\x1b[0m unused manifest key\n"), False),
    ("a coded cargo warning is not clean", (FINISHED + "\n", "warning[E0000]: something\n"), False),
    ("the word warnings in a summary is not a warning", (FINISHED + "\n", "note: warnings: none were emitted\nwarnings are denied\n"), True),
    ("no stderr file means unknown, not clean", (FINISHED + "\n", None), False),
]


def main():
    failed = 0
    for name, (out, err), want_clean in CASES:
        got = diag(out, err)
        if (got == CLEAN) == want_clean:
            print("ok    %s" % name)
        else:
            failed += 1
            print("FAIL  %s\n      got: %s" % (name, got))
    print("%d cases, %d failed" % (len(CASES), failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
