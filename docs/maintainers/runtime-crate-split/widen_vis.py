#!/usr/bin/env python3
"""widen_vis.py: turn `pub(crate)` into `pub` exactly where the compiler says a move needs it.

After a module moves to its own crate, items it declared `pub(crate)` that the
old crate still uses are no longer visible. Rather than guess, feed this script the
JSON diagnostics of a failed check and it widens only the items rustc names:

  cargo check -p zeroclaw-runtime --all-targets --message-format=json 2>/dev/null \
      | widen_vis.py --repo . --only crates/zeroclaw-observability

Repeat until it reports 0 edits. Every edit is printed, so the list can go in the
PR description. Handles E0603 (private item), E0616/E0451 (private field) and
E0624 (private method). It never touches a file outside --only.

It also handles the one case a crate boundary breaks that is not about privacy: a
`#[cfg(test)]` helper in the moved module that tests in the OLD crate still use
(E0425/E0432/E0433 "cannot find X in module"). `cfg(test)` is per crate, so the
helper is re-gated as `#[cfg(any(test, feature = "test-util"))]`, made `pub`, and
with --from-crate the feature is declared in the new crate and enabled from the old
crate's dev-dependencies only. That is the pattern this repo already uses
(`zeroclaw-runtime/test-util`, `zeroclaw-tools/test-helpers`).
"""
import argparse
import json
import os
import re
import sys

VIS = re.compile(r"pub\s*\(\s*(?:crate|super|in\s+[^)]*)\)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--only", required=True, help="path prefix (repo-relative) that may be edited")
    ap.add_argument("--from-crate", help="crate dir (repo-relative) whose dev-dependencies should enable test-util")
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    only = a.only.rstrip("/") + "/"

    targets = set()   # (file, line) definition sites
    fields = set()    # (field, struct)
    missing = set()   # names the old crate cannot find any more
    other = {}
    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        msg = o.get("message") if o.get("reason") == "compiler-message" else None
        if not msg or msg.get("level") != "error":
            continue
        code = (msg.get("code") or {}).get("code")
        if code in ("E0603", "E0624"):
            spans = list(msg.get("spans", []))
            for ch in msg.get("children", []):
                spans += ch.get("spans", [])
                if "defined here" in ch.get("message", "") or "private" in ch.get("message", ""):
                    for sp in ch.get("spans", []):
                        if sp["file_name"].startswith(only):
                            targets.add((sp["file_name"], sp["line_start"]))
            for sp in spans:
                lab = sp.get("label") or ""
                if sp["file_name"].startswith(only) and ("defined here" in lab):
                    targets.add((sp["file_name"], sp["line_start"]))
        elif code in ("E0616", "E0451"):
            m = re.search(r"field `([^`]+)` of (?:struct|type|union) `([^`]+)` is private", msg.get("message", ""))
            if m:
                fields.add((m.group(1), m.group(2).split("::")[-1].split("<")[0]))
        elif code in ("E0425", "E0432", "E0433", "E0412"):
            m = re.search(r"cannot find (?:value|function|struct|type|trait|macro|unit struct|tuple struct|type alias|constant|static)?\s*`([A-Za-z_][A-Za-z0-9_]*)` in ", msg.get("message", ""))
            m = m or re.search(r"unresolved import `(?:[A-Za-z0-9_]+::)*([A-Za-z_][A-Za-z0-9_]*)`", msg.get("message", ""))
            if m:
                missing.add(m.group(1))
            else:
                other[code] = other.get(code, 0) + 1
        else:
            other[code] = other.get(code, 0) + 1

    edits = []
    cache = {}

    def lines_of(f):
        if f not in cache:
            cache[f] = open(os.path.join(repo, f), encoding="utf-8").read().split("\n")
        return cache[f]

    for f, ln in sorted(targets):
        ls = lines_of(f)
        for k in range(ln - 1, min(ln + 6, len(ls))):
            if VIS.search(ls[k]):
                new = VIS.sub("pub", ls[k], count=1)
                edits.append((f, k + 1, ls[k].strip()[:90]))
                ls[k] = new
                break
    if fields:
        files = []
        for d, _, fs in os.walk(os.path.join(repo, only)):
            files += [os.path.relpath(os.path.join(d, x), repo) for x in fs if x.endswith(".rs")]
        for field, struct in sorted(fields):
            pat = re.compile(r"pub\s*\(\s*(?:crate|super)\s*\)(\s+%s\s*:)" % re.escape(field))
            hits = []
            for f in files:
                ls = lines_of(f)
                text = "\n".join(ls)
                sm = re.search(r"(?:struct|union)\s+%s\b" % re.escape(struct), text)
                if not sm:
                    continue
                start = text.count("\n", 0, sm.start())
                for k in range(start, min(start + 400, len(ls))):
                    if pat.search(ls[k]):
                        hits.append((f, k))
                        break
            for f, k in hits:
                ls = lines_of(f)
                edits.append((f, k + 1, ls[k].strip()[:90]))
                ls[k] = pat.sub(r"pub\1", ls[k], count=1)
    regated = False
    if missing:
        files = []
        for d, _, fs in os.walk(os.path.join(repo, only)):
            files += [os.path.relpath(os.path.join(d, x), repo) for x in fs if x.endswith(".rs")]
        for name in sorted(missing):
            decl = re.compile(r"^(\s*)(?:pub(?:\s*\([^)]*\))?\s+)?((?:async\s+|unsafe\s+|const\s+)*(?:static|fn|struct|enum|const|type|trait|mod)\s+%s\b)" % re.escape(name))
            for f in files:
                ls = lines_of(f)
                for k, line in enumerate(ls):
                    mm = decl.match(line)
                    if not mm:
                        continue
                    a_ = k - 1
                    while a_ >= 0 and ls[a_].strip().startswith("#[") and ls[a_].strip() != "#[cfg(test)]":
                        a_ -= 1
                    if a_ < 0 or ls[a_].strip() != "#[cfg(test)]":
                        continue
                    ls[a_] = ls[a_].replace("#[cfg(test)]", '#[cfg(any(test, feature = "test-util"))]')
                    ls[k] = decl.sub(lambda q: q.group(1) + "pub " + q.group(2), line, count=1)
                    edits.append((f, k + 1, "test-util: " + line.strip()[:78]))
                    regated = True
    if regated:
        man = os.path.join(repo, only, "Cargo.toml")
        t = open(man, encoding="utf-8").read()
        if not re.search(r"(?m)^test-util\s*=", t):
            if "[features]" in t:
                t = t.replace("[features]\n", "[features]\n# Test-only helpers for OTHER crates' test builds; no production edge enables it.\ntest-util = []\n", 1)
            else:
                t = t.rstrip("\n") + "\n\n[features]\n# Test-only helpers for OTHER crates' test builds; no production edge enables it.\ntest-util = []\n"
            open(man, "w", encoding="utf-8").write(t)
            print("declared feature test-util in %s" % os.path.relpath(man, repo))
        if a.from_crate:
            dep = os.path.basename(only.rstrip("/"))
            man = os.path.join(repo, a.from_crate, "Cargo.toml")
            t = open(man, encoding="utf-8").read()
            line = '%s = { workspace = true, features = ["test-util"] }' % dep
            if line not in t and "[dev-dependencies]" in t:
                t = t.replace("[dev-dependencies]\n", "[dev-dependencies]\n" + line + "\n", 1)
                open(man, "w", encoding="utf-8").write(t)
                print("enabled %s/test-util from %s dev-dependencies" % (dep, a.from_crate))
    for f, ls in cache.items():
        open(os.path.join(repo, f), "w", encoding="utf-8").write("\n".join(ls))
    for f, ln, text in edits:
        print("widened %s:%d  %s" % (f, ln, text))
    print("%d edits; other error codes seen: %s" % (len(edits), other or "none"))


if __name__ == "__main__":
    main()
