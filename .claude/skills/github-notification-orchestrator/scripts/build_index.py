#!/usr/bin/env python3
"""Build INDEX.md for a notification-digest run.

Reads every report in <run-dir>/items/*.md, parses its frontmatter, sorts
newest-to-oldest by `updated_at`, groups by priority, and writes
<run-dir>/INDEX.md with correct relative links plus a lede placeholder for the
summarizer to fill.

Sorting and link generation are deterministic, so they live here rather than in
a model: the digest is reproducible and links never hallucinate. No third-party
dependencies — frontmatter is parsed directly so this runs anywhere Python 3 does.

    Usage: build_index.py <run-dir>
"""
import os
import re
import sys

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
KV_RE = re.compile(r"^([A-Za-z0-9_]+):\s*(.*)$")
TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})")

BANDS = [("P1", "needs you"), ("P2", "drafted & waiting"), ("P3", "FYI")]
LEDE_PLACEHOLDER = "> _Lede pending._ <!-- LEDE -->"


def parse_frontmatter(text):
    """Return a dict of the leading YAML-ish frontmatter, or None if absent."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    data = {}
    for line in m.group(1).splitlines():
        km = KV_RE.match(line)
        if not km:
            continue
        key, val = km.group(1), km.group(2).strip()
        if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
            val = val[1:-1]
        data[key] = val
    return data


def human_time(iso):
    m = TIME_RE.match(iso or "")
    return f"{m.group(1)} {m.group(2)} UTC" if m else (iso or "unknown time")


def label(rec):
    num = rec.get("number", "")
    tag = f"#{num} " if num else ""
    return f"{tag}{rec.get('title', '(untitled)')}"


def bullet(rec):
    meta = f"{rec.get('reason', '?')} · {rec.get('repo', '?')} · {human_time(rec.get('updated_at'))}"
    return f"- **[{label(rec)}](items/{rec['_file']})** — {meta}"


def existing_lede(run_dir):
    """Preserve a human-written lede across re-runs. Returns the filled-in lede
    line (the one carrying the LEDE marker) if present, else None — so re-running
    the builder after a late item lands does not wipe the summarizer's narrative."""
    path = os.path.join(run_dir, "INDEX.md")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if "<!-- LEDE -->" in line:
                line = line.rstrip("\n")
                return None if line.strip() == LEDE_PLACEHOLDER else line
    return None


def main():
    if len(sys.argv) != 2:
        print("usage: build_index.py <run-dir>", file=sys.stderr)
        return 2
    run_dir = sys.argv[1]
    items_dir = os.path.join(run_dir, "items")
    if not os.path.isdir(items_dir):
        print(f"no items/ directory under {run_dir}", file=sys.stderr)
        return 1

    records, skipped = [], []
    for name in sorted(os.listdir(items_dir)):
        if not name.endswith(".md"):
            continue
        with open(os.path.join(items_dir, name), encoding="utf-8") as f:
            fm = parse_frontmatter(f.read())
        if not fm or not fm.get("updated_at"):
            skipped.append(name)
            continue
        fm["_file"] = name
        records.append(fm)

    # Newest first. ISO-8601 UTC timestamps sort correctly as plain strings.
    records.sort(key=lambda r: r.get("updated_at", ""), reverse=True)

    date = os.path.basename(os.path.normpath(run_dir))
    known = {b for b, _ in BANDS}
    counts = {b: sum(1 for r in records if r.get("priority") == b) for b, _ in BANDS}
    other = sum(1 for r in records if r.get("priority") not in known)

    out = [f"# Notification digest — {date}\n", (existing_lede(run_dir) or LEDE_PLACEHOLDER) + "\n"]
    stat = " · ".join(
        [f"{len(records)} reports"]
        + [f"{counts[b]} {b}" for b, _ in BANDS if counts[b]]
        + ([f"{other} other"] if other else [])
    )
    out.append(f"{stat} · newest first\n")

    for band, desc in BANDS:
        group = [r for r in records if r.get("priority") == band]
        if group:
            out.append(f"## {band} — {desc} ({len(group)})\n")
            out.extend(bullet(r) for r in group)
            out.append("")

    leftover = [r for r in records if r.get("priority") not in known]
    if leftover:
        out.append(f"## Unprioritized ({len(leftover)})\n")
        out.extend(bullet(r) for r in leftover)
        out.append("")

    out.append("## All items, newest → oldest\n")
    for i, r in enumerate(records, 1):
        out.append(f"{i}. [{label(r)}](items/{r['_file']}) — {human_time(r.get('updated_at'))}")
    out.append("")

    index_path = os.path.join(run_dir, "INDEX.md")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

    print(f"Wrote {index_path} ({len(records)} reports indexed).")
    if skipped:
        print(f"Skipped {len(skipped)} file(s) with missing/invalid frontmatter: {', '.join(skipped)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
