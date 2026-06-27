#!/usr/bin/env python3
"""Post ACCEPTED gh-notif drafts to GitHub as COMMENTS — deterministically.

Finds drafts in the private drafts-repo clone whose frontmatter says
`status: accepted`, extracts the verbatim text between <!-- REPLY:BEGIN --> and
<!-- REPLY:END -->, and posts it as a COMMENT via `gh` — never a review,
approval, request-changes, merge, close, or label. On success it flips the draft
to `status: posted` and records `posted_at` + `posted_comment_url`, then commits
and pushes the clone.

SAFE BY DEFAULT: dry-run unless --post is given. Only `status: accepted` drafts
are touched; only issue/PR comments are posted; nothing else is mutated. There is
no LLM in this path — the text posted is exactly the marked block.

  usage: ship_accepted.py <gh-notif-workspace-dir> [--post]
                          [--repo OWNER/REPO] [--only SUBSTR]
"""
import argparse
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
KV_RE = re.compile(r"^([A-Za-z0-9_]+):\s*(.*)$")
REPLY_RE = re.compile(r"<!--\s*REPLY:BEGIN\s*-->\n?(.*?)\n?<!--\s*REPLY:END\s*-->", re.DOTALL)
PLACEHOLDER = "REPLACE_WITH_PUBLIC_REPLY_OR_LEAVE_EMPTY"


def parse_fm(text):
    m = FM_RE.match(text)
    if not m:
        return None
    data = {}
    for line in m.group(1).splitlines():
        km = KV_RE.match(line)
        if not km:
            continue
        k, v = km.group(1), km.group(2).strip()
        if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
            v = v[1:-1]
        data[k] = v
    return data


def extract_reply(text):
    """Return the stripped reply between the markers, '' if empty/placeholder, or
    None if the markers are absent."""
    m = REPLY_RE.search(text)
    if not m:
        return None
    body = m.group(1).strip()
    return "" if (not body or body == PLACEHOLDER) else body


def set_posted(text, url, when):
    m = FM_RE.match(text)
    out, fm = [], m.group(1)
    for line in fm.splitlines():
        km = KV_RE.match(line)
        if km and km.group(1) == "status":
            out.append('status: "posted"')
        elif km and km.group(1) in ("posted_at", "posted_comment_url"):
            continue  # replace any stale values
        else:
            out.append(line)
    out.append(f'posted_at: "{when}"')
    out.append(f'posted_comment_url: "{url}"')
    return text[: m.start(1)] + "\n".join(out) + text[m.end(1):]


def gh_comment(repo, kind, number, body, post):
    """kind is 'pr' or 'issue'. Returns (ok, url_or_error)."""
    if not post:
        return True, "(dry-run, not posted)"
    cmd = ["gh", kind, "comment", str(number), "--repo", repo, "--body-file", "-"]
    try:
        r = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return False, f"gh invocation failed: {e}"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "gh failed").strip()
    out = (r.stdout or "").strip()
    return True, (out.splitlines()[-1] if out else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("--post", action="store_true", help="actually post (default: dry-run)")
    ap.add_argument("--repo", help="restrict to this owner/repo")
    ap.add_argument("--only", help="restrict to files whose path contains this substring")
    args = ap.parse_args()

    clone = os.path.join(args.workspace, "drafts-repo")
    if not os.path.isdir(os.path.join(clone, ".git")):
        print(f"ship: no drafts-repo clone at {clone}; nothing to do", file=sys.stderr)
        return 0
    subprocess.run(["git", "-C", clone, "pull", "--ff-only", "--quiet"], check=False)

    triage = os.path.join(clone, "triage")
    posted = skipped = errors = 0
    changed = False
    days = sorted(os.listdir(triage)) if os.path.isdir(triage) else []
    for day in days:
        items = os.path.join(triage, day, "items")
        if not os.path.isdir(items):
            continue
        for name in sorted(os.listdir(items)):
            if not name.endswith(".md"):
                continue
            path = os.path.join(items, name)
            if args.only and args.only not in path:
                continue
            with open(path, encoding="utf-8") as f:
                text = f.read()
            fm = parse_fm(text)
            if not fm or fm.get("status") != "accepted":
                continue
            repo, number, typ = fm.get("repo", ""), fm.get("number", ""), fm.get("type", "")
            if args.repo and repo != args.repo:
                continue
            kind = {"PullRequest": "pr", "Issue": "issue"}.get(typ)
            reply = extract_reply(text)
            label = f"{repo}#{number} ({typ})"
            if not kind or not number:
                print(f"SKIP  {label}: not a commentable issue/PR — {name}")
                skipped += 1
                continue
            if reply is None:
                print(f"SKIP  {label}: no REPLY block — {name}")
                skipped += 1
                continue
            if reply == "":
                print(f"SKIP  {label}: empty REPLY block (accepted but nothing to post) — {name}")
                skipped += 1
                continue
            print(f"\n{'POST' if args.post else 'WOULD POST'} -> {label}  [{name}]")
            print("  | " + "\n  | ".join(reply.splitlines()))
            ok, res = gh_comment(repo, kind, number, reply, args.post)
            if not ok:
                print(f"  ERROR: {res}")
                errors += 1
                continue
            if args.post:
                when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(set_posted(text, res, when))
                changed = True
                print(f"  posted: {res}")
            posted += 1

    if args.post and changed:
        subprocess.run(["git", "-C", clone, "add", "-A"], check=False)
        subprocess.run(["git", "-C", clone, "-c", "user.name=gh_notif",
                        "-c", "user.email=gh-notif@local", "commit", "-q",
                        "-m", f"ship: posted {posted} accepted draft(s)"], check=False)
        subprocess.run(["git", "-C", clone, "push", "-q"], check=False)

    verb = "posted" if args.post else "would post"
    tail = "" if args.post else "  (dry-run — pass --post to actually comment)"
    print(f"\nship: {verb} {posted}, skipped {skipped}, errors {errors}{tail}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
