#!/usr/bin/env python3
"""Keep the ready-for-review pull request queue reviewable.

Policy: docs/book/src/maintainers/pr-workflow.md#queue-hygiene-automation.
Report-only unless the ENFORCE environment variable is "true".
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import re
import subprocess
import sys
from typing import Any, Callable, Iterable

READY_CAP = 15
IDLE_DRAFT_DAYS = 21
DOCS_ONLY_MAX_LINES = 50
RELEASE_LABEL_PREFIX = "release:"
NO_STALE_LABEL = "status:no-stale"
EXEMPT_AUTHORS = {"zeroclaw-bot"}
QUALITY_GATE_WORKFLOW = "ci.yml"
GH_TIMEOUT_SECONDS = 30
MAX_REFERENCES = 20
MARKER = "<!-- pr-queue-hygiene:{rule} -->"

REFERENCE = re.compile(r"(?:github\.com/{repo}/(?:issues|pull)/|(?<![\w/])#)(\d+)\b")
FENCED_CODE = re.compile(r"```.*?```", re.S)


class GitHubError(RuntimeError):
    """A GitHub request failed or returned an unusable shape."""


def run_gh(*args: str) -> Any:
    try:
        result = subprocess.run(
            ["gh", *args], check=True, capture_output=True, text=True, timeout=GH_TIMEOUT_SECONDS
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise GitHubError(f"gh command failed: {detail}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitHubError(f"gh command timed out after {GH_TIMEOUT_SECONDS}s") from exc
    return json.loads(result.stdout) if result.stdout.strip() else None


def graphql(gh: Callable[..., Any], query: str, **variables: Any) -> dict[str, Any]:
    args = ["api", "graphql", "-f", f"query={query}"]
    for key, value in variables.items():
        args += ["-F" if isinstance(value, int) else "-f", f"{key}={value}"]
    payload = gh(*args)
    if not isinstance(payload, dict) or "data" not in payload:
        raise GitHubError(f"unexpected GraphQL response: {payload!r}")
    return payload["data"]


# ---------------------------------------------------------------- decisions


def release_labeled(pr: dict[str, Any]) -> bool:
    return any(label.startswith(RELEASE_LABEL_PREFIX) for label in pr["labels"])


def exempt_author(pr: dict[str, Any]) -> bool:
    return pr["author_type"] == "Bot" or pr["author"].casefold() in EXEMPT_AUTHORS


def docs_only_small(pr: dict[str, Any]) -> bool:
    files = pr["files"]
    if not files or pr["files_truncated"]:
        return False
    changed = sum(f["additions"] + f["deletions"] for f in files)
    return changed <= DOCS_ONLY_MAX_LINES and all(f["path"].endswith(".md") for f in files)


def body_references(body: str, repository: str, own_number: int) -> list[int]:
    text = FENCED_CODE.sub("", body or "")
    pattern = re.compile(REFERENCE.pattern.format(repo=re.escape(repository)))
    numbers = sorted({int(n) for n in pattern.findall(text)} - {own_number})
    return numbers[:MAX_REFERENCES]


def link_decision(pr: dict[str, Any], issue_references: list[int]) -> str | None:
    """Return None when the PR may stay ready, else the reason it may not."""
    if exempt_author(pr) or docs_only_small(pr) or release_labeled(pr):
        return None
    if pr["closing_issue_count"] or issue_references:
        return None
    return "it does not link an issue and carries no `release:*` label"


def cap_decision(pr: dict[str, Any], author_ready: list[dict[str, Any]], cap: int = READY_CAP) -> str | None:
    if exempt_author(pr) or release_labeled(pr):
        return None
    counted = {p["number"] for p in author_ready if not release_labeled(p)} | {pr["number"]}
    if len(counted) <= cap:
        return None
    return f"@{pr['author']} already has {len(counted) - 1} ready pull requests without a `release:*` label (limit {cap})"


def ci_decision(
    pr: dict[str, Any], head_sha: str, head_conclusion: str | None, master_conclusion: str | None
) -> str | None:
    if pr["state"] != "OPEN" or pr["is_draft"] or exempt_author(pr):
        return None
    if pr["head_sha"] != head_sha or head_conclusion != "failure":
        return None
    if master_conclusion != "success":
        return None
    return f"its Quality Gate failed on the current head `{head_sha[:10]}`"


def idle_cutoff(now: datetime, days: int = IDLE_DRAFT_DAYS) -> str:
    return (now - timedelta(days=days)).strftime("%Y-%m-%d")


def find_marker_comment(comments: Iterable[dict[str, Any]], rule: str) -> dict[str, Any] | None:
    marker = MARKER.format(rule=rule)
    for comment in comments:
        if marker in (comment.get("body") or "") and (comment.get("user") or {}).get("type") == "Bot":
            return comment
    return None


def comment_body(rule: str, reason: str, detail: str) -> str:
    return (
        f"{MARKER.format(rule=rule)}\n"
        f"This pull request was moved to draft because {reason}.\n\n"
        f"{detail}\n\n"
        "See [queue hygiene](https://github.com/zeroclaw-labs/zeroclaw/blob/master/"
        "docs/book/src/maintainers/pr-workflow.md#queue-hygiene-automation)."
    )


DETAIL = {
    "link": "Add `Closes #N`, `Part of #N`, or the tracker issue to the description, then mark it ready again.",
    "cap": "Mark it ready again when one of your other ready pull requests merges, closes, or returns to draft.",
    "ci": "Fix or rerun the failing jobs, then mark it ready again once the Quality Gate is green.",
}


# ---------------------------------------------------------------- GitHub reads

PR_QUERY = """query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){
pullRequest(number:$number){id number state isDraft headRefOid body author{__typename login}
labels(first:50){nodes{name}} closingIssuesReferences(first:1){totalCount}
files(first:100){totalCount nodes{path additions deletions}}}}}"""


def normalize_pr(node: dict[str, Any]) -> dict[str, Any]:
    author = node.get("author") or {}
    files = node["files"]
    return {
        "id": node["id"],
        "number": node["number"],
        "state": node["state"],
        "is_draft": node["isDraft"],
        "head_sha": node["headRefOid"],
        "body": node.get("body") or "",
        "author": author.get("login") or "ghost",
        "author_type": author.get("__typename") or "User",
        "labels": [label["name"] for label in node["labels"]["nodes"]],
        "closing_issue_count": node["closingIssuesReferences"]["totalCount"],
        "files": files["nodes"],
        "files_truncated": files["totalCount"] > len(files["nodes"]),
    }


def fetch_pr(gh: Callable[..., Any], repository: str, number: int) -> dict[str, Any]:
    owner, name = repository.split("/", 1)
    node = graphql(gh, PR_QUERY, owner=owner, name=name, number=number)["repository"]["pullRequest"]
    if not node:
        raise GitHubError(f"pull request #{number} not found")
    return normalize_pr(node)


def issue_numbers(gh: Callable[..., Any], repository: str, numbers: list[int]) -> list[int]:
    """Return the first referenced number that is an issue; unresolvable numbers are skipped."""
    for number in numbers:
        try:
            item = gh("api", f"repos/{repository}/issues/{number}")
        except GitHubError:
            continue
        if isinstance(item, dict) and "pull_request" not in item:
            return [number]
    return []


def search_prs(gh: Callable[..., Any], query: str) -> list[dict[str, Any]]:
    payload = gh("api", "--paginate", "--slurp", "-X", "GET", "search/issues", "-f", f"q={query}", "-f", "per_page=100")
    items: list[dict[str, Any]] = []
    for page in payload or []:
        items += page.get("items", [])
    return [
        {"number": item["number"], "labels": [label["name"] for label in item.get("labels", [])]}
        for item in items
    ]


def latest_quality_gate(gh: Callable[..., Any], repository: str, *filters: str) -> str | None:
    args = ["api", f"repos/{repository}/actions/workflows/{QUALITY_GATE_WORKFLOW}/runs", "-X", "GET"]
    for item in (*filters, "status=completed", "per_page=10"):
        args += ["-f", item]
    runs = gh(*args)
    for run in (runs or {}).get("workflow_runs", []):
        if run.get("conclusion") in {"success", "failure"}:
            return run["conclusion"]
    return None


# ---------------------------------------------------------------- GitHub writes


def move_to_draft(gh: Callable[..., Any], repository: str, pr: dict[str, Any], rule: str, reason: str) -> None:
    graphql(
        gh,
        "mutation($id:ID!){convertPullRequestToDraft(input:{pullRequestId:$id}){pullRequest{isDraft}}}",
        id=pr["id"],
    )
    body = comment_body(rule, reason, DETAIL[rule])
    pages = gh("api", "--paginate", "--slurp", f"repos/{repository}/issues/{pr['number']}/comments?per_page=100")
    existing = find_marker_comment((c for page in pages or [] for c in page), rule)
    if existing:
        gh("api", "-X", "PATCH", f"repos/{repository}/issues/comments/{existing['id']}", "-f", f"body={body}")
    else:
        gh("api", "-X", "POST", f"repos/{repository}/issues/{pr['number']}/comments", "-f", f"body={body}")


# ---------------------------------------------------------------- commands


class Context:
    def __init__(self, repository: str, enforce: bool, summary: str | None, gh: Callable[..., Any] = run_gh):
        self.repository, self.enforce, self.summary_path, self.gh = repository, enforce, summary, gh
        self.lines: list[str] = []

    def record(self, line: str) -> None:
        print(line)
        self.lines.append(line)

    def act(self, pr: dict[str, Any], rule: str, reason: str) -> None:
        verb = "Moved" if self.enforce else "Would move"
        self.record(f"- {verb} #{pr['number']} to draft ({rule}): {reason}.")
        if self.enforce:
            move_to_draft(self.gh, self.repository, pr, rule, reason)

    def flush(self) -> None:
        if self.summary_path:
            mode = "enforcing" if self.enforce else "report-only"
            with open(self.summary_path, "a", encoding="utf-8") as out:
                out.write(f"### PR queue hygiene ({mode})\n\n" + ("\n".join(self.lines) or "No action.") + "\n")


def command_pr(ctx: Context, number: int) -> None:
    pr = fetch_pr(ctx.gh, ctx.repository, number)
    if pr["state"] != "OPEN" or pr["is_draft"]:
        ctx.record(f"- #{number} is not an open ready pull request; nothing to check.")
        return
    references = issue_numbers(ctx.gh, ctx.repository, body_references(pr["body"], ctx.repository, number))
    reason = link_decision(pr, references)
    if reason:
        ctx.act(pr, "link", reason)
        return
    author_ready = search_prs(ctx.gh, f"repo:{ctx.repository} is:pr is:open draft:false author:{pr['author']}")
    reason = cap_decision(pr, author_ready)
    if reason:
        ctx.act(pr, "cap", reason)
        return
    ctx.record(f"- #{number} may stay ready.")


def command_ci(ctx: Context, head_sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise GitHubError("head SHA must be 40 lowercase hex characters")
    master = latest_quality_gate(ctx.gh, ctx.repository, "branch=master", "event=push")
    head = latest_quality_gate(ctx.gh, ctx.repository, f"head_sha={head_sha}", "event=pull_request")
    candidates = search_prs(ctx.gh, f"repo:{ctx.repository} is:pr is:open draft:false {head_sha}")
    if not candidates:
        ctx.record(f"- No open ready pull request has head `{head_sha[:10]}`.")
    for candidate in candidates:
        pr = fetch_pr(ctx.gh, ctx.repository, candidate["number"])
        reason = ci_decision(pr, head_sha, head, master)
        if reason:
            ctx.act(pr, "ci", reason)
        elif head != "failure":
            ctx.record(f"- Left #{pr['number']} ready: its latest Quality Gate on this head is `{head}`.")
        elif master != "success":
            ctx.record(f"- Left #{pr['number']} ready: master's latest Quality Gate is `{master}`.")
        else:
            ctx.record(f"- Left #{pr['number']} unchanged: already draft, closed, or head moved.")


def command_idle_drafts(ctx: Context, now: datetime) -> None:
    query = (
        f"repo:{ctx.repository} is:pr is:open draft:true updated:<{idle_cutoff(now)} -label:{NO_STALE_LABEL}"
    )
    for pr in search_prs(ctx.gh, query):
        body = (
            f"{MARKER.format(rule='idle-draft')}\n"
            f"This draft has had no activity for {IDLE_DRAFT_DAYS} days. Please mark it ready, "
            "say what it is waiting on, or close it so the queue reflects live work."
        )
        verb = "Reminded" if ctx.enforce else "Would remind"
        ctx.record(f"- {verb} idle draft #{pr['number']}.")
        if ctx.enforce:
            ctx.gh("api", "-X", "POST", f"repos/{ctx.repository}/issues/{pr['number']}/comments", "-f", f"body={body}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--summary")
    sub = parser.add_subparsers(dest="command", required=True)
    pr_cmd = sub.add_parser("pr", help="check one pull request that was opened, reopened, or marked ready")
    pr_cmd.add_argument("--pr-number", type=int, required=True)
    ci_cmd = sub.add_parser("ci", help="handle a failed Quality Gate run")
    ci_cmd.add_argument("--head-sha", required=True)
    sub.add_parser("idle-drafts", help="remind drafts with no recent activity")
    args = parser.parse_args(argv)

    ctx = Context(args.repository, os.environ.get("ENFORCE") == "true", args.summary)
    try:
        if args.command == "pr":
            command_pr(ctx, args.pr_number)
        elif args.command == "ci":
            command_ci(ctx, args.head_sha)
        else:
            command_idle_drafts(ctx, datetime.now(timezone.utc))
    except GitHubError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        ctx.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
