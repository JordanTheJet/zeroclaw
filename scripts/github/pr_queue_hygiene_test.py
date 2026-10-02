#!/usr/bin/env python3
"""Tests for PR queue hygiene decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import unittest

import pr_queue_hygiene as hygiene


REPO_ROOT = Path(__file__).resolve().parents[2]
REPO = "zeroclaw-labs/zeroclaw"
SHA = "a" * 40


def pr(**changes):
    base = {
        "id": "PR_node",
        "number": 100,
        "state": "OPEN",
        "is_draft": False,
        "head_sha": SHA,
        "body": "",
        "author": "contributor",
        "author_type": "User",
        "labels": [],
        "closing_issue_count": 0,
        "files": [{"path": "src/lib.rs", "additions": 10, "deletions": 2}],
        "files_truncated": False,
    }
    base.update(changes)
    return base


def ready(number, *labels):
    return {"number": number, "labels": list(labels)}


class LinkDecisionTest(unittest.TestCase):
    def test_unlinked_code_change_must_return_to_draft(self):
        self.assertIsNotNone(hygiene.link_decision(pr(), []))

    def test_closing_reference_satisfies_the_link(self):
        self.assertIsNone(hygiene.link_decision(pr(closing_issue_count=1), []))

    def test_body_issue_reference_satisfies_the_link(self):
        self.assertIsNone(hygiene.link_decision(pr(), [42]))

    def test_release_label_satisfies_the_link(self):
        self.assertIsNone(hygiene.link_decision(pr(labels=["release:v0.8.6"]), []))

    def test_bots_and_the_project_bot_are_exempt(self):
        self.assertIsNone(hygiene.link_decision(pr(author="dependabot", author_type="Bot"), []))
        self.assertIsNone(hygiene.link_decision(pr(author="ZeroClaw-Bot"), []))

    def test_small_docs_only_change_is_exempt(self):
        docs = [{"path": "docs/book/src/a.md", "additions": 30, "deletions": 5}]
        self.assertIsNone(hygiene.link_decision(pr(files=docs), []))

    def test_large_or_mixed_docs_change_is_not_exempt(self):
        large = [{"path": "README.md", "additions": 60, "deletions": 0}]
        mixed = [{"path": "README.md", "additions": 1, "deletions": 0},
                 {"path": "src/main.rs", "additions": 1, "deletions": 0}]
        self.assertIsNotNone(hygiene.link_decision(pr(files=large), []))
        self.assertIsNotNone(hygiene.link_decision(pr(files=mixed), []))

    def test_truncated_file_list_never_counts_as_docs_only(self):
        docs = [{"path": "a.md", "additions": 1, "deletions": 0}]
        self.assertIsNotNone(hygiene.link_decision(pr(files=docs, files_truncated=True), []))


class BodyReferencesTest(unittest.TestCase):
    def test_finds_hash_and_url_references_but_not_its_own_number(self):
        body = f"Part of #42. See https://github.com/{REPO}/issues/77 and #100."
        self.assertEqual(hygiene.body_references(body, REPO, 100), [42, 77])

    def test_ignores_references_inside_code_fences_and_other_repos(self):
        body = "```\nerror #999\n```\nother/repo#5 and https://github.com/other/repo/issues/6"
        self.assertEqual(hygiene.body_references(body, REPO, 1), [])

    def test_bounds_the_number_of_references(self):
        body = " ".join(f"#{n}" for n in range(1, 50))
        self.assertEqual(len(hygiene.body_references(body, REPO, 0)), hygiene.MAX_REFERENCES)


class IssueNumbersTest(unittest.TestCase):
    def test_skips_pull_requests_and_unresolvable_numbers(self):
        def gh(*args):
            number = int(args[-1].rsplit("/", 1)[1])
            if number == 1:
                raise hygiene.GitHubError("Not Found")
            if number == 2:
                return {"number": 2, "pull_request": {}}
            return {"number": number}

        self.assertEqual(hygiene.issue_numbers(gh, REPO, [1, 2, 3, 4]), [3])
        self.assertEqual(hygiene.issue_numbers(gh, REPO, [1, 2]), [])


class CapDecisionTest(unittest.TestCase):
    def test_author_at_the_cap_may_mark_another_ready_only_below_it(self):
        others = [ready(n) for n in range(1, hygiene.READY_CAP)]
        self.assertIsNone(hygiene.cap_decision(pr(number=999), others))
        others.append(ready(hygiene.READY_CAP))
        self.assertIsNotNone(hygiene.cap_decision(pr(number=999), others))

    def test_release_labeled_pull_requests_do_not_count(self):
        others = [ready(n, "release:v0.8.6") for n in range(1, 40)]
        self.assertIsNone(hygiene.cap_decision(pr(number=999), others))

    def test_release_labeled_pull_request_is_never_capped(self):
        others = [ready(n) for n in range(1, 40)]
        self.assertIsNone(hygiene.cap_decision(pr(number=999, labels=["release:v0.9.0"]), others))

    def test_search_results_that_include_this_pull_request_are_not_double_counted(self):
        others = [ready(n) for n in range(1, hygiene.READY_CAP)] + [ready(999)]
        self.assertIsNone(hygiene.cap_decision(pr(number=999), others))


class CiDecisionTest(unittest.TestCase):
    def test_failed_gate_on_current_head_returns_to_draft(self):
        self.assertIsNotNone(hygiene.ci_decision(pr(), SHA, "failure", "success"))

    def test_a_later_green_run_on_the_same_head_wins(self):
        self.assertIsNone(hygiene.ci_decision(pr(), SHA, "success", "success"))
        self.assertIsNone(hygiene.ci_decision(pr(), SHA, None, "success"))

    def test_bot_pull_requests_are_left_for_maintainers(self):
        self.assertIsNone(hygiene.ci_decision(pr(author="dependabot", author_type="Bot"), SHA, "failure", "success"))

    def test_red_master_protects_every_pull_request(self):
        self.assertIsNone(hygiene.ci_decision(pr(), SHA, "failure", "failure"))
        self.assertIsNone(hygiene.ci_decision(pr(), SHA, "failure", None))

    def test_moved_head_draft_or_closed_pull_request_is_left_alone(self):
        self.assertIsNone(hygiene.ci_decision(pr(head_sha="b" * 40), SHA, "failure", "success"))
        self.assertIsNone(hygiene.ci_decision(pr(is_draft=True), SHA, "failure", "success"))
        self.assertIsNone(hygiene.ci_decision(pr(state="CLOSED"), SHA, "failure", "success"))


class CommentTest(unittest.TestCase):
    def test_marker_comment_is_found_only_from_a_bot(self):
        marker = hygiene.MARKER.format(rule="ci")
        human = {"id": 1, "body": marker, "user": {"type": "User"}}
        bot = {"id": 2, "body": f"{marker}\ntext", "user": {"type": "Bot"}}
        self.assertEqual(hygiene.find_marker_comment([human, bot], "ci"), bot)
        self.assertIsNone(hygiene.find_marker_comment([human], "ci"))

    def test_every_rule_has_a_next_step(self):
        for rule in ("link", "cap", "ci"):
            self.assertIn(hygiene.MARKER.format(rule=rule), hygiene.comment_body(rule, "x", hygiene.DETAIL[rule]))

    def test_idle_cutoff_is_the_configured_days_ago(self):
        now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
        self.assertEqual(hygiene.idle_cutoff(now), "2026-10-01")


class CommandTest(unittest.TestCase):
    def test_report_only_mode_never_writes(self):
        calls = []

        def gh(*args):
            calls.append(args)
            if "graphql" in args and any("pullRequest(number" in a for a in args):
                node = {"id": "PR_node", "number": 100, "state": "OPEN", "isDraft": False, "headRefOid": SHA,
                        "body": "", "author": {"__typename": "User", "login": "contributor"},
                        "labels": {"nodes": []}, "closingIssuesReferences": {"totalCount": 0},
                        "files": {"totalCount": 1, "nodes": [{"path": "src/a.rs", "additions": 1, "deletions": 0}]}}
                return {"data": {"repository": {"pullRequest": node}}}
            raise AssertionError(f"unexpected call {args}")

        ctx = hygiene.Context(REPO, enforce=False, summary=None, gh=gh)
        hygiene.command_pr(ctx, 100)
        self.assertTrue(any("Would move #100" in line for line in ctx.lines))
        self.assertFalse(any("mutation" in a for call in calls for a in call))
        self.assertFalse(any(a in ("POST", "PATCH") for call in calls for a in call))

    def test_ci_rejects_a_malformed_head_sha(self):
        ctx = hygiene.Context(REPO, enforce=False, summary=None, gh=lambda *a: None)
        with self.assertRaises(hygiene.GitHubError):
            hygiene.command_ci(ctx, "not-a-sha; rm -rf /")


class WorkflowTest(unittest.TestCase):
    workflow = (REPO_ROOT / ".github/workflows/pr-queue-hygiene.yml").read_text(encoding="utf-8")

    def test_workflow_never_checks_out_pull_request_code(self):
        self.assertNotIn("actions/checkout", self.workflow)
        self.assertIn("scripts/github/pr_queue_hygiene.py?ref=$TRUSTED_REF", self.workflow)

    def test_enforcement_is_opt_in(self):
        self.assertIn("vars.PR_QUEUE_HYGIENE_ENFORCE == 'true'", self.workflow)

    def test_event_fields_reach_the_script_only_through_env(self):
        for line in self.workflow.splitlines():
            if line.strip().startswith("python3 "):
                self.assertNotIn("${{", line)


if __name__ == "__main__":
    unittest.main()
