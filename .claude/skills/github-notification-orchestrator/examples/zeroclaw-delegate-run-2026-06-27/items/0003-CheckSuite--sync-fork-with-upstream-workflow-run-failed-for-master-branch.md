---
notification_id: "24391994492"
updated_at: "2026-06-27T08:10:35Z"
reason: "ci_activity"
repo: "JordanTheJet/zeroclaw"
type: "CheckSuite"
number: ""
title: "sync fork with upstream workflow run failed for master branch"
url: "https://github.com/JordanTheJet/zeroclaw/actions/runs/28283483718"
agent_profile: "ci-failure-investigator"
priority: "P2"
status: "action-required"
---

# — sync fork with upstream workflow run failed for master branch

**Repo:** JordanTheJet/zeroclaw · **Type:** CheckSuite · **Reason:** ci_activity · **Updated:** 2026-06-27 08:10 UTC
**Link:** https://github.com/JordanTheJet/zeroclaw/actions/runs/28283483718

## What happened

The scheduled **"sync fork with upstream"** workflow (`.github/workflows/sync-upstream.yml`, run ID `28283483718`) failed at 08:10 UTC on 2026-06-27 in the single job **sync**, specifically at the **"Merge upstream/master into master"** step. The merge itself succeeded — `git merge --no-edit upstream/master` pulled in 166 changed files (11 072 insertions) from `zeroclaw-labs/zeroclaw` — but the subsequent `git push origin HEAD:master` was rejected by GitHub:

```
! [remote rejected] HEAD -> master
  (refusing to allow a GitHub App to create or update workflow
   `.github/workflows/ci-sbom.yml` without `workflows` permission)
error: failed to push some refs to 'https://github.com/JordanTheJet/zeroclaw'
```

The upstream batch introduced a **new workflow file** (`.github/workflows/ci-sbom.yml`) and a second one (`.github/workflows/npm-deps-review.yml`). GitHub's API requires the `workflows` permission to push commits that add or modify files under `.github/workflows/`. The fork's `GITHUB_TOKEN` for this workflow only declares `contents: write` — it lacks `workflows: write` — so the push is blocked. The identical error also fired on 2026-06-26 (run `28226591480`), making this a **recurring daily failure** until the permission is added.

## Who needs what from you

You need to add `workflows: write` to the `permissions` block of `.github/workflows/sync-upstream.yml` so that the `GITHUB_TOKEN` is allowed to push commits containing workflow file changes. No merge conflict resolution is needed — the merge was clean.

## Suggested response

Edit `.github/workflows/sync-upstream.yml` — change the `permissions` block from:

```yaml
permissions:
  contents: write
```

to:

```yaml
permissions:
  contents: write
  workflows: write
```

Then either trigger a manual `workflow_dispatch` run to verify the fix, or wait for the next scheduled run at 07:17 UTC tomorrow.

> ⚠ If the fork's repository settings have "Allow GitHub Actions to create and approve pull requests" disabled, the `workflows` permission grant alone may not be sufficient — you may also need to enable that setting under **Settings → Actions → General → Workflow permissions**.

## Next action
- [ ] Add `workflows: write` to `.github/workflows/sync-upstream.yml` permissions block and push to `master` (or manually re-trigger the run after the fix lands).
