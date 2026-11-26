---
name: backporting
user-invocable: false
description: "Backport merged PRs from main to a release/N.x LTS branch. Covers labels, easy-to-review cherry-pick and fixup commit structure, and the Backport checks workflow."
---

# Backporting

Use this skill to prepare or update a PR that targets a `release/N.x` branch.
The [release process](../../../doc/contribute/release_ccf.rst) defines the policy.
The "Backport checks" workflow (`.github/workflows/backport-checks.yml`) runs `scripts/backport.py` on every PR into `release/**`.
It verifies that every commit with a `(cherry picked from commit ...)` line is an exact, unchanged `git cherry-pick` of a commit merged to `main` since the release branched, so reviewers do not need to re-review the cherry-picks and only need to review any fixup commits.

## Structure for reviewability

- Backport only PRs that have merged to `main`. Cherry-pick the commit that the PR's squash merge created on `main`, never the PR's own head commits.
- Keep the PR easy to review by separating unchanged cherry-picks from release-specific changes:
  1. Put `git cherry-pick -x <commit on main>` commits first, unchanged and in `main` merge order, one per backported PR.
  2. Put anything needed to adapt, build, or test the change on `release/N.x` in small, separate fixup commits without a `(cherry picked from commit ...)` line.
  Place a fixup before or between cherry-picks only when needed (for example, a prep fixup or manual conflict port so a later commit cherry-picks cleanly).
- Never edit a cherry-pick commit. CI replays each cherry-pick onto its parent commit and fails if the result differs in any way.
- If a commit does not cherry-pick cleanly, run `git cherry-pick --abort` and port it as a fixup commit instead (later commits that apply cleanly on top can still be cherry-picked with `-x`). Name the original commit and PR in each message, and say in the PR description that these ports need a full review.
- Prefer rebasing onto `release/N.x` when updating the branch locally so the commit list stays easy to review.
- Label the original PR `N.x-todo` and the backport PR `N.x-backport`. CI does not check labels; the releaser scans for `N.x-todo`.
- Title the PR as the release process describes, and link each original PR in the description.
- Verify locally with `scripts/backport.py --base origin/release/N.x` before pushing.
