#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Check cherry-pick commits in a pull request to a release/N.x branch.

Every commit with a `(cherry picked from commit ...)` line must be an
unchanged, single-parent, clean `git cherry-pick` of a commit merged to main
since the release branched. Malformed or duplicate cherry-pick lines fail.
All other commits (fixups, merge commits such as GitHub's "Update branch", or
PRs with no cherry-picks) pass and are left to normal review. Uses only git,
not the GitHub API.
"""

import argparse
import re
import subprocess
import sys

CHERRY_PICKED = re.compile(
    r"^\(cherry picked from commit ([0-9a-f]{40})\)$", re.MULTILINE
)
CHERRY_PICKED_LOOSE = re.compile(
    r"^\s*\(\s*cherry[\W_]*picked\b", re.IGNORECASE | re.MULTILINE
)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "log.showSignature=false", *args],
        check=check,
        capture_output=True,
        text=True,
        errors="replace",
    )


def is_clean_pick(source: str, commit: str) -> bool:
    # Replays source onto commit's parent as `git cherry-pick` does; a clean
    # pick produces commit's tree exactly.
    replay = git(
        "merge-tree",
        "--write-tree",
        f"--merge-base={source}^",
        f"{commit}^",
        source,
        check=False,
    )
    if replay.returncode > 1:
        replay.check_returncode()
    tree = git("rev-parse", f"{commit}^{{tree}}").stdout.strip()
    return replay.returncode == 0 and replay.stdout.split()[0] == tree


def check(base: str, head: str, main: str) -> list[str]:
    # Non-merge commits landed on main since the release branched.
    merged = git("rev-list", "--first-parent", "--no-merges", main, f"^{base}")
    mainline = set(merged.stdout.split())
    errors = []
    for line in git(
        "rev-list", "--reverse", "--parents", f"{base}..{head}"
    ).stdout.splitlines():
        commit, *parents = line.split()
        message = git("log", "-1", "--format=%B", commit).stdout
        sources = CHERRY_PICKED.findall(message)
        if len(sources) > 1 or len(sources) != len(
            CHERRY_PICKED_LOOSE.findall(message)
        ):
            errors.append(
                f"{commit} has a malformed or extra cherry-pick line; use "
                "`git cherry-pick -x` once per commit"
            )
            continue
        if not sources:
            continue
        if len(parents) != 1:
            errors.append(
                f"{commit} is not a single-parent commit and cannot be a "
                "cherry-pick; keep cherry-picks as standalone commits"
            )
            continue
        source = sources[0]
        if source not in mainline:
            errors.append(
                f"{source} is not a squash merge to {main} since {base} "
                "branched; cherry-pick the commit that its PR merged to main"
            )
            continue
        if not is_clean_pick(source, commit):
            subject = git("log", "-1", "--format=%s", source).stdout.strip()
            errors.append(
                f"The cherry-pick of {source} ({subject!r}) differs from a clean "
                "cherry-pick; keep cherry-picks unchanged and put changes in "
                "separate fixup commits"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="e.g. origin/release/7.x")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--main", default="origin/main")
    args = parser.parse_args()
    try:
        errors = check(args.base, args.head, args.main)
    except subprocess.CalledProcessError as error:
        errors = [f"`{' '.join(error.cmd)}` failed: {error.stderr.strip()}"]
    for message in errors:
        print(f"error: {message}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
