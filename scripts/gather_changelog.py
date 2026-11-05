#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import os
import re
import textwrap
from pathlib import Path

from github import Auth, Github, GithubException
from github.Repository import Repository

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "microsoft/CCF"
CATEGORIES = (
    "added",
    "changed",
    "deprecated",
    "removed",
    "fixed",
    "security",
    "dependencies",
)


def change_descriptions(
    root: Path, selected: list[Path] | None = None
) -> dict[Path, tuple[str, str]]:
    directory = root / ".changes"
    paths = selected if selected is not None else directory.glob("*.md")
    pending = {}
    for path in sorted(set(paths)):
        path = (root / path).resolve()
        name, _, category = path.stem.rpartition(".")
        if (
            path.parent != directory
            or path.suffix != ".md"
            or not name
            or category not in CATEGORIES
        ):
            raise ValueError(f"{path}: expected .changes/<name>.<category>.md")
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            raise ValueError(f"Empty change description: {path.name}")
        pending[path] = (category, text)
    return pending


def resolve_pr(repository: Repository, path: str, base_branch: str) -> int:
    # Find the latest addition, not later edits or previous uses of this name.
    commit = next(
        (
            commit
            for commit in repository.get_commits(sha=base_branch, path=path)
            if any(
                file.filename == path and file.status == "added"
                for file in commit.files
            )
        ),
        None,
    )
    if commit is None:
        raise ValueError(f"No GitHub addition for {path} on {base_branch}; use --pr.")
    candidates = {
        pr.number
        for pr in commit.get_pulls()
        if pr.merged_at is not None
        and pr.base.ref == base_branch
        and pr.base.repo.full_name.lower() == REPOSITORY.lower()
    }
    if len(candidates) != 1:
        raise ValueError(
            f"{path}: expected one merged PR targeting {base_branch}, "
            f"found {sorted(candidates)}. Use --pr {Path(path).name}=NUMBER."
        )
    return candidates.pop()


def gather(
    root: Path,
    version: str,
    base_branch: str,
    selected: list[Path] | None = None,
    pr_overrides: list[str] | None = None,
    write: bool = False,
) -> str:
    pending = change_descriptions(root, selected)
    overrides = {}
    names = {path.name for path in pending}
    for value in pr_overrides or []:
        name, _, number = value.partition("=")
        if (
            name not in names
            or not number.isdecimal()
            or int(number) < 1
            or name in overrides
        ):
            raise ValueError(
                f"Invalid --pr {value!r}; use a selected FILENAME=NUMBER once."
            )
        overrides[name] = int(number)

    changelog = root / "CHANGELOG.md"
    content = changelog.read_text(encoding="utf-8")
    entries: dict[str, list[str]] = {category: [] for category in CATEGORIES}
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    with Github(auth=Auth.Token(token) if token else None, lazy=True) as github:
        repository = github.get_repo(REPOSITORY)
        for path, (category, text) in pending.items():
            number = (
                overrides[path.name]
                if path.name in overrides
                else resolve_pr(
                    repository, path.relative_to(root).as_posix(), base_branch
                )
            )
            entries[category].append(f"- {textwrap.indent(text, '  ')[2:]} (#{number})")
    lines = [
        f"## [{version}]",
        "",
        f"[{version}]: https://github.com/{REPOSITORY}/releases/tag/ccf-{version}",
        "",
    ]
    for category, notes in entries.items():
        if notes:
            lines.extend([f"### {category.title()}", "", *notes, ""])
    if not pending:
        lines.extend(["No significant changes.", ""])
    section = "\n".join(lines) + "\n"
    if write:
        first_release = re.search(r"^## \[", content, re.MULTILINE)
        index = first_release.start() if first_release else len(content)
        preamble = content[:index] if first_release else content.rstrip() + "\n\n"
        changelog.write_text(preamble + section + content[index:], encoding="utf-8")
        for path in pending:
            path.unlink()
    return section


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect CCF change descriptions; preview by default."
    )
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="Selected .changes/*.md files; defaults to all.",
    )
    parser.add_argument("--version", help="Release version, without 'ccf-'.")
    parser.add_argument("--base-branch", help="Branch targeted by the introducing PRs.")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Prepend the notes and delete selected change descriptions.",
    )
    parser.add_argument(
        "--pr",
        action="append",
        default=[],
        metavar="FILENAME=NUMBER",
        help="Override a selected change description's PR lookup.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check change description names and contents without GitHub access.",
    )
    args = parser.parse_args()
    try:
        if args.check:
            if args.version or args.base_branch or args.write or args.pr:
                parser.error("--check cannot be combined with release options.")
            print(
                f"Validated {len(change_descriptions(ROOT, args.files or None))} change description(s)."
            )
        else:
            if not args.version or not args.base_branch:
                parser.error(
                    "--version and --base-branch are required to collect notes."
                )
            print(
                gather(
                    ROOT,
                    args.version,
                    args.base_branch,
                    args.files or None,
                    args.pr,
                    args.write,
                ),
                end="",
            )
    except (ValueError, OSError, GithubException) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
