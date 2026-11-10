# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import re
import subprocess
import textwrap
from pathlib import Path
from urllib.parse import urljoin, urlparse

CATEGORIES = (
    "added",
    "changed",
    "deprecated",
    "removed",
    "fixed",
    "security",
    "dependencies",
)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def category_for(path: Path) -> str:
    name, _, category = path.stem.rpartition(".")
    if (
        path.parent != Path(".changes")
        or path.suffix != ".md"
        or not name
        or category not in CATEGORIES
    ):
        raise ValueError(f"{path}: expected .changes/<name>.<category>.md")
    return category


def check_descriptions(root: Path) -> None:
    for path in sorted((root / ".changes").glob("*.md")):
        category_for(path.relative_to(root))
        if not path.read_text(encoding="utf-8").strip():
            raise ValueError(f"Empty change description: {path.name}")


def parse_changelog(content: str) -> tuple[dict[str, list[str]], list[str]]:
    version_header = re.compile(r"## \[(.+)\]")
    link_definition = re.compile(r"\[(.+)\]:")
    notes: dict[str, list[str]] = {}
    links = []
    current = None
    for line in content.splitlines():
        if match := version_header.match(line):
            current = []
            notes[match[1]] = current
        elif match := link_definition.match(line):
            links.append(match[1])
        elif current is not None:
            current.append(line.rstrip())
    return notes, links


def previous_tag(root: Path, tag: str) -> str:
    return git(root, "describe", "--tags", "--match", "ccf-*", f"{tag}^", "--abbrev=0")


def describe_path_changes(root: Path, tag: str, previous: str, path: str) -> str:
    if git(root, "diff", "--name-only", previous, tag, "--", path):
        return (
            f"\n\n- **Note**: This release includes changes to `{path}`, which may be viewed "
            f"[here](https://github.com/microsoft/CCF/compare/{previous}...{tag}#files_bucket)"
        )
    return ""


def release_links(text: str, tag: str) -> str:
    def replace(match: re.Match[str]) -> str:
        target = match[2]
        parsed = urlparse(target)
        if parsed.scheme or parsed.netloc or target.startswith(("#", "/")):
            return match[0]
        return match[1] + urljoin(
            f"https://github.com/microsoft/CCF/blob/{tag}/", target
        )

    return re.sub(r"(\]\()([^\s)]+)", replace, text)


def from_descriptions(
    root: Path,
    version: str,
    pr_overrides: list[str] | None = None,
) -> str:
    tag = f"ccf-{version}"
    paths = [
        Path(path)
        for path in git(
            root, "ls-tree", "-r", "--name-only", tag, "--", ".changes"
        ).splitlines()
        if path.endswith(".md")
    ]
    overrides = {}
    names = {path.name for path in paths}
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

    entries: dict[str, list[str]] = {category: [] for category in CATEGORIES}
    changelog_notes, _ = parse_changelog(git(root, "show", f"{tag}:CHANGELOG.md"))
    uncategorized = []
    current_category = None
    category_lines: dict[str, list[str]] = {category: [] for category in CATEGORIES}
    for line in changelog_notes.get(version, []):
        heading = re.fullmatch(r"### (\w+)", line)
        if heading and heading[1].lower() in CATEGORIES:
            current_category = heading[1].lower()
        elif current_category is not None:
            category_lines[current_category].append(line)
        else:
            uncategorized.append(line)
    for category, lines in category_lines.items():
        text = "\n".join(lines).strip()
        if text:
            entries[category].append(release_links(text, tag))

    for path in sorted(paths):
        category = category_for(path)
        text = git(root, "show", f"{tag}:{path.as_posix()}")
        if not text:
            raise ValueError(f"Empty change description: {path.name}")
        text = release_links(text, tag)
        number = overrides.get(path.name)
        if number is None:
            subject = git(
                root,
                "log",
                "-1",
                "--format=%s",
                "--diff-filter=A",
                "--no-renames",
                tag,
                "--",
                path.as_posix(),
            )
            reference = re.search(r"\(#([1-9][0-9]*)\)$", subject)
            if reference is None:
                raise ValueError(
                    f"{path}: adding commit has no trailing PR reference: {subject!r}. "
                    f"Use --pr {path.name}=NUMBER."
                )
            number = int(reference[1])
        entries[category].append(f"- {textwrap.indent(text, '  ')[2:]} (#{number})")

    lines = [release_links("\n".join(uncategorized).strip(), tag)]
    for category, notes in entries.items():
        if notes:
            lines.extend([f"### {category.title()}", "", *notes, ""])
    if not paths and not any(entries.values()) and not any(uncategorized):
        lines.append("No significant changes.")
    return "\n".join(lines).strip()
