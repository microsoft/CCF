#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import re
import subprocess
import sys
from pathlib import Path

import release_notes as fragments


def archive_section(changelog: str, version: str, notes: str) -> str:
    section = (
        f"## [{version}]\n\n"
        f"[{version}]: https://github.com/microsoft/CCF/releases/tag/ccf-{version}\n\n"
        f"{notes}\n\n"
    )
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\][^\n]*\n.*?(?=^## \[|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    if match := pattern.search(changelog):
        # Preserve other versions' link definitions if stored at the end.
        links = re.findall(r"^\[.+\]:.*$", match[0], re.MULTILINE)
        section += "".join(
            f"{link}\n" for link in links if not link.startswith(f"[{version}]:")
        )
        return changelog[: match.start()] + section + changelog[match.end() :]
    first_section = re.search(r"^## \[", changelog, re.MULTILINE)
    position = first_section.start() if first_section else len(changelog)
    return changelog[:position].rstrip() + "\n\n" + section + changelog[position:]


def main():
    parser = argparse.ArgumentParser(
        description="Archive release ranges in CHANGELOG.md and remove unchanged released fragments. "
        "Supply ranges oldest first; all inputs are checked before writing."
    )
    parser.add_argument(
        "ranges",
        nargs="+",
        metavar="PREVIOUS_TAG..RELEASE_TAG",
        help="Explicit release ranges, e.g. ccf-7.0.24..ccf-7.0.25.",
    )
    parser.add_argument(
        "--pr",
        action="append",
        default=[],
        metavar="FILENAME=NUMBER",
        help="Override PR lookup (for a single release range only).",
    )
    args = parser.parse_args()
    if args.pr and len(args.ranges) != 1:
        parser.error("--pr requires a single release range.")

    root = Path.cwd()
    changelog_path = root / "CHANGELOG.md"
    changelog = changelog_path.read_text(encoding="utf-8")
    cleanup: set[Path] = set()
    for release_range in args.ranges:
        previous, separator, tag = release_range.partition("..")
        if not separator or not previous or not tag.startswith("ccf-") or ".." in tag:
            parser.error(f"Invalid release range: {release_range!r}")
        fragments.git(root, "merge-base", "--is-ancestor", tag, "HEAD")
        version = tag.removeprefix("ccf-")
        notes = fragments.from_descriptions(
            root, version, args.pr, previous, absolute_links=False
        )
        changelog = archive_section(changelog, version, notes)
        for path in fragments.descriptions_in_range(root, previous, tag):
            current = root / path
            if not current.exists():
                continue
            released = subprocess.run(
                ["git", "show", f"{tag}:{path.as_posix()}"],
                cwd=root,
                check=True,
                capture_output=True,
            ).stdout
            if current.read_bytes() != released:
                raise ValueError(
                    f"{path}: differs from {tag}; preserve or move post-release edits "
                    "to a new fragment before consolidating."
                )
            cleanup.add(path)

    dirty = fragments.git(
        root, "status", "--porcelain", "--", "CHANGELOG.md", *map(str, cleanup)
    )
    if dirty:
        raise ValueError(
            f"Commit or stash changes to consolidation inputs first:\n{dirty}"
        )
    changelog_path.write_text(changelog.rstrip() + "\n", encoding="utf-8")
    for path in sorted(cleanup):
        (root / path).unlink()
    print(
        f"Archived {len(args.ranges)} release(s); removed {len(cleanup)} fragment(s)."
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        detail = (
            error.stderr.strip()
            if isinstance(error, subprocess.CalledProcessError)
            else str(error)
        )
        sys.exit(f"Error: {detail or str(error)}")
