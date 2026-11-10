#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Checks that every built-in public:ccf.gov.* and public:ccf.internal.* map
defined in the C++ sources is documented in doc/audit/builtin_maps.rst, and
that every map documented there is still defined in the sources.

builtin_maps.rst documents maps under one section per prefix, titled for
example ``public:ccf.gov.`` (underlined with '-'), with one entry per map
titled by its name without that prefix, for example ``nodes.snp.host_data``
(underlined with '~').
"""

import argparse
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

SOURCE_DIRS = ["include", "src"]
SOURCE_SUFFIXES = {".h", ".hpp", ".cpp"}
# Unit tests may define maps which are not part of a real service
EXCLUDED_DIR_NAMES = {"test"}

DOC_PATH = "doc/audit/builtin_maps.rst"

MAP_NAME_RE = re.compile(r'"(public:ccf\.(?:gov|internal)\.[A-Za-z0-9_.]+)"')

RST_LITERAL_TITLE_RE = re.compile(r"^``([^`]+)``\s*$")
SECTION_UNDERLINE_RE = re.compile(r"^-{3,}\s*$")
ENTRY_UNDERLINE_RE = re.compile(r"^~{3,}\s*$")

# Maps which are intentionally not documented in builtin_maps.rst, mapped to
# the reason they are excluded.
UNDOCUMENTED_ALLOW_LIST: dict[str, str] = {}


def find_source_maps(root: Path) -> dict[str, set[Path]]:
    maps: dict[str, set[Path]] = {}
    for source_dir in SOURCE_DIRS:
        for path in sorted((root / source_dir).rglob("*")):
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            relative = path.relative_to(root)
            if EXCLUDED_DIR_NAMES.intersection(relative.parts):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in MAP_NAME_RE.finditer(text):
                maps.setdefault(match.group(1), set()).add(relative)
    return maps


def find_documented_maps(root: Path) -> tuple[dict[str, int], list[str]]:
    documented: dict[str, int] = {}
    errors: list[str] = []
    lines = (root / DOC_PATH).read_text(encoding="utf-8").splitlines()
    prefix = None
    for i, line in enumerate(lines[:-1]):
        title = RST_LITERAL_TITLE_RE.match(line)
        if title is None:
            continue
        underline = lines[i + 1]
        line_number = i + 1
        if SECTION_UNDERLINE_RE.match(underline):
            prefix = title.group(1)
        elif ENTRY_UNDERLINE_RE.match(underline):
            if prefix is None:
                errors.append(
                    f"{DOC_PATH}:{line_number}: map entry ``{title.group(1)}`` "
                    "is not under a ``public:ccf.<...>.`` section"
                )
                continue
            name = prefix + title.group(1)
            if name in documented:
                errors.append(
                    f"{DOC_PATH}:{line_number}: {name} is documented more than "
                    f"once (previously on line {documented[name]})"
                )
            documented[name] = line_number
    return documented, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT_DIR,
        help="Repository root (defaults to the parent of this script's directory)",
    )
    args = parser.parse_args()
    root: Path = args.root

    source_maps = find_source_maps(root)
    documented, errors = find_documented_maps(root)

    for name in sorted(source_maps):
        if name in documented or name in UNDOCUMENTED_ALLOW_LIST:
            continue
        defined_in = ", ".join(p.as_posix() for p in sorted(source_maps[name]))
        errors.append(
            f"{name} (defined in {defined_in}) is not documented in {DOC_PATH}"
        )

    for name in sorted(UNDOCUMENTED_ALLOW_LIST):
        if name in documented:
            errors.append(
                f"{name} is documented in {DOC_PATH}, so should be removed from "
                "UNDOCUMENTED_ALLOW_LIST"
            )
        if name not in source_maps:
            errors.append(
                f"{name} is no longer defined in the sources, so should be "
                "removed from UNDOCUMENTED_ALLOW_LIST"
            )

    for name, line_number in sorted(documented.items(), key=lambda kv: kv[1]):
        if name not in source_maps:
            errors.append(
                f"{DOC_PATH}:{line_number}: {name} is documented but not defined "
                f"in {' or '.join(SOURCE_DIRS)}"
            )

    if errors:
        for error in errors:
            print(error)
        print(
            f"Found {len(errors)} problem(s). Document each built-in map in "
            f"{DOC_PATH} under the section matching its prefix, or add it to "
            f"UNDOCUMENTED_ALLOW_LIST in {Path(__file__).name} with a reason."
        )
        return 1

    print(f"All {len(source_maps)} built-in maps are documented in {DOC_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
