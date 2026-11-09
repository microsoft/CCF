#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Checks tracked documentation sources (doc/**/*.rst) for outdated terminology.

CCF no longer has a separate enclave and host, so new uses of "enclave" (in
any case) are reported. Remaining legitimate uses are listed explicitly in
ALLOW_LIST, each scoped to a single file and pattern, with a reason.
Generated schemas under doc/schemas and doc/host_config_schema are not checked.
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

DOC_GLOB = "doc/*.rst"
EXCLUDED_PREFIXES = ("doc/schemas/", "doc/host_config_schema/")


@dataclass(frozen=True)
class Term:
    pattern: re.Pattern[str]
    advice: str


TERMS = [
    Term(
        re.compile(r"enclave", re.IGNORECASE),
        "CCF no longer has a separate enclave and host; refer to the CCF node "
        "or the TEE instead",
    ),
]


@dataclass(frozen=True)
class Allowed:
    path: str
    pattern: re.Pattern[str]
    reason: str


# Matches of each pattern are removed from lines of the given file before terms
# are searched for, so other uses on the same line are still reported.
ALLOW_LIST = [
    Allowed(
        "doc/audit/builtin_maps.rst",
        re.compile(r"\bMRENCLAVE\b"),
        "Name of the SGX code measurement, which older ledgers may still contain",
    ),
    Allowed(
        "doc/overview/glossary.rst",
        re.compile(r"^  Enclave$"),
        "Glossary entry explaining the historical term",
    ),
    Allowed(
        "doc/overview/glossary.rst",
        re.compile(r"\ban SGX enclave\b"),
        "Glossary definition of the historical term",
    ),
]


def tracked_documentation_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", DOC_GLOB],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return sorted(
        name
        for name in result.stdout.decode().split("\0")
        if name and not name.startswith(EXCLUDED_PREFIXES)
    )


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

    errors: list[str] = []
    used: set[int] = set()
    paths = tracked_documentation_files(root)

    for path in paths:
        allowed = [(i, a) for i, a in enumerate(ALLOW_LIST) if a.path == path]
        lines = (root / path).read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, start=1):
            remaining = line
            for i, allow in allowed:
                remaining, count = allow.pattern.subn("", remaining)
                if count:
                    used.add(i)
            for term in TERMS:
                match = term.pattern.search(remaining)
                if match:
                    errors.append(
                        f'{path}:{line_number}: "{match.group(0)}": {term.advice}'
                    )

    for i, allow in enumerate(ALLOW_LIST):
        if i not in used:
            errors.append(
                f"ALLOW_LIST entry for {allow.path} ({allow.pattern.pattern!r}) no "
                "longer matches anything, so should be removed"
            )

    if errors:
        for error in errors:
            print(error)
        print(
            f"Found {len(errors)} problem(s). Reword the documentation, or add a "
            f"narrow entry to ALLOW_LIST in {Path(__file__).name} with a reason."
        )
        return 1

    print(f"No outdated terminology found in {len(paths)} documentation files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
