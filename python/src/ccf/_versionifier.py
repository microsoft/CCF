# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import subprocess
from email.parser import Parser
from pathlib import Path

from packaging.version import (
    InvalidVersion,
    Version,
)


def _replace_char(s: str, n: int, c: str) -> str:
    return s[:n] + str(c) + s[n + 1 :]


def to_python_version(original: str) -> Version:
    """Convert a CCF release identifier into a Python package version."""
    unprefixed = original.removeprefix("ccf-")

    # Try to parse this as a Version (with automatic normalisation).
    # If it fails, try making part of the suffix a local version specifier (+foo).
    # Keep expanding this suffix until you get a valid version, or run out of attempts.
    next_attempt = unprefixed
    next_replace = len(next_attempt)
    plus_remover = str.maketrans({ord("+"): ""})
    while True:
        try:
            version = Version(next_attempt)
            return version
        except InvalidVersion:
            next_replace = unprefixed.rfind("-", 0, next_replace)
            if next_replace == -1:
                break
            # Remove any existing +s, and convert one - to a +
            next_attempt = _replace_char(
                unprefixed.translate(plus_remover), next_replace, "+"
            )

    raise ValueError(f"Cannot convert '{original}' to a Version")


_SDK_DIR = Path(__file__).resolve().parents[2]


def sdk_version(sdk_dir: Path = _SDK_DIR) -> str:
    """Resolve the SDK build version from the release job, Git, or a source archive."""
    if override := os.environ.get("CCF_PYTHON_PACKAGE_VERSION"):
        return str(Version(override))

    # A wheel built from an sdist must retain its recorded version without Git.
    pkg_info = sdk_dir / "PKG-INFO"
    if pkg_info.is_file():
        with pkg_info.open(encoding="utf-8") as metadata:
            version = Parser().parse(metadata, headersonly=True).get("Version")
            if not version:
                raise ValueError(f"Missing version in {pkg_info}")
            return str(Version(str(version)))

    if (sdk_dir.parent / ".git").exists():
        description = subprocess.check_output(
            ["git", "describe", "--tags", "--match=ccf-*", "--exclude=ccf-0.0.0*"],
            cwd=sdk_dir.parent,
            text=True,
        ).strip()
        return str(to_python_version(description))

    # git archive expands the description for source trees without .git.
    archival = sdk_dir / ".git_archival.txt"
    if archival.is_file():
        description = archival.read_text(encoding="utf-8").strip()
        if description.startswith("ccf-"):
            return str(to_python_version(description))
    raise ValueError(
        "Build from a CCF checkout with release tags, git archive or sdist"
    )


if __name__ == "__main__":
    # Run some tests that expected versions are correctly parsed
    v = to_python_version("1")
    assert v.release == (1,)

    v = to_python_version("1.2.3")
    assert v.release == (1, 2, 3)
    assert v == to_python_version("ccf-1.2.3")

    v = to_python_version("ccf-1.2.3")
    assert v.release == (1, 2, 3)
    assert v == to_python_version("ccf-1.2.3")

    v = to_python_version("ccf-1.2.3-a42")
    assert v.release == (1, 2, 3)
    assert v.pre == ("a", 42)
    assert v < to_python_version("ccf-1.2.3")  # -x precedes main release

    v = to_python_version("ccf-1.2.3-rc1")
    assert v.release == (1, 2, 3)
    assert v.pre == ("rc", 1)
    assert v < to_python_version("ccf-1.2.3")  # RC precedes main release

    v = to_python_version("ccf-1.2.3-dev2")
    assert v.release == (1, 2, 3)
    assert v.dev == 2
    assert v < to_python_version("ccf-1.2.3")  # dev precedes main release

    v = to_python_version("ccf-1.2.3-dev3-5-deadbeef")
    assert v.release == (1, 2, 3)
    assert v.dev == 3
    assert v.local == "5.deadbeef"
    assert v < to_python_version("ccf-1.2.3")  # dev precedes main release

    v = to_python_version("ccf-1.2.3-42-deadbeef")
    assert v.release == (1, 2, 3)
    assert v.post == 42
    assert v.local == "deadbeef"
    assert v > to_python_version("ccf-1.2.3")  # -N comes after main release

    v = to_python_version("ccf-2.0.0-rc4-26-g49d7b7941+unsafe")
    assert v.release == (2, 0, 0)
    assert v.pre == ("rc", 4)
    assert v.post == 26
    assert v.local == "g49d7b7941unsafe"
    assert v < to_python_version("ccf-2.0.0")  # RC precedes main release
