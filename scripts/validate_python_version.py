#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/src"))
from ccf._versionifier import to_python_version


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print the Python package version for a release tag or the current checkout."
    )
    parser.add_argument(
        "tag",
        nargs="?",
        help="Explicit PyPI release tag, optionally prefixed with refs/tags/.",
    )
    args = parser.parse_args()

    if args.tag is not None:
        tag = args.tag.removeprefix("refs/tags/")
    else:
        tag = subprocess.check_output(
            ["git", "describe", "--tags", "--match=ccf-*", "--exclude=ccf-0.0.0*"],
            text=True,
        ).strip()

    if not tag.startswith("ccf-"):
        parser.error(f"Expected a ccf-* release tag, got {tag}")
    version = to_python_version(tag)
    if args.tag is not None and version.local is not None:
        parser.error(f"PyPI does not accept local versions: {version}")
    print(version)


if __name__ == "__main__":
    main()
