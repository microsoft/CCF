#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/src"))
from ccf._versionifier import to_python_version


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print the Python package version for a CCF release tag."
    )
    parser.add_argument(
        "tag", help="CCF release tag, optionally prefixed with refs/tags/."
    )
    args = parser.parse_args()

    tag = args.tag.removeprefix("refs/tags/")
    if not tag.startswith("ccf-"):
        parser.error(f"Expected a ccf-* release tag, got {tag}")
    version = to_python_version(tag)
    if version.local is not None:
        parser.error(f"PyPI does not accept local versions: {version}")
    print(version)


if __name__ == "__main__":
    main()
