#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import sys
import tomllib
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/src"))
from ccf._versionifier import to_python_version


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check SDK metadata against a release tag and print its Python version."
    )
    parser.add_argument(
        "tag", help="CCF release tag, optionally prefixed with refs/tags/."
    )
    args = parser.parse_args()

    tag = args.tag.removeprefix("refs/tags/")
    expected_version = to_python_version(tag)
    with open(ROOT / "python/pyproject.toml", "rb") as project:
        package_version = Version(tomllib.load(project)["project"]["version"])
    if package_version != expected_version:
        sys.exit(
            f"Release tag {tag} expects SDK version {expected_version}, "
            f"but python/pyproject.toml contains {package_version}"
        )
    print(expected_version)


if __name__ == "__main__":
    main()
