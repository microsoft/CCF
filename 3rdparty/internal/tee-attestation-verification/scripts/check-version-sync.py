#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import argparse
import glob
import pathlib
import re
import sys
import tomllib
from collections.abc import Iterator
from typing import Any


VERSION_HEADING = re.compile(
    r"^##\s+\[?v?(\d+\.\d+\.\d+(?:[-+][^\]\s]+)?)\]?",
    re.MULTILINE,
)


class VersionSyncError(Exception):
    """Expected validation failure for the version-sync check."""


def latest_changelog_version(root : pathlib.Path) -> str:
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    latest = VERSION_HEADING.search(changelog)
    if latest is None:
        raise VersionSyncError(
            "Could not find a version heading like '## [1.2.3]' in CHANGELOG.md"
        )
    return latest.group(1)

def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise VersionSyncError(f"Failed to parse {path}: {error}") from error

def workspace_manifest_paths_with_package(root: pathlib.Path) -> list[pathlib.Path]:
    workspace_manifest = root / "Cargo.toml"
    workspace = load_toml(workspace_manifest)
    workspace_members = workspace.get("workspace", {}).get("members")
    if not isinstance(workspace_members, list):
        raise VersionSyncError("Cargo.toml must define [workspace].members")

    manifest_paths = []

    if "package" in workspace:
        manifest_paths.append(workspace_manifest)

    for member in workspace_members:
        matches = glob.glob(str(root / member))
        if not matches:
            raise VersionSyncError(f"Workspace member pattern matched nothing: {member}")
        manifest_paths.extend(pathlib.Path(match) / "Cargo.toml" for match in matches)

    return sorted(set(manifest_paths))

def dependency_sections(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield section, data.get(section, {})

    for target_name, target in data.get("target", {}).items():
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield f"target.{target_name}.{section}", target.get(section, {})


def check_version_sync(root: pathlib.Path) -> None:
    changelog_version = latest_changelog_version(root)

    # First check that all packages define the same version
    packages = set()
    for manifest in workspace_manifest_paths_with_package(root):
        if not manifest.is_file():
            raise VersionSyncError(f"Expected Cargo.toml file not found: {manifest}")
        manifest_data = load_toml(manifest)
        version = manifest_data.get("package", {}).get("version", None)
        if version is None:
            raise VersionSyncError(f"{manifest}: [package] section must define a version")

        if version != changelog_version:
            raise VersionSyncError(
                f"{manifest}: package version {version} does not match "
                f"CHANGELOG.md latest version {changelog_version}"
            )

        package = manifest_data.get("package", {}).get("name", None)
        if package is None:
            raise VersionSyncError(f"{manifest}: [package] section must define a name")
        packages.add(package)

    # Check that all internal dependencies point to the same version as well
    for manifest in workspace_manifest_paths_with_package(root):
        manifest_data = load_toml(manifest)
        for section, dependencies in dependency_sections(manifest_data):
            for alias, spec in dependencies.items():
                if isinstance(spec, str):
                    package_name = alias
                    actual_version = spec
                elif isinstance(spec, dict):
                    package_name = spec.get("package", alias)
                    actual_version = spec.get("version")
                else:
                    continue

                if package_name in packages and actual_version != changelog_version:
                    raise VersionSyncError(
                        f"{manifest}: {section}.{alias} points at internal package {package_name} "
                        f"but version is {actual_version!r}; expected {changelog_version!r}"
                    )
    print(f"All Cargo package versions and internal dependency versions match {changelog_version}")


def main() -> int:
    argparser = argparse.ArgumentParser(description="Check that package versions match")

    argparser.add_argument(
        "--root-path",
        default = pathlib.Path.cwd(), # Use cwd
        help = "Path to the root of the repository (default: current working directory)",
        type = pathlib.Path,
    )

    args = argparser.parse_args()

    try:
        check_version_sync(args.root_path)
    except VersionSyncError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
