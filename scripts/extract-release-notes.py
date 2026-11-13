#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import sys
import subprocess
from pathlib import Path

import release_notes as fragments


def main():
    parser = argparse.ArgumentParser(
        description="Validate the historical CHANGELOG or extract release notes for targeted versions. "
        "Use --from-changes to generate notes directly from tagged change descriptions."
    )
    parser.add_argument(
        "--target-version",
        help="Release version without 'ccf-'; must be in CHANGELOG unless --from-changes is used",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--target-git-version",
        help="Derive target version from current git version",
        action="store_true",
    )
    parser.add_argument(
        "--changelog", help="Path to CHANGELOG file to parse", default="CHANGELOG.md"
    )
    parser.add_argument(
        "--from-changes",
        help="Generate notes from descriptions added since the previous release tag.",
        action="store_true",
    )
    parser.add_argument(
        "--previous-tag",
        help="Explicit range start for --from-changes (default: nearest ancestor ccf-* tag).",
    )
    parser.add_argument(
        "--pr",
        action="append",
        default=[],
        metavar="FILENAME=NUMBER",
        help="Override a change description's PR lookup.",
    )
    parser.add_argument(
        "-f",
        "--fix",
        help="Fix any automatically correctable errors",
        action="store_true",
    )
    parser.add_argument(
        "--describe-path-changes",
        help="If true, add a note whenever the given path has changes between releases.",
        action="append",
        default=[],
    )
    args = parser.parse_args()
    root = Path.cwd()

    if args.pr and not args.from_changes:
        parser.error("--pr requires --from-changes.")
    if args.previous_tag and not args.from_changes:
        parser.error("--previous-tag requires --from-changes.")
    if args.from_changes and args.fix:
        parser.error("--from-changes cannot be combined with --fix.")

    if args.target_git_version:
        git_version = fragments.git(
            root, "describe", "--tags", "--exact-match", "--match", "ccf-*"
        )
        git_version = git_version.removeprefix("ccf-")
        args.target_version.append(git_version)

    if args.from_changes:
        if len(args.target_version) != 1:
            parser.error("--from-changes requires exactly one target version.")
        version = args.target_version[0]
        tag = f"ccf-{version}"
        previous = args.previous_tag or fragments.previous_tag(root, tag)
        notes = fragments.from_descriptions(root, version, args.pr, previous)
        if args.describe_path_changes:
            for path in args.describe_path_changes:
                notes += fragments.describe_path_changes(root, tag, previous, path)
        print(notes)
        return

    fragments.check_descriptions(root)

    with open(args.changelog) as f:
        release_notes, links_found = fragments.parse_changelog(f.read())

    documented_versions = set(release_notes.keys())

    # Check that each version has a link
    versions_without_links = documented_versions - set(links_found)
    if len(versions_without_links) > 0:
        print("Missing links for following versions:")
        for version in versions_without_links:
            print(f"  {version}")

    # Check that each target version is present
    missing_target_versions = set(args.target_version) - documented_versions
    if len(missing_target_versions) > 0:
        print("Missing required versions:")
        for version in missing_target_versions:
            print(f"  {version}")

    # If there were any problems, try to fix them and exit
    if len(versions_without_links) > 0 or len(missing_target_versions) > 0:
        if args.fix:
            with open(args.changelog, "a") as f:
                for version in versions_without_links:
                    # Append presumed link
                    f.write(
                        f"[{version}]: https://github.com/microsoft/CCF/releases/tag/ccf-{version}\n"
                    )
        sys.exit(1)
    else:
        # File is valid.
        if len(args.target_version) > 0:
            # Print release notes for each target version.
            # If multiple versions are requested, delimit and prefix each.
            multiple = len(args.target_version) > 1
            for i, version in enumerate(args.target_version):
                if multiple:
                    if i > 0:
                        print("\n" + "-" * 80 + "\n")
                    print(f"# {version}")
                print("\n".join(release_notes[version]).strip())

                for path in args.describe_path_changes:
                    git_version = f"ccf-{version}"
                    prev_version = subprocess.run(
                        ["git", "describe", "--tags", f"{git_version}^", "--abbrev=0"],
                        capture_output=True,
                        universal_newlines=True,
                    ).stdout.strip()
                    diff = subprocess.run(
                        [
                            "git",
                            "diff",
                            "--exit-code",
                            prev_version,
                            git_version,
                            "--",
                            path,
                        ],
                        capture_output=True,
                        universal_newlines=True,
                    )
                    if diff.returncode == 1:
                        # Insert a hyperlink to a GitHub compare page.
                        # This shows all changes between tags, not localised to the path, but seems to be the best we can do automatically.
                        print(
                            f"\n- **Note**: This release include changes to `{path}`, which may be viewed [here](https://github.com/Microsoft/CCF/compare/{prev_version}...{git_version}#files_bucket)"
                        )

        else:
            print("CHANGELOG is valid!")


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
