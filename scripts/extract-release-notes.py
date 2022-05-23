# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import re
import sys
import subprocess


def main():
    parser = argparse.ArgumentParser(
        description="Parses a CHANGELOG file and checks it meets some formatting expectations. "
        "Will also extract release notes for targeted versions."
    )
    parser.add_argument(
        "--target-version",
        help="Add a version string which must be present in the CHANGELOG",
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
        "-f",
        "--fix",
        help="Fix any automatically correctable errors",
        action="store_true",
    )
    args = parser.parse_args()

    if args.target_git_version:
        git_version = subprocess.run(
            ["git", "describe", "--tags"], capture_output=True, universal_newlines=True
        ).stdout.strip()
        git_version = git_version.replace("ccf-", "")
        args.target_version.append(git_version)

    version_header = re.compile(r"## \[(.+)\]")
    link_definition = re.compile(r"\[(.+)\]:")

    release_notes = {}
    links_found = []

    # Parse file, bucketing lines into each version's release notes
    current_release_notes = None
    with open(args.changelog) as f:
        while line := f.readline():
            if match := version_header.match(line):
                log_version = match.group(1)
                current_release_notes = []
                release_notes[log_version] = current_release_notes
            elif match := link_definition.match(line):
                link_version = match.group(1)
                links_found.append(link_version)
            else:
                if current_release_notes != None:
                    current_release_notes.append(line.strip())

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
        else:
            print("CHANGELOG is valid!")


if __name__ == "__main__":
    main()
