# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import re
import subprocess


def main():
    git_version = subprocess.run(
        ["git", "describe", "--tags"], capture_output=True, universal_newlines=True
    ).stdout.strip()
    git_version = git_version.replace("ccf-", "")

    version_header = re.compile(r"## \[(.+)\]")
    link_definition = re.compile(r"\[(.+)\]:")

    release_notes = ""

    # Look for version_header line
    found_version = False
    found_version_end = False
    found_link = False
    with open("CHANGELOG.md") as f:
        while line := f.readline():
            if match := version_header.match(line):
                if found_version:
                    found_version_end = True
                    if found_link:
                        break
                log_version = match.group(1)
                if log_version == git_version:
                    found_version = True
            elif match := link_definition.match(line):
                link_version = match.group(1)
                if link_version == git_version:
                    found_link = True
                    if found_version and found_version_end:
                        break
            else:
                if found_version and not found_version_end:
                    release_notes += line

    if not found_version:
        raise RuntimeError(f"git version {git_version} not found in CHANGELOG.md")

    if not found_link:
        expected_line = f"[{git_version}]: https://github.com/microsoft/CCF/releases/tag/ccf-{git_version}"
        raise RuntimeError(
            f"Link to release for git version {git_version} not found in CHANGELOG.md. Add a link definition like:\n{expected_line}"
        )

    release_notes = release_notes.strip()
    print(release_notes)


if __name__ == "__main__":
    main()
