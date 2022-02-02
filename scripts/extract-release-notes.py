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

    release_notes = ""
    found_version = False
    with open("CHANGELOG.md") as f:
        while line := f.readline():
            if match := version_header.match(line):
                if found_version:
                    # Next version starts, we're done.
                    break
                log_version = match.group(1)
                if log_version == git_version:
                    found_version = True
            else:
                if found_version:
                    release_notes += line
    if not found_version:
        raise RuntimeError(f"git version {git_version} not found in CHANGELOG.md")

    release_notes = release_notes.strip()
    print(release_notes)


if __name__ == "__main__":
    main()
