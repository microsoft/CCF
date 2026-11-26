#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import subprocess

NOTICE_LINES_CCF = [
    "Copyright (c) Microsoft Corporation. All rights reserved.",
    "Licensed under the Apache 2.0 License.",
]

SLASH_PREFIXED = os.linesep.join(["// " + line for line in NOTICE_LINES_CCF])
HASH_PREFIXED = os.linesep.join(["# " + line for line in NOTICE_LINES_CCF])
PYTHON_SHEBANG = "#!/usr/bin/env python3"

# Must have a '#pragma once' line
HEADERS_WITH_PRAGMAS = [
    SLASH_PREFIXED + os.linesep + "#pragma once",
    # Maybe there's a single blank line
    SLASH_PREFIXED + os.linesep + os.linesep + "#pragma once",
]

PREFIX_BY_FILETYPE = {
    ".c": [SLASH_PREFIXED],
    ".cpp": [SLASH_PREFIXED],
    ".h": HEADERS_WITH_PRAGMAS,
    ".hpp": HEADERS_WITH_PRAGMAS,
    ".py": [
        HASH_PREFIXED,
        # May have a shebang before the license
        PYTHON_SHEBANG + os.linesep + HASH_PREFIXED,
    ],
    ".sh": [
        HASH_PREFIXED,
        # May have a shebang before the license
        "#!/bin/bash" + os.linesep + HASH_PREFIXED,
    ],
    ".cmake": [HASH_PREFIXED],
}


def has_notice(path, prefixes):
    with open(path) as f:
        text = f.read()
        for prefix in prefixes:
            if text.startswith(prefix):
                return True
    return False


def check_python_shebang(path):
    is_executable = os.access(path, os.X_OK)
    with open(path) as f:
        first_line = f.readline().removesuffix("\n")
    has_shebang = first_line.startswith("#!")
    errors = []
    if is_executable and first_line != PYTHON_SHEBANG:
        errors.append(
            f"{path}: executable Python file must start with '{PYTHON_SHEBANG}'"
        )
    elif has_shebang and not is_executable:
        errors.append(f"{path}: has shebang but is not executable (run chmod +x)")
    return errors


def submodules():
    r = subprocess.run(["git", "submodule", "status"], capture_output=True, check=True)
    return [
        line.strip().split(" ")[1]
        for line in r.stdout.decode().split(os.linesep)
        if line
    ]


EXCLUDED = ["3rdparty", ".git", "build", "env"] + submodules()


def list_files(suffix):
    cmd = f"git ls-files | grep -E -v \"{'|'.join('^' + prefix for prefix in EXCLUDED)}\" | grep -e '\\{suffix}$'"
    r = subprocess.run(
        cmd,
        capture_output=True,
        shell=True,
    )
    return r.stdout.decode().splitlines()


def check_ccf():
    missing = []
    shebang_errors = []
    count = 0
    for file_suffix, notice_lines in PREFIX_BY_FILETYPE.items():
        for path in list_files(file_suffix):
            # git ls-files returns moved/deleted files - ignore those
            if os.path.isfile(path):
                count += 1
                if not has_notice(path, notice_lines):
                    missing.append(path)
                if file_suffix == ".py":
                    shebang_errors.extend(check_python_shebang(path))
    return missing, shebang_errors, count


if __name__ == "__main__":
    missing, shebang_errors, count = check_ccf()
    print(f"Checked {count} files for copyright notices.")

    for path in missing:
        print(f"Copyright notice missing from {path}")
    for err in shebang_errors:
        print(err)
    sys.exit(len(missing) + len(shebang_errors))
