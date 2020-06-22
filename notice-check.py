# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import subprocess

NOTICE_LINES_CCF = [
    "Copyright (c) Microsoft Corporation. All rights reserved.",
    "Licensed under the Apache 2.0 License.",
]

NOTICE_LINES_PBFT = [
    "Copyright (c) Microsoft Corporation.",
    "Copyright (c) 1999 Miguel Castro, Barbara Liskov.",
    "Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.",
    "Licensed under the MIT license.",
]

PREFIXES_CCF = [
    os.linesep.join([prefix + " " + line for line in NOTICE_LINES_CCF])
    for prefix in ["//", "--", "#"]
]
PREFIXES_CCF.append("#!/bin/bash" + os.linesep + PREFIXES_CCF[-1])
PREFIXES_CCF.append(os.linesep.join(["//" + " " + line for line in NOTICE_LINES_PBFT]))
PREFIXES_CCF.append(
    os.linesep.join(
        ["//" + " " + line for line in [NOTICE_LINES_PBFT[0], NOTICE_LINES_PBFT[3]]]
    )
)


def has_notice(path, prefixes):
    print(f"Reading {path}")
    with open(path) as f:
        text = f.read()
        for prefix in prefixes:
            if text.startswith(prefix):
                return True
    return False


def is_src(name):
    for suffix in [".c", ".cpp", ".h", ".hpp", ".py", ".sh", ".lua", ".cmake"]:
        if name.endswith(suffix):
            return True
    return False


def submodules():
    r = subprocess.run(["git", "submodule", "status"], capture_output=True, check=True)
    return [
        line.strip().split(" ")[1]
        for line in r.stdout.decode().split(os.linesep)
        if line
    ]


def check_ccf():
    missing = []
    excluded = ["3rdparty", ".git", "build"] + submodules()
    for root, dirs, files in os.walk("."):
        for edir in excluded:
            if edir in dirs:
                dirs.remove(edir)
        for name in files:
            if name.startswith("."):
                continue
            if is_src(name):
                path = os.path.join(root, name)
                if not has_notice(path, PREFIXES_CCF):
                    missing.append(path)
    return missing


if __name__ == "__main__":
    missing = []
    missing.extend(check_ccf())

    for path in missing:
        print(f"Copyright notice missing from {path}")
    sys.exit(len(missing))
