# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import subprocess

NOTICE_LINES = [
    "Copyright (c) Microsoft Corporation. All rights reserved.",
    "Licensed under the Apache 2.0 License.",
]

PREFIXES = [
    os.linesep.join([prefix + " " + line for line in NOTICE_LINES])
    for prefix in ["//", "--", "#"]
]
PREFIXES.append("#!/bin/bash" + os.linesep + PREFIXES[-1])


def has_notice(path):
    with open(path) as f:
        text = f.read()
        for prefix in PREFIXES:
            if text.startswith(prefix):
                return True
    return False


def is_src(name):
    for suffix in [".c", ".cpp", ".h", ".hpp", ".py", ".sh", ".lua"]:
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


if __name__ == "__main__":
    missing = []
    excluded = ["3rdparty", ".git"] + submodules()
    for root, dirs, files in os.walk("."):
        for edir in excluded:
            if edir in dirs:
                dirs.remove(edir)
        for name in files:
            if name.startswith("."):
                continue
            if is_src(name):
                path = os.path.join(root, name)
                if not has_notice(path):
                    missing.append(path)
    for path in missing:
        print("Copyright notice missing from {}".format(path))
    sys.exit(len(missing))
