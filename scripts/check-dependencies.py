# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import subprocess
import re


LOCAL_INCLUDE = re.compile(r"#include \"([^/\"]*)\"")


def canonicalise_includes(path):
    rel_path = os.path.dirname(path)
    original = open(path).read()
    (fixed, corrections) = LOCAL_INCLUDE.subn(f'#include "{rel_path}/\g<1>"', original)

    if corrections > 0:
        with open(path, "w") as f:
            f.write(fixed)
            return True

    return False


def run(files):
    includes_changed = []
    for path in files:
        if canonicalise_includes(path):
            includes_changed.append(path)

    if len(includes_changed) == 0:
        print("All files contain canonical includes")
    else:
        print("Canonicalised include paths in the following files:")
        for path in includes_changed:
            print(f"  {path}")


if __name__ == "__main__":
    files = sys.argv[1:]
    run(files)
