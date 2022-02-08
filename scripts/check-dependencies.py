# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
from collections import defaultdict
import re


LOCAL_INCLUDE = re.compile(r"#include \"([^/\"]*)\"")
INCLUDE_DEPS = re.compile(r"#include \"(.*)/.*\.h\"")


def root_component(path):
    return path.split("/")[0]


def get_include_dependencies(path, canonicalise_includes=False):
    rel_path = os.path.dirname(path).replace("src/", "")
    contents = open(path).read()

    if canonicalise_includes:
        (contents, corrections) = LOCAL_INCLUDE.subn(
            f'#include "{rel_path}/\g<1>"', contents
        )

        if corrections > 0:
            print(f"Canonicalised includes in {path}")
            with open(path, "w") as f:
                f.write(contents)

    deps = INCLUDE_DEPS.findall(contents)
    return rel_path, deps


def run(files):
    all_deps = defaultdict(set)
    for path in files:
        component, deps = get_include_dependencies(path)
        all_deps[root_component(component)].update(root_component(dep) for dep in deps)

    print("graph LR")
    for c, deps in sorted(all_deps.items(), key=lambda p: len(p[1])):
        for dep in deps:
            print(f"    {c} --> {dep}")


if __name__ == "__main__":
    files = sys.argv[1:]
    run(files)
