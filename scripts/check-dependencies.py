# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
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

    changed = False
    if canonicalise_includes:
        (contents, corrections) = LOCAL_INCLUDE.subn(
            f'#include "{rel_path}/\g<1>"', contents
        )

        if corrections > 0:
            print(f"Canonicalised {corrections} includes in {path}", file=sys.stderr)
            with open(path, "w") as f:
                f.write(contents)
                changed = True

    deps = INCLUDE_DEPS.findall(contents)
    return rel_path, deps, changed


def run(paths, fix, mermaid_path):
    all_deps = defaultdict(set)
    any_changes = False
    for path in paths:
        component, deps, changed = get_include_dependencies(
            path, canonicalise_includes=fix
        )
        any_changes |= changed
        all_deps[root_component(component)].update(root_component(dep) for dep in deps)

    if mermaid_path:
        mermaid_contents = []
        mermaid_contents.append("graph LR")
        for c, deps in sorted(all_deps.items(), key=lambda p: len(p[1])):
            for dep in sorted(deps):
                #  Don't print self-dependencies
                if c == dep:
                    continue

                # Don't print dependencies on public headers
                if dep == "ccf":
                    continue

                # If this is a circular dependency, render it with a dotted arrow
                if c in all_deps[dep]:
                    mermaid_contents.append(f"    {c} -.-> {dep}")
                else:
                    mermaid_contents.append(f"    {c} --> {dep}")

        try:
            original = open(mermaid_path).read().splitlines()
        except:
            original = ""

        if original != mermaid_contents:
            open(mermaid_path, "w").write("\n".join(mermaid_contents))
            any_changes = True
            print(f"Rewrote diagram in {mermaid_path}", file=sys.stderr)

    return any_changes


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-mermaid",
        help="Path where mermaid file should be written. If empty, nothing is written.",
    )
    parser.add_argument("--fix", "-f", action="store_true")
    parser.add_argument("files", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    any_changes = run(args.files, args.fix, args.write_mermaid)
    if any_changes:
        sys.exit(1)
    else:
        print("No problems found")
