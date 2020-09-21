# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("out_path")
args = parser.parse_args()

with open("CHANGELOG.md") as f:
    changelog = f.read()

marker = "\n## "

idx_unreleased = changelog.find(marker)
idx_newest = changelog.find(marker, idx_unreleased + len(marker))
idx_newest_2nd_line = changelog.find("\n", idx_newest + len(marker))
idx_end = changelog.find(marker, idx_newest + len(marker))

rel_notes = changelog[idx_newest_2nd_line:idx_end].strip()
print(rel_notes)

with open(args.out_path, "w") as f:
    f.write(rel_notes)
