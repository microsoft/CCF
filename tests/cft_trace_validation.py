# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Replay the complete --capture-cft-trace captures under the given directories
against the Lean model of the CCF consensus protocol.

usage: cft_trace_validation.py CONSENSUS_REPLAY DIRECTORY...

Inconclusive captures are skipped. Fails if a complete capture is rejected, or
if there is no complete capture to replay.
"""

import collections
import concurrent.futures
import functools
import json
import os
import pathlib
import subprocess
import sys


def replay(replayer, manifest_path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not manifest["complete"]:
        return "SKIP", "; ".join(manifest["reasons"])
    result = subprocess.run(
        [replayer, str(manifest_path.parent / "cft.ndjson")],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return "OK", result.stdout.strip()
    return "FAIL", (result.stdout + result.stderr).strip()


def main(replayer, *directories):
    paths = sorted(
        path
        for directory in directories
        for path in pathlib.Path(directory).rglob("*_trace/*/manifest.json")
    )
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
        results = list(pool.map(functools.partial(replay, replayer), paths))
    for path, (status, detail) in zip(paths, results, strict=True):
        print(f"{status:4} {path.parent}: {detail}")
    counts = collections.Counter(status for status, _ in results)
    print(
        f"{counts['OK']} accepted, {counts['FAIL']} rejected, "
        f"{counts['SKIP']} inconclusive"
    )
    return 0 if counts["OK"] and not counts["FAIL"] else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
