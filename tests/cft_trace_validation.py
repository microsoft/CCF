# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Replay the --capture-cft-trace captures under the given directories against
the Lean model of the CCF consensus protocol.

usage: cft_trace_validation.py CONSENSUS_REPLAY DIRECTORY...

Fails if a capture is rejected, or if there is no capture to replay.
"""

import concurrent.futures
import functools
import os
import pathlib
import subprocess
import sys


def replay(replayer, path):
    return subprocess.run(
        [replayer, str(path)], capture_output=True, text=True, check=False
    )


def main(replayer, *directories):
    paths = sorted(
        path
        for directory in directories
        for path in pathlib.Path(directory).rglob("*_trace/*.ndjson")
    )
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
        results = list(pool.map(functools.partial(replay, replayer), paths))
    rejected = 0
    for path, result in zip(paths, results, strict=True):
        rejected += result.returncode != 0
        status = "FAIL" if result.returncode else "OK  "
        print(f"{status} {path}: {(result.stdout + result.stderr).strip()}")
    print(f"{len(paths) - rejected} accepted, {rejected} rejected")
    return 0 if paths and not rejected else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
