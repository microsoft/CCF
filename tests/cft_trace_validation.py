# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Replay the --capture-trace captures under the given directories against
the Lean model of the CCF consensus protocol.

usage: cft_trace_validation.py CONSENSUS_REPLAY DIRECTORY...

A capture may be incomplete, for example if a node was killed, so replay need
not consume every event. Fails if the model disagrees with a capture, if replay
consumes less than WATERMARK of the events of one of its nodes, or if there is
no capture to replay. Captures without ccf.cft events, as of a network whose
first node did not start, are not replayed.
"""

import concurrent.futures
import functools
import json
import os
import pathlib
import subprocess
import sys

WATERMARK = 0.9


def replay(replayer, path):
    """Whether the capture is accepted, and the replayer's output."""
    result = subprocess.run(
        [replayer, "--lenient", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    accepted = (
        result.returncode == 0 and json.loads(result.stdout)["watermark"] >= WATERMARK
    )
    return accepted, (result.stdout + result.stderr).strip()


def has_cft_events(path):
    with open(path, encoding="utf-8") as capture:
        return any(line.startswith('{"tag": "ccf.cft"') for line in capture)


def main(replayer, *directories):
    paths = sorted(
        path
        for directory in directories
        for path in pathlib.Path(directory).rglob("*_trace/*.ndjson")
        if has_cft_events(path)
    )
    # Schedule largest captures first so long traces overlap with smaller ones.
    by_size = sorted(paths, key=lambda path: path.stat().st_size, reverse=True)
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
        results = dict(
            zip(
                by_size,
                pool.map(functools.partial(replay, replayer), by_size),
                strict=True,
            )
        )
    rejected = 0
    for path in paths:
        accepted, output = results[path]
        rejected += not accepted
        print(f"{'OK  ' if accepted else 'FAIL'} {path}: {output}")
    print(f"{len(paths) - rejected} accepted, {rejected} rejected")
    return 0 if paths and not rejected else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
