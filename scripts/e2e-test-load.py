#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Measure the runner load of CCF end-to-end tests from CI logs.

Each e2e test declares a ``PROCESSORS`` weight in ``CMakeLists.txt`` (see
``add_e2e_test`` in ``cmake/common.cmake``). The weight is expressed in
concurrently live CCF node processes, and ctest keeps the sum of the weights of
running tests within its ``-j`` budget. This script recomputes those weights
from a CI run so they can be refreshed when a test's set of sub-tests changes.

Usage::

    gh run download <run-id> -n logs-azurelinux-virtual-b -D logs-b
    gh run view <run-id> --log > run.log
    python scripts/e2e-test-load.py logs-b run.log

``logs-b`` is the uploaded ``build/workspace`` tree: one directory per CCF node,
each containing the node's ``out``/``err`` logs. ``run.log`` is any file
containing the ctest summary lines, which give each test's wall-clock duration.

A node's lifetime is the span between its first and last timestamped log line.
Summing node lifetimes for a test and dividing by the test's duration gives the
average number of nodes it keeps alive, which is what the weight should be.
"""

import argparse
import math
import os
import re
import sys
from datetime import datetime

LOG_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z")

# e.g. "  7/13 Test #84: e2e_logging ...........   Passed   84.01 sec"
CTEST_RESULT = re.compile(
    r"Test\s+#\d+:\s+(?P<name>\S+)\s+\.+\s+\S+\s+(?P<seconds>\d+\.\d+)\s+sec"
)


def parse_ctest_durations(path):
    """Map ctest test name to its wall-clock duration in seconds."""
    durations = {}
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = CTEST_RESULT.search(line)
            if m:
                # A test can appear in several jobs; keep the longest run, which
                # is the one the weight has to accommodate.
                name = m.group("name")
                seconds = float(m.group("seconds"))
                durations[name] = max(durations.get(name, 0.0), seconds)
    return durations


def node_lifetime(node_dir):
    """Seconds between a node's first and last timestamped log line."""
    first = last = None
    for filename in ("out", "err"):
        path = os.path.join(node_dir, filename)
        if not os.path.isfile(path):
            continue
        with open(path, "r", errors="ignore") as f:
            for line in f:
                m = LOG_TIMESTAMP.match(line)
                if not m:
                    continue
                stamp = datetime.strptime(m.group(1)[:26], "%Y-%m-%dT%H:%M:%S.%f")
                if first is None or stamp < first:
                    first = stamp
                if last is None or stamp > last:
                    last = stamp
    if first is None or last is None:
        return 0.0
    return (last - first).total_seconds()


def owning_test(workspace_name, test_names):
    """Attribute a workspace directory to the ctest test that created it.

    Workspace directories are named ``<sub-test>_<ctest label>_<suffix>``, where
    the label is the ctest test name. Prefer the longest match so that, for
    example, ``e2e_logging`` does not claim ``e2e_logging_http2``'s directories.
    """
    best = None
    for name in test_names:
        if name in workspace_name and (best is None or len(name) > len(best)):
            best = name
    return best


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", help="Downloaded build/workspace log tree")
    parser.add_argument("ctest_log", help="File containing ctest summary lines")
    parser.add_argument(
        "--min-duration",
        type=float,
        default=1.0,
        help="Ignore tests shorter than this many seconds (default: 1.0)",
    )
    args = parser.parse_args()

    durations = parse_ctest_durations(args.ctest_log)
    if not durations:
        print(f"No ctest result lines found in {args.ctest_log}", file=sys.stderr)
        return 1

    node_seconds = {name: 0.0 for name in durations}
    node_counts = {name: 0 for name in durations}
    leaked = []

    for entry in sorted(os.listdir(args.workspace)):
        node_dir = os.path.join(args.workspace, entry)
        if not os.path.isdir(node_dir):
            continue
        name = owning_test(entry, durations)
        if name is None:
            continue
        lifetime = node_lifetime(node_dir)
        if lifetime <= 0:
            continue
        node_seconds[name] += lifetime
        node_counts[name] += 1
        # A node living far longer than its own test was never reaped, which
        # both wastes CPU and inflates the measured weight.
        if lifetime > durations[name] * 1.5:
            leaked.append((entry, lifetime, name, durations[name]))

    print(f"{'test':<44} {'wall_s':>8} {'nodes':>6} {'node_s':>9} {'PROCESSORS':>11}")
    total = 0.0
    for name, wall in sorted(durations.items(), key=lambda kv: -kv[1]):
        if wall < args.min_duration and node_counts[name] == 0:
            continue
        weight = max(1, math.ceil(node_seconds[name] / wall)) if wall > 0 else 1
        print(
            f"{name:<44} {wall:8.1f} {node_counts[name]:6d} "
            f"{node_seconds[name]:9.1f} {weight:11d}"
        )
        total += wall
    print(f"\nserial total: {total:.1f}s")

    if leaked:
        print("\nNodes outliving their test (weights above are overstated):")
        for entry, lifetime, name, wall in leaked:
            print(f"  {entry}: lived {lifetime:.0f}s, {name} took {wall:.0f}s")

    return 0


if __name__ == "__main__":
    sys.exit(main())
