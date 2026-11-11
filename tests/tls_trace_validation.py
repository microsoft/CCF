#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture TLS connection engine traces and optionally replay them through the Lean model."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

# The test cases which establish connections with a traffic-key policy. Only
# these are run, so that an unrelated test which the capture environment cannot
# support, such as one which binds IPv6 loopback, does not fail the capture.
TRACED_CASES = [
    "Traffic keys*",
    "A connection exceeding its queued output bound is closed alone",
    "Client and server owners propagate the opt-in traffic-key policy",
]

# What the captured passes must include between them, so that a change to the
# tests cannot silently stop the traces from reaching the states the model is
# about. Each name is explained where it is computed, in coverage().
REQUIRED_COVERAGE = {
    "application record read",
    "application record written",
    "write retried",
    "KeyUpdate sent",
    "KeyUpdate unflushed",
    "peer KeyUpdate",
    "peer KeyUpdate requested",
    "response owed",
    "response owed behind a pending write",
    "read blocked on a response",
    "record held",
    "receive budget exceeded",
    "peer closed",
    "closed after flush",
    "aborted",
}


def execute(command, directory, prefix, timeout, env=None):
    with (directory / f"{prefix}.stdout.txt").open("wb") as stdout, (
        directory / f"{prefix}.stderr.txt"
    ).open("wb") as stderr:
        return subprocess.run(
            command,
            check=False,
            env=env,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
        )


def check_case_list(binary):
    # A renamed or removed case would otherwise silently drop out of the traces.
    for pattern in TRACED_CASES:
        listing = subprocess.run(
            [
                str(binary),
                "--list-test-cases",
                f"--test-case={pattern}",
                "--case-sensitive=true",
                "--reporters=xml",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if not list(ElementTree.fromstring(listing).iter("TestCase")):
            raise RuntimeError(f"no test case of {binary.name} matches '{pattern}'")


def coverage(trace):
    """The states and operations of interest which a trace's passes include."""
    found = set()
    with trace.open(encoding="utf-8") as source:
        events = [json.loads(line) for line in source]
    if not events or events[-1].get("type") != "trace_end":
        raise RuntimeError(f"{trace} is truncated: it does not end with trace_end")
    for event in events:
        kind = event.get("type")
        if kind == "abort":
            found.add("aborted")
        if kind != "pass":
            continue
        operations = event["ops"]
        if any(operation.startswith("d") for operation in operations):
            found.add("application record read")
        if any(operation.startswith("s") for operation in operations):
            found.add("application record written")
        if "wk0" in operations:
            found.add("KeyUpdate sent")
        if "rk0" in operations or "rk1" in operations:
            found.add("peer KeyUpdate")
        if "rk1" in operations:
            found.add("peer KeyUpdate requested")
        if not event["alive"]:
            if event["exceeded"]:
                found.add("receive budget exceeded")
            else:
                found.add("peer closed")
            continue
        if event["closed"]:
            found.add("closed after flush")
        if event["retry"] != 0:
            found.add("write retried")
        if event["in_init"]:
            # A KeyUpdate was constructed and the socket has not taken it.
            found.add("KeyUpdate unflushed")
        if event["update_queued"]:
            found.add("response owed")
            if event["retry"] != 0:
                found.add("response owed behind a pending write")
        if event["read_wants_write"]:
            found.add("read blocked on a response")
        # A KeyUpdate record was decrypted and its message is not yet processed.
        inbound = [o for o in operations if o in ("r22", "rk0", "rk1")]
        if inbound and inbound[-1] == "r22":
            found.add("record held")
    return found


def capture(binary, directory, timeout):
    directory.mkdir(parents=True, exist_ok=True)
    trace = directory / "trace.ndjson"
    env = dict(os.environ, CCF_TLS_TRACE_FILE=str(trace.resolve()))
    command = [
        str(binary),
        f"--test-case={','.join(TRACED_CASES)}",
        "--case-sensitive=true",
    ]
    result = execute(command, directory, "capture", timeout, env)
    if result.returncode != 0:
        raise RuntimeError(
            f"{binary.name} failed with exit code {result.returncode}; see {directory}"
        )
    if not trace.exists():
        raise RuntimeError(
            f"{binary.name} wrote no trace: it must be built with -DCCF_TLS_TRACING=ON"
        )
    return trace


def replay(checker, trace, timeout):
    result = execute(
        [str(checker), "--json", str(trace)], trace.parent, "replay", timeout
    )
    report = json.loads((trace.parent / "replay.stdout.txt").read_text("utf-8"))
    if result.returncode != 0 or report["status"] != "accepted":
        raise RuntimeError(f"{trace}: {report['status']}: {report['message']}")
    return report["message"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checker", type=Path)
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if args.capture_only == (args.checker is not None):
        parser.error("pass exactly one of --checker and --capture-only")
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    check_case_list(args.binary)
    # The engine's passes depend on timing, so each run yields a different trace.
    traces = [
        capture(args.binary, args.output / f"run-{run}", args.timeout)
        for run in range(args.runs)
    ]
    found = set().union(*(coverage(trace) for trace in traces))
    missing = REQUIRED_COVERAGE - found
    if missing:
        raise RuntimeError(f"the traces do not cover: {', '.join(sorted(missing))}")
    print(f"captured {len(traces)} traces covering {len(found)} required states")
    if args.checker is not None:
        for trace in traces:
            print(f"{trace}: {replay(args.checker, trace, args.timeout)}")


if __name__ == "__main__":
    try:
        main()
    except (
        RuntimeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
