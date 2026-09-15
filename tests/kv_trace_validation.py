#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate KV traces and check that the Lean model accepts them."""

import argparse
import json
import math
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FUZZ_CASE = "KV trace concurrent operation fuzzer"
TRACE_CASES = {
    "KV trace multi-map semantics",
    "KV trace dependencies",
    "KV trace iteration",
    "KV trace compaction rollback",
    "KV trace per-map global snapshots",
    "KV trace disjoint concurrent commits",
    "KV trace replication failure after apply",
}
REQUIRED_FUZZ_COVERAGE = {
    "snapshot",
    "map_acquire",
    "map_unavailable",
    "get",
    "has",
    "get_global",
    "has_global",
    "previous_write",
    "put",
    "remove",
    "clear",
    "size",
    "foreach_begin",
    "foreach_entry",
    "foreach_continue",
    "foreach_end",
    "commit_begin",
    "apply",
    "commit_result",
    "compact",
    "rollback",
    "rollback_rejected",
    "commit_result:success",
    "commit_result:conflict",
    "commit_result:no_replicate",
    "foreach_continue:false",
    "get:absent",
    "get:present",
    "get_global:absent",
    "get_global:present",
    "previous_write:absent",
    "previous_write:present",
    "put:empty_key",
    "put:empty_value",
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


def inspect_trace(trace, expected_cases, require_fuzz_coverage):
    cases = set()
    coverage = set()
    with trace.open(encoding="utf-8") as source:
        for line in source:
            event = json.loads(line)
            kind = event.get("type")
            coverage.add(kind)
            if kind == "case_begin":
                cases.add(event["name"])
            elif kind in {"get", "get_global", "previous_write"}:
                state = "absent" if event["value"] is None else "present"
                coverage.add(f"{kind}:{state}")
            elif kind == "commit_result":
                coverage.add(f"{kind}:{event['result']}")
            elif kind == "foreach_continue" and event["value"] is False:
                coverage.add("foreach_continue:false")
            elif kind == "put":
                if event["key"] == "":
                    coverage.add("put:empty_key")
                if event["value"] == "":
                    coverage.add("put:empty_value")

    if cases != expected_cases:
        raise RuntimeError(
            f"{trace}: expected cases {sorted(expected_cases)}, observed {sorted(cases)}"
        )
    if require_fuzz_coverage:
        missing = sorted(REQUIRED_FUZZ_COVERAGE - coverage)
        if missing:
            raise RuntimeError(f"{trace}: missing fuzzer coverage: {missing}")


def check_trace(args, label, case_filter, expected_cases, seed=None):
    directory = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=args.output.resolve()))
    print(f"{label}: {directory}", flush=True)
    trace = directory / "trace.ndjson"
    env = dict(os.environ)
    env["CCF_KV_TRACE_FILE"] = str(trace)
    if seed is not None:
        env["CCF_KV_FUZZ_SEED"] = str(seed)
    try:
        test_status = execute(
            [
                str(args.binary),
                f"--test-case={case_filter}",
                "--case-sensitive=true",
                "--reporters=console,kv_trace",
                "--no-colors=true",
            ],
            directory,
            "test",
            args.timeout,
            env,
        ).returncode
    except subprocess.TimeoutExpired:
        test_status = "timeout"
    if not trace.is_file():
        raise RuntimeError(f"{directory}: KV test {test_status} and emitted no trace")

    checked = execute(
        [str(args.checker), str(trace)],
        directory,
        "checker",
        args.timeout,
    )
    if test_status != 0 or checked.returncode != 0:
        raise RuntimeError(
            f"{directory}: KV test {test_status}; "
            f"Lean checker exited {checked.returncode}"
        )
    inspect_trace(trace, expected_cases, seed is not None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed-start", type=int, default=0)
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()

    maximum_seed = 2**64 - 1
    if not 1 <= args.seeds <= 256:
        parser.error("--seeds must be in [1, 256]")
    if not 0 <= args.seed_start <= maximum_seed - args.seeds + 1:
        parser.error("seed range must fit in an unsigned 64-bit integer")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")

    args.binary = args.binary.resolve(strict=True)
    args.checker = args.checker.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        check_trace(
            args,
            "suite",
            ",".join(sorted(TRACE_CASES)),
            TRACE_CASES,
        )
        for offset in range(args.seeds):
            seed = args.seed_start + offset
            check_trace(args, f"seed-{seed}", FUZZ_CASE, {FUZZ_CASE}, seed)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
