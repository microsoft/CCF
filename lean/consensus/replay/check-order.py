#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Check that consensus replay verdicts depend on neither record order nor schedule.

Each trace is replayed after shuffling its records, and after also moving each node's
records into a process of its own with a random, gapped h_ts counter, which changes the
order in which the replayer runs enabled groups. Every variant must give the original's
exit status and output, ignoring record locations.
"""

import argparse
import json
import pathlib
import random
import re
import subprocess
import sys
import tempfile

LOCATION = re.compile(r"\S+\.ndjson(:\d+)?")


def replay(replayer, trace):
    result = subprocess.run(
        [replayer, str(trace)], capture_output=True, text=True, check=False
    )
    return result.returncode, LOCATION.sub("<location>", result.stdout + result.stderr)


def owner(record):
    message = record["msg"]
    if "cmd" in message:
        return "commands"
    if message["function"] == "retired_committed_tx":
        return message["node_id"]
    return message["state"]["node_id"]


def per_node(records, rng):
    clocks = {}
    for record in sorted(records, key=lambda r: (r["process_id"], r["h_ts"])):
        key = (record["process_id"], owner(record))
        if key not in clocks:
            clocks[key] = rng.randrange(1000)
        clocks[key] += rng.randrange(1, 5)
        yield {
            "process_id": "/".join(key),
            "h_ts": clocks[key],
            "msg": record["msg"],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("replayer")
    parser.add_argument("traces", nargs="+", type=pathlib.Path)
    parser.add_argument("--seeds", type=int, default=3)
    args = parser.parse_args()

    failures = 0
    with tempfile.TemporaryDirectory() as work:
        for trace in args.traces:
            expected = replay(args.replayer, trace)
            records = [json.loads(line) for line in trace.read_text().splitlines()]
            for seed in range(args.seeds):
                for name, variant in [
                    ("shuffled", records),
                    ("per-node", list(per_node(records, random.Random(seed)))),
                ]:
                    variant = variant[:]
                    random.Random(seed).shuffle(variant)
                    path = pathlib.Path(work) / f"{name}-{seed}.ndjson"
                    path.write_text("".join(json.dumps(r) + "\n" for r in variant))
                    actual = replay(args.replayer, path)
                    if actual != expected:
                        failures += 1
                        print(f"{trace} ({name}, seed {seed}):")
                        print(f"  expected {expected}")
                        print(f"  actual   {actual}")
    print(f"{len(args.traces)} traces checked, {failures} differing variants")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
