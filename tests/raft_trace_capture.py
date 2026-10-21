# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Collect native driver traces; leave protocol interpretation to Lean."""

import json
import pathlib
import sys

import raft_trace

import msgpack


def write_evidence(prefix, stdout, stderr, records):
    prefix.with_suffix(prefix.suffix + ".driver.stdout").write_bytes(stdout)
    prefix.with_suffix(prefix.suffix + ".driver.stderr").write_bytes(stderr)
    partial = prefix.with_suffix(".partial")
    try:
        with partial.open("w", encoding="utf-8") as output:
            for record in records:
                line = json.dumps({"tag": "ccf.raft_trace", **record}, allow_nan=False)
                output.write(line + "\n")
    except (TypeError, ValueError):
        # Keep unsupported values as evidence, never coerce them into replay JSON.
        prefix.with_suffix(prefix.suffix + ".driver.records.msgpack").write_bytes(
            msgpack.packb(records)
        )
        raise
    return partial


def capture(driver, scenario, output):
    prefix = pathlib.Path(output)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    prefix.unlink(missing_ok=True)
    try:
        result, records = raft_trace.run_driver(driver, scenario)
    except raft_trace.CaptureError as error:
        write_evidence(prefix, error.stdout, error.stderr, error.records)
        raise
    partial = write_evidence(
        prefix, result.stdout.encode("utf-8"), result.stderr.encode("utf-8"), records
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"raft_driver exited {result.returncode}; see {prefix}.driver.stdout"
        )
    if result.stderr:
        raise RuntimeError(f"raft_driver wrote to stderr; see {prefix}.driver.stderr")
    partial.replace(prefix)


def main():
    driver, scenarios, output = sys.argv[1:]
    scenarios = pathlib.Path(scenarios).resolve()
    output = pathlib.Path(output).resolve()
    if output.is_relative_to(scenarios) or scenarios.is_relative_to(output):
        raise ValueError("Output and scenario inventory trees must be disjoint")
    selected = sorted(path for path in scenarios.rglob("*") if path.is_file())
    if not selected:
        raise ValueError("Empty scenario inventory")
    failures = []
    for scenario in selected:
        destination = output / (str(scenario.relative_to(scenarios)) + ".stdout")
        try:
            capture(driver, scenario, destination)
        except Exception as error:
            failures.append(f"{scenario}: {error}")
            print(failures[-1], file=sys.stderr)
    if failures:
        raise RuntimeError(f"{len(failures)}/{len(selected)} captures failed")


if __name__ == "__main__":
    main()
