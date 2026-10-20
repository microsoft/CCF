# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Collect native driver traces; leave protocol interpretation to Lean."""

import json
import pathlib
import sys

import raft_trace


def capture(driver, scenario, output):
    result, records = raft_trace.run_driver(driver, scenario)
    prefix = pathlib.Path(output)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    prefix.with_suffix(prefix.suffix + ".driver.stdout").write_text(
        result.stdout, encoding="utf-8"
    )
    prefix.with_suffix(prefix.suffix + ".driver.stderr").write_text(
        result.stderr, encoding="utf-8"
    )
    prefix.write_text(
        "".join(
            json.dumps({"tag": "ccf.raft_trace", **record}, allow_nan=False) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"raft_driver exited {result.returncode}; see {prefix}.driver.stdout"
        )
    if result.stderr:
        raise RuntimeError(f"raft_driver wrote to stderr; see {prefix}.driver.stderr")


def main():
    driver, scenarios, output = sys.argv[1:]
    scenarios = pathlib.Path(scenarios).resolve()
    output = pathlib.Path(output).resolve()
    if output.is_relative_to(scenarios):
        raise ValueError("Output must be outside the scenario inventory")
    selected = sorted(path for path in scenarios.rglob("*") if path.is_file())
    if not selected:
        raise ValueError("Empty scenario inventory")
    failures = []
    for scenario in selected:
        destination = output / (str(scenario.relative_to(scenarios)) + ".stdout")
        destination.unlink(missing_ok=True)
        try:
            capture(driver, scenario, destination)
        except Exception as error:
            # Preserve partial evidence, but never let it become a replay input.
            if destination.exists():
                destination.replace(destination.with_suffix(".partial"))
            failures.append(f"{scenario}: {error}")
            print(failures[-1], file=sys.stderr)
    if failures:
        raise RuntimeError(f"{len(failures)}/{len(selected)} captures failed")


if __name__ == "__main__":
    main()
