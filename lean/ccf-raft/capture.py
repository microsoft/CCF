#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture raft_driver stdout verbatim, without upstream preprocessing."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from trace_io import TraceError, read_trace


def capture(driver: Path, scenario: Path, output: Path, timeout: float = 120) -> Path:
    """Run one real scenario, keeping stdout and stderr even on failure."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix != ".stdout":
        raise TraceError("capture output must have the .stdout suffix")
    if not scenario.is_file():
        raise TraceError(f"{scenario}: scenario is not a file")
    with output.open("wb") as stdout, output.with_suffix(".stderr").open(
        "wb"
    ) as stderr:
        try:
            result = subprocess.run(
                [str(driver.resolve()), str(scenario.resolve())],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise TraceError(f"{scenario}: raft_driver exceeded {timeout}s") from error
    if result.returncode:
        raise TraceError(
            f"{scenario}: raft_driver exited {result.returncode}; "
            f"see {output} and {output.with_suffix('.stderr')}"
        )
    if output.with_suffix(".stderr").stat().st_size:
        raise TraceError(
            f"{scenario}: raft_driver wrote to stderr; see {output.with_suffix('.stderr')}"
        )
    read_trace(output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("driver", type=Path)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    try:
        capture(args.driver, args.scenario, args.output, args.timeout)
    except (TraceError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
