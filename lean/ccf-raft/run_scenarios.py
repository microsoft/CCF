#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture, reduce, and replay every upstream raft_scenario_test input."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from capture import capture
from reduction import reduce_trace
from trace_io import TraceError, json_object, read_trace

PACKAGE = Path(__file__).resolve().parent
REPOSITORY = PACKAGE.parent.parent


def inventory(directory: Path) -> list[Path]:
    """Select every file recursively, as upstream expand_files does."""
    if not directory.is_dir():
        raise TraceError(f"{directory}: scenario inventory is not a directory")
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    if not files:
        raise TraceError(f"{directory}: empty scenario inventory")
    return files


def run_suite(
    driver: Path | None,
    replayer: Path,
    scenarios: Path,
    output: Path,
    timeout: float = 120,
    raw_directory: Path | None = None,
) -> dict:
    """Attempt every selected input. A failed stage never counts as a pass."""
    scenarios = scenarios.resolve()
    output = output.resolve()
    summary_path = output / "summary.json"
    summary_path.unlink(missing_ok=True)
    if raw_directory is not None:
        raw_directory = raw_directory.resolve()
    selected = inventory(scenarios)
    if driver is None and raw_directory is None:
        raise TraceError("provide a driver or --raw-directory")
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for scenario in selected:
        relative = scenario.relative_to(scenarios)
        base = output / relative
        base.parent.mkdir(parents=True, exist_ok=True)
        raw_base = base if raw_directory is None else raw_directory / relative
        raw = raw_base.with_name(raw_base.name + ".stdout")
        replay = base.with_name(base.name + ".replay.json")
        lean_stdout = base.with_name(base.name + ".lean.stdout")
        lean_stderr = base.with_name(base.name + ".lean.stderr")
        result = {
            "scenario": str(relative),
            "raw": str(raw),
            "status": "failed",
            "stage": "capture" if raw_directory is None else "reduction",
        }
        try:
            for artifact in (replay, lean_stdout, lean_stderr):
                artifact.unlink(missing_ok=True)
            if raw_directory is None:
                if driver is None:
                    raise TraceError("capture requires a driver")
                capture(driver, scenario, raw, timeout)
            result["stage"] = "reduction"
            reduced = reduce_trace(read_trace(raw))
            replay.write_text(
                json.dumps(reduced, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            result["stage"] = "replay"
            with lean_stdout.open("wb") as stdout, lean_stderr.open("wb") as stderr:
                try:
                    process = subprocess.run(
                        [str(replayer.resolve()), str(replay.resolve())],
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        timeout=timeout,
                        check=False,
                    )
                except subprocess.TimeoutExpired as error:
                    raise TraceError(f"canonical replay exceeded {timeout}s") from error
            if process.returncode:
                raise TraceError(
                    f"canonical replay exited {process.returncode}; see {lean_stderr}"
                )
            response = json_object(
                lean_stdout.read_text(encoding="utf-8"), str(lean_stdout)
            )
            expected = {
                "status": "ok",
                "instructions": len(reduced["instructions"]),
                "actions": sum(i["kind"] == "action" for i in reduced["instructions"]),
                "observations": sum(
                    i["kind"] == "observation" for i in reduced["instructions"]
                ),
            }
            if response != expected:
                raise TraceError(
                    f"{lean_stdout}: canonical replay did not consume every instruction: {response!r}"
                )
            result.update(status="passed", instructions=len(reduced["instructions"]))
        except (TraceError, OSError) as error:
            result["error"] = str(error)
        results.append(result)
        print(f"{relative}: {result['status']} ({result['stage']})", flush=True)
    summary = {
        "inventory": str(scenarios.resolve()),
        "selected": len(selected),
        "passed": sum(result["status"] == "passed" for result in results),
        "results": results,
    }
    summary["failed"] = summary["selected"] - summary["passed"]
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("driver", type=Path, nargs="?")
    parser.add_argument(
        "--raw-directory",
        type=Path,
        help="Use existing <scenario>.stdout files without running the driver",
    )
    parser.add_argument(
        "--replayer", type=Path, default=PACKAGE / ".lake/build/bin/ccfraft-replay"
    )
    parser.add_argument(
        "--scenarios", type=Path, default=REPOSITORY / "tests/raft_scenarios"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    try:
        summary = run_suite(
            args.driver,
            args.replayer,
            args.scenarios,
            args.output,
            args.timeout,
            args.raw_directory,
        )
    except (TraceError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"{summary['passed']}/{summary['selected']} passed")
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
