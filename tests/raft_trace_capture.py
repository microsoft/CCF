# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Capture and replay native scenarios; leave protocol interpretation to Lean."""

import argparse
import json
import math
import pathlib
import subprocess
import sys

import raft_trace

import msgpack


def evidence_paths(prefix):
    return {
        "partial": prefix.with_suffix(".partial"),
        "stdout": prefix.with_suffix(prefix.suffix + ".driver.stdout"),
        "stderr": prefix.with_suffix(prefix.suffix + ".driver.stderr"),
        "records": prefix.with_suffix(prefix.suffix + ".driver.records.msgpack"),
    }


def write_evidence(prefix, stdout, stderr, records):
    paths = evidence_paths(prefix)
    paths["stdout"].write_bytes(stdout)
    paths["stderr"].write_bytes(stderr)
    try:
        with paths["partial"].open("w", encoding="utf-8") as output:
            for record in records:
                line = json.dumps({"tag": "ccf.raft_trace", **record}, allow_nan=False)
                output.write(line + "\n")
    except (TypeError, ValueError):
        # Keep unsupported values as evidence, never coerce them into replay JSON.
        paths["records"].write_bytes(msgpack.packb(records))
        raise
    return paths["partial"]


def capture(driver, scenario, output, timeout=60):
    prefix = pathlib.Path(output)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    prefix.unlink(missing_ok=True)
    try:
        result, records = raft_trace.run_driver(
            driver, scenario, timeout=timeout, text=False
        )
    except raft_trace.CaptureError as error:
        write_evidence(prefix, error.stdout, error.stderr, error.records)
        raise
    partial = write_evidence(prefix, result.stdout, result.stderr, records)
    if result.returncode != 0:
        raise RuntimeError(
            f"raft_driver exited {result.returncode}; see {prefix}.driver.stdout"
        )
    if result.stderr:
        print(f"raft_driver diagnostics: {prefix}.driver.stderr", file=sys.stderr)
    partial.replace(prefix)


def run_suite(
    scenarios, output, *, driver=None, raw_directory=None, replayer=None, timeout=60
):
    if (driver is None) == (raw_directory is None):
        raise ValueError("Provide exactly one of driver and raw_directory")
    if raw_directory is not None and replayer is None:
        raise ValueError("raw_directory requires a replayer")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be positive and finite")
    scenarios = pathlib.Path(scenarios).resolve()
    output = pathlib.Path(output).resolve()
    if output.is_relative_to(scenarios) or scenarios.is_relative_to(output):
        raise ValueError("Output and scenario inventory trees must be disjoint")
    summary_path = output / "summary.json"
    raw_directory = (
        pathlib.Path(raw_directory).resolve() if raw_directory is not None else output
    )
    runs = []
    artifacts = [summary_path]
    for scenario in sorted(path for path in scenarios.rglob("*") if path.is_file()):
        relative = scenario.relative_to(scenarios)
        destination = raw_directory / (str(relative) + ".stdout")
        result_path = output / (str(relative) + ".result.json")
        runs.append((scenario, relative, destination, result_path))
        artifacts.append(result_path)
        if driver is not None:
            artifacts.extend([destination, *evidence_paths(destination).values()])
    files = set()
    for path in artifacts:
        if path in files:
            raise ValueError(f"Artifact path collision: {path} is used more than once")
        files.add(path)
    for path in artifacts:
        for parent in path.parents:
            if parent in files:
                raise ValueError(
                    f"Artifact path collision: {parent} is both a file and "
                    f"a directory for {path}"
                )
    summary_path.unlink(missing_ok=True)
    if not scenarios.is_dir():
        raise ValueError(f"Not a scenario inventory directory: {scenarios}")
    if not runs:
        raise ValueError("Empty scenario inventory")
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for scenario, relative, destination, result_path in runs:
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.unlink(missing_ok=True)
        result = {
            "scenario": str(relative),
            "raw": str(destination),
            "stage": "capture" if driver is not None else "replay",
        }
        try:
            if driver is not None:
                capture(driver, scenario, destination, timeout=timeout)
            if replayer is not None:
                result["stage"] = "replay"
                completed = subprocess.run(
                    [str(pathlib.Path(replayer).resolve()), str(destination)],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=True,
                )
                if completed.stderr:
                    print(completed.stderr, file=sys.stderr, end="")
                counts = json.loads(completed.stdout)
                result.update(
                    (key, counts[key])
                    for key in ("instructions", "actions", "observations")
                )
            result["status"] = "passed"
        except Exception as error:
            diagnostic = (
                error.stderr
                if isinstance(error, subprocess.CalledProcessError) and error.stderr
                else str(error)
            )
            result.update(status="failed", error=diagnostic)
            print(f"{scenario}: {diagnostic}", file=sys.stderr)
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"{relative}: {result['status']} ({result['stage']})")
        results.append(result)
    passed = sum(result["status"] == "passed" for result in results)
    summary = {
        "inventory": str(scenarios),
        "selected": len(runs),
        "passed": passed,
        "failed": len(runs) - passed,
        "results": results,
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenarios", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--driver", type=pathlib.Path)
    source.add_argument("--raw-directory", type=pathlib.Path)
    parser.add_argument("--replayer", type=pathlib.Path)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    summary = run_suite(**vars(args))
    if summary["failed"]:
        raise RuntimeError(
            f"{summary['failed']}/{summary['selected']} scenarios failed"
        )


if __name__ == "__main__":
    main()
