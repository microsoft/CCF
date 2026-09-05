# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture KV unit-test observations and replay them with the Lean checker."""

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

CHECKER_STATUSES = {"accepted", "rejected", "invalid_trace", "unsupported"}


def load_manifest(path):
    with path.open(encoding="utf-8") as source:
        manifest = json.load(source)
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema")) is not int
        or manifest["schema"] != 1
    ):
        raise ValueError("Unsupported KV trace coverage manifest")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("The coverage manifest must select at least one test")
    names = []
    for case in cases:
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("name"), str)
            or not case["name"]
            or not isinstance(case.get("features"), list)
            or not case["features"]
            or not all(
                isinstance(feature, str) and feature.strip()
                for feature in case["features"]
            )
        ):
            raise ValueError("Each selected test needs a name and covered features")
        if case["name"] in names:
            raise ValueError(f"Duplicate selected test: {case['name']}")
        names.append(case["name"])
    exclusions = manifest.get("exclusions")
    if not isinstance(exclusions, list):
        raise TypeError("The coverage manifest must declare its exclusions")
    for exclusion in exclusions:
        if (
            not isinstance(exclusion, dict)
            or not isinstance(exclusion.get("name"), str)
            or not exclusion["name"]
            or not isinstance(exclusion.get("reason"), str)
            or not exclusion["reason"]
        ):
            raise ValueError("Each excluded test needs an exact name and a reason")
    excluded_names = [exclusion["name"] for exclusion in exclusions]
    if len(excluded_names) != len(set(excluded_names)):
        raise ValueError("Duplicate excluded tests")
    overlap = set(names).intersection(excluded_names)
    if overlap:
        raise ValueError(
            f"Tests cannot be both selected and excluded: {sorted(overlap)}"
        )
    return manifest


def test_arguments(name):
    # Doctest interprets these characters as filter syntax, not literal names.
    if not name or any(character in name for character in ",*?\\"):
        raise ValueError(f"Test name cannot be expressed as an exact filter: {name!r}")
    return [
        f"--test-case={name}",
        "--case-sensitive=true",
        "--reporters=console,kv_trace",
        "--no-colors=true",
    ]


def inventory(binary, timeout):
    result = subprocess.run(
        [str(binary), "--list-test-cases", "--reporters=xml", "--no-colors=true"],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={
            key: value
            for key, value in os.environ.items()
            if key != "CCF_KV_TRACE_FILE"
        },
    )
    root = ET.fromstring(result.stdout)
    names = [case.attrib["name"] for case in root.iter("TestCase")]
    if not names:
        raise ValueError("The KV test binary reported no test cases")
    if len(names) != len(set(names)):
        raise ValueError("Duplicate test names cannot be selected unambiguously")
    return names


def coverage(manifest, available, selected):
    unknown = sorted(set(selected).difference(available))
    if unknown:
        raise ValueError(f"Selected tests are absent from this binary: {unknown}")
    exclusions = {
        entry["name"]: entry["reason"] for entry in manifest.get("exclusions", [])
    }
    stale = sorted(set(exclusions).difference(available))
    unclassified = sorted(set(available).difference(selected).difference(exclusions))
    return {
        "available": sorted(available),
        "selected": selected,
        "features": {
            case["name"]: case["features"]
            for case in manifest.get("cases", [])
            if case["name"] in selected
        },
        "excluded": [
            {"name": name, "reason": exclusions[name]}
            for name in sorted(
                set(available).intersection(exclusions).difference(selected)
            )
        ],
        "unclassified": unclassified,
        "stale_exclusions": stale,
        "complete_inventory": not unclassified and not stale,
    }


def decode_checker_result(output, returncode):
    result = json.loads(output)
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("status"), str)
        or result["status"] not in CHECKER_STATUSES
    ):
        raise ValueError("The Lean checker did not return a recognized status")
    if (
        type(result.get("events")) is not int
        or result["events"] < 0
        or not isinstance(result.get("message"), str)
    ):
        raise ValueError("The Lean checker returned malformed diagnostics")
    for field in ("seq", "store", "tx"):
        if field in result and (type(result[field]) is not int or result[field] < 0):
            raise ValueError(f"Invalid checker diagnostic field: {field}")
    if (returncode == 0) != (result["status"] == "accepted"):
        raise ValueError("Checker exit code contradicts its reported status")
    if result["status"] == "accepted" and result["events"] == 0:
        raise ValueError("An empty execution cannot demonstrate KV conformance")
    return result


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def observed_cases(path):
    names = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            event = json.loads(line)
            if event.get("type") == "case_begin":
                names.append(event["name"])
    return names


def preserve_prefix(trace, seq):
    destination = trace.with_suffix(".prefix.ndjson")
    with trace.open(encoding="utf-8") as source, destination.open(
        "x", encoding="utf-8", newline="\n"
    ) as output:
        for line in source:
            event = json.loads(line)
            output.write(line)
            if event.get("seq") == seq:
                return destination.name
    destination.unlink()
    raise ValueError(f"Failing event {seq} is absent from {trace.name}")


def run_case(binary, checker, name, directory, timeout):
    arguments = test_arguments(name)
    trace = directory / "trace.ndjson"
    environment = dict(os.environ, CCF_KV_TRACE_FILE=str(trace))
    with (directory / "test.stdout.txt").open("wb") as stdout, (
        directory / "test.stderr.txt"
    ).open("wb") as stderr:
        result = subprocess.run(
            [str(binary), *arguments],
            check=False,
            stdout=stdout,
            stderr=stderr,
            env=environment,
            timeout=timeout,
        )

    record = {
        "name": name,
        "directory": directory.name,
        "test_returncode": result.returncode,
        "trace": trace.name,
    }
    if not trace.is_file():
        record.update(
            status="capture_failed",
            message="No trace was emitted; use a CCF_KV_TRACING build and reporter",
        )
        return record

    checked = subprocess.run(
        [str(checker), "--json", str(trace)],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    (directory / "checker.stdout.txt").write_text(checked.stdout, encoding="utf-8")
    (directory / "checker.stderr.txt").write_text(checked.stderr, encoding="utf-8")
    diagnostic = decode_checker_result(checked.stdout, checked.returncode)
    record.update(
        status=diagnostic["status"],
        checker_returncode=checked.returncode,
        diagnostic=diagnostic,
    )
    if result.returncode:
        record.update(status="test_failed", message="The C++ test did not succeed")
    elif diagnostic["status"] == "accepted":
        names = observed_cases(trace)
        if not names or any(observed != name for observed in names):
            record.update(
                status="capture_failed",
                message=f"Trace contains unexpected test selection: {names!r}",
            )
    elif diagnostic["status"] == "rejected" and "seq" in diagnostic:
        record["failing_prefix"] = preserve_prefix(trace, diagnostic["seq"])
    return record


def outcome(records, inventory_complete, explicit_selection=False):
    if not records:
        return 1
    if any(
        record["status"] not in {"accepted", "rejected", "unsupported"}
        for record in records
    ):
        return 1
    if not explicit_selection and not inventory_complete:
        return 1
    if any(record["status"] != "accepted" for record in records):
        return 2
    return 0


def run(args):
    binary = args.binary.resolve(strict=True)
    checker = args.checker.resolve(strict=True)
    manifest = load_manifest(args.manifest)
    selected = args.case or [case["name"] for case in manifest["cases"]]
    if len(selected) != len(set(selected)):
        raise ValueError("A test must not be selected more than once")
    for name in selected:
        test_arguments(name)
    available = inventory(binary, args.timeout)
    reported_coverage = coverage(manifest, available, selected)
    args.output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=args.output.resolve()))
    report = {
        "schema": 1,
        "state": "incomplete",
        "scope": "explicit_selection" if args.case else "coverage_manifest",
        "revision": args.revision,
        "binary_sha256": digest(binary),
        "checker_sha256": digest(checker),
        "manifest_sha256": digest(args.manifest),
        "coverage": reported_coverage,
        "cases": [],
    }
    report_path = directory / "report.json"
    try:
        for index, name in enumerate(selected):
            case_directory = directory / f"case-{index:04}"
            case_directory.mkdir()
            report["cases"].append(
                {
                    "name": name,
                    "directory": case_directory.name,
                    "status": "capture_incomplete",
                }
            )
            try:
                report["cases"][-1] = run_case(
                    binary, checker, name, case_directory, args.timeout
                )
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                report["cases"][-1]["message"] = str(error)
                raise
            report_path.write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
        report["state"] = "complete"
    finally:
        # A failed subprocess or parser must still leave the completed case results.
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    result = outcome(
        report["cases"], reported_coverage["complete_inventory"], bool(args.case)
    )
    print(
        json.dumps(
            {
                "report": str(report_path),
                "accepted": sum(
                    case["status"] == "accepted" for case in report["cases"]
                ),
                "total": len(report["cases"]),
                "inventory_complete": reported_coverage["complete_inventory"],
                "exit_code": result,
            }
        )
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).with_name("kv_trace_cases.json"),
    )
    parser.add_argument("--case", action="append", help="Select an exact doctest case")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--revision", default=os.environ.get("GITHUB_SHA"))
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
