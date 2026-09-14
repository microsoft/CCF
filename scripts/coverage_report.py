# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Summarise and check a summary-only llvm-cov JSON export."""

import argparse
import json
import sys
from pathlib import Path

METRICS = ("lines", "branches")
SCOPES = ("Framework", "Samples", "Other", "All reported C++")

# One implementation file per first-party library, plus formerly unhit headers.
INSTRUMENTATION_SENTINELS = (
    "src/host/run.cpp",
    "src/enclave/main.cpp",
    "src/crypto/base64.cpp",
    "src/js/core/context.cpp",
    "src/endpoints/authentication/jwt_auth.cpp",
    "src/kv/tx.cpp",
    "src/tasks/task_system.cpp",
    "src/pal/attestation.cpp",
    "src/threading/thread_ids.cpp",
    "src/node/node_state.h",
    "src/host/tcp.h",
    "src/http/http2_parser.h",
)


def coverage_files(document: dict, source_dir: Path) -> dict:
    if document["type"] != "llvm.coverage.json.export" or not document["data"]:
        raise ValueError("Expected a non-empty llvm-cov JSON export")

    source_dir = source_dir.resolve()
    files = {}
    for data in document["data"]:
        for entry in data["files"]:
            path = Path(entry["filename"]).resolve()
            filename = (
                path.relative_to(source_dir).as_posix()
                if path.is_relative_to(source_dir)
                else path.as_posix()
            )
            if filename in files:
                raise ValueError(f"Duplicate coverage file: {filename}")
            files[filename] = entry["summary"]
    if not files:
        raise ValueError("Coverage export contains no files")
    return files


def scoped_totals(files: dict) -> dict:
    totals = {
        scope: {metric: {"count": 0, "covered": 0} for metric in METRICS}
        for scope in SCOPES
    }
    for filename, summary in files.items():
        if filename.startswith(("src/", "include/")):
            scope = "Framework"
        elif filename.startswith("samples/"):
            scope = "Samples"
        else:
            scope = "Other"
        for group in (scope, "All reported C++"):
            for metric in METRICS:
                for field in ("count", "covered"):
                    totals[group][metric][field] += summary[metric][field]
    return totals


def format_count(counts: dict) -> str:
    count = counts["count"]
    covered = counts["covered"]
    percent = f"{100 * covered / count:.2f}%" if count else "n/a"
    return f"{covered}/{count} ({percent})"


def render_report(files: dict) -> str:
    lines = [
        "## Native C++ coverage scope",
        "",
        "| Scope | Covered lines | Covered branches |",
        "| --- | --- | --- |",
    ]
    for scope, totals in scoped_totals(files).items():
        lines.append(
            f"| {scope} | {format_count(totals['lines'])} "
            f"| {format_count(totals['branches'])} |"
        )
    lines += [
        "",
        "Framework is `src/` and `include/`; samples are `samples/`. Other "
        "reported paths are retained in the combined total. All scopes use "
        "the same third-party, test and performance-code exclusions as HTML.",
        "",
        "These totals include separately compiled first-party C++ libraries. "
        "The denominator is not comparable with older reports that only "
        "instrumented application and test translation units; adding previously "
        "invisible code can reduce the headline percentage. Rust is not "
        "instrumented by these C++ flags.",
        "",
    ]
    return "\n".join(lines)


def instrumentation_failures(files: dict) -> list[str]:
    failures = []
    for filename in INSTRUMENTATION_SENTINELS:
        summary = files.get(filename)
        if summary is None:
            failures.append(f"{filename}: missing from coverage report")
        elif summary["lines"]["count"] == 0 or summary["lines"]["covered"] == 0:
            failures.append(f"{filename}: no covered executable lines")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="llvm-cov JSON export")
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Source directory used for this report (default: repository root)",
    )
    parser.add_argument(
        "--check-instrumentation",
        action="store_true",
        help="Require implementation sentinels to have hits after unit and e2e tests",
    )
    args = parser.parse_args()
    files = coverage_files(
        json.loads(args.report.read_text(encoding="utf-8")), args.source_dir
    )
    print(render_report(files))

    if args.check_instrumentation:
        print("## Instrumentation sentinels\n")
        print("| Source | Covered lines |")
        print("| --- | --- |")
        for filename in INSTRUMENTATION_SENTINELS:
            summary = files.get(filename)
            coverage = format_count(summary["lines"]) if summary else "Missing"
            print(f"| `{filename}` | {coverage} |")
        failures = instrumentation_failures(files)
        if failures:
            for failure in failures:
                print(
                    f"Coverage instrumentation check failed: {failure}", file=sys.stderr
                )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
