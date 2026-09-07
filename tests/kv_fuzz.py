# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run bounded concurrent KV operation campaigns against the Lean trace model."""

import argparse
import json
import math
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import kv_trace_validation as trace

CASE = "KV trace concurrent operation fuzzer"
MAX_SEED = 2**64 - 1
MAX_WORK = 65536
REQUIRED_COUNTERS = (
    "get",
    "has",
    "get_global",
    "has_global",
    "previous_write",
    "put",
    "remove",
    "clear",
    "size",
    "foreach",
    "foreach_key",
    "foreach_value",
    "nested_foreach",
    "callback_write",
    "alias",
    "read_only",
    "abandon",
    "commit_success",
    "commit_conflict",
    "commit_no_replicate",
    "compact",
    "rollback",
    "rollback_rejected",
    "snapshot_unavailable",
    "same_value_write",
    "remove_missing",
    "empty_key",
    "binary_value",
    "worker_operations",
    "worker_transactions",
    "worker_commit_success",
    "max_live_workers",
)
REQUIRED_EVENTS = (
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
)
REQUIRED_OBSERVATIONS = (
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
)


@dataclass(frozen=True)
class Workload:
    threads: int = 4
    transactions: int = 24
    operations: int = 8

    def validate(self):
        for name, value, maximum in (
            ("threads", self.threads, 16),
            ("transactions", self.transactions, 256),
            ("operations", self.operations, 32),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in [1, {maximum}]")
        if self.threads * self.transactions * self.operations > MAX_WORK:
            raise ValueError(f"The worker operation budget must not exceed {MAX_WORK}")

    def environment(self, seed):
        self.validate()
        validate_seed_range(seed, 1)
        return {
            "CCF_KV_FUZZ_SEED": str(seed),
            "CCF_KV_FUZZ_THREADS": str(self.threads),
            "CCF_KV_FUZZ_TRANSACTIONS": str(self.transactions),
            "CCF_KV_FUZZ_OPERATIONS": str(self.operations),
        }


def validate_seed_range(first, count):
    if type(first) is not int or not 0 <= first <= MAX_SEED:
        raise ValueError("seed-start must be an unsigned 64-bit integer")
    if type(count) is not int or not 1 <= count <= 256:
        raise ValueError("seeds must be an integer in [1, 256]")
    if first + count - 1 > MAX_SEED:
        raise ValueError("The requested seed range exceeds uint64")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate metadata key: {key}")
        result[key] = value
    return result


def metadata_lines(lines):
    records = {}
    for line in lines:
        for prefix in ("KV_FUZZ_RECIPE", "KV_FUZZ_COVERAGE"):
            marker = prefix + " "
            if line.startswith(marker):
                if prefix in records:
                    raise ValueError(f"Duplicate {prefix} record")
                value = json.loads(line[len(marker) :], object_pairs_hook=unique_object)
                if not isinstance(value, dict):
                    raise ValueError(f"{prefix} must be a JSON object")
                records[prefix] = value
    if set(records) != {"KV_FUZZ_RECIPE", "KV_FUZZ_COVERAGE"}:
        raise ValueError("Missing fuzzer recipe or completed coverage record")
    return records["KV_FUZZ_RECIPE"], records["KV_FUZZ_COVERAGE"]


def validate_metadata(recipe, counters, seed, workload):
    expected = {
        "version": 1,
        "seed": str(seed),
        "threads": workload.threads,
        "transactions": workload.transactions,
        "operations": workload.operations,
    }
    for name, value in expected.items():
        if type(recipe.get(name)) is not type(value) or recipe[name] != value:
            raise ValueError(f"Fuzzer recipe does not match requested {name}")
    for name in ("maps", "keys"):
        if type(recipe.get(name)) is not int or not 2 <= recipe[name] <= 128:
            raise ValueError(f"Invalid bounded fuzzer {name} count")
    for name, value in counters.items():
        if type(value) is not int or value < 0:
            raise ValueError(f"Invalid coverage counter: {name}")
    missing = [name for name in REQUIRED_COUNTERS if counters.get(name, 0) <= 0]
    if missing:
        raise ValueError(f"Required fuzzer behaviors were not exercised: {missing}")
    live = counters["max_live_workers"]
    if not 1 <= live <= workload.threads or (workload.threads > 1 and live < 2):
        raise ValueError("The requested worker concurrency was not observed")


def event_coverage(path):
    counts = Counter()
    with path.open(encoding="utf-8") as source:
        for line in source:
            event = json.loads(line)
            kind = event["type"]
            counts[kind] += 1
            if kind in {"get", "get_global", "previous_write"}:
                presence = "absent" if event["value"] is None else "present"
                counts[f"{kind}:{presence}"] += 1
            elif kind == "commit_result":
                counts[f"{kind}:{event['result']}"] += 1
            elif kind == "foreach_continue" and event["value"] is False:
                counts["foreach_continue:false"] += 1
            elif kind == "put":
                if event["key"] == "":
                    counts["put:empty_key"] += 1
                if event["value"] == "":
                    counts["put:empty_value"] += 1
    missing = [
        name for name in (*REQUIRED_EVENTS, *REQUIRED_OBSERVATIONS) if counts[name] == 0
    ]
    if missing:
        raise ValueError(
            f"Required behavior is absent from the actual trace: {missing}"
        )
    return dict(counts)


def run_seed(binary, checker, directory, seed, workload, timeout):
    record = trace.run_case(
        binary,
        checker,
        CASE,
        directory,
        timeout,
        extra_env=workload.environment(seed),
    )
    record["seed"] = str(seed)
    try:
        with (directory / "test.stdout.txt").open(encoding="utf-8") as source:
            recipe, counters = metadata_lines(source)
        record["recipe"] = recipe
        record["coverage"] = counters
        validate_metadata(recipe, counters, seed, workload)
        if record["status"] == "accepted":
            record["trace_events"] = event_coverage(directory / record["trace"])
    except (OSError, ValueError) as error:
        record["coverage_error"] = str(error)
        if record["status"] == "accepted":
            record["status"] = "coverage_incomplete"
    return record


def run(args):
    workload = Workload(args.threads, args.transactions, args.operations)
    workload.validate()
    validate_seed_range(args.seed_start, args.seeds)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    binary = args.binary.resolve(strict=True)
    checker = args.checker.resolve(strict=True)
    if CASE not in trace.inventory(binary, args.timeout):
        raise ValueError(f"The KV binary does not contain {CASE!r}")
    args.output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="campaign-", dir=args.output.resolve()))
    report_path = directory / "report.json"
    report = {
        "schema": 1,
        "state": "incomplete",
        "case": CASE,
        "seed_start": str(args.seed_start),
        "requested_seeds": args.seeds,
        "keep_going": args.keep_going,
        "workload": {
            "threads": workload.threads,
            "transactions": workload.transactions,
            "operations": workload.operations,
        },
        "binary_sha256": trace.digest(binary),
        "checker_sha256": trace.digest(checker),
        "schedule": "Seed fixes program choices; the trace records the observed schedule.",
        "cases": [],
    }
    try:
        for index in range(args.seeds):
            seed = args.seed_start + index
            seed_dir = directory / f"seed-{index:04}"
            seed_dir.mkdir()
            report["cases"].append(
                {
                    "seed": str(seed),
                    "directory": seed_dir.name,
                    "status": "capture_incomplete",
                }
            )
            try:
                report["cases"][-1] = run_seed(
                    binary, checker, seed_dir, seed, workload, args.timeout
                )
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                report["cases"][-1]["message"] = str(error)
            report_path.write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            if report["cases"][-1]["status"] != "accepted" and not args.keep_going:
                break
        report["state"] = (
            "complete" if len(report["cases"]) == args.seeds else "stopped"
        )
        result = trace.outcome(report["cases"], True, explicit_selection=True)
        report["exit_code"] = result
        report["accepted_seeds"] = sum(
            case["status"] == "accepted" for case in report["cases"]
        )
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "report": str(report_path),
                "accepted": report["accepted_seeds"],
                "total": len(report["cases"]),
                "requested": args.seeds,
                "state": report["state"],
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
    parser.add_argument("--seed-start", type=int, default=0)
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--transactions", type=int, default=24)
    parser.add_argument("--operations", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument(
        "--keep-going", action="store_true", help="Continue after a non-passing seed"
    )
    return run(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
