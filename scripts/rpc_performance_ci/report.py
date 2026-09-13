# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Export only diagnostic evidence, never a node workspace or private keys."""

import json
import os
import re
from pathlib import Path

from common import ROOT, measurement_plan, sha256, write_json

PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
ERROR_MARKERS = ("[fail ]", "[fatal]", "Atom leak", "atom leakage")


def safe_copy(source, destination):
    data = source.read_bytes()
    if PRIVATE_KEY.search(data):
        raise RuntimeError(
            f"Refusing to export private key material from {source.name}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def log_summary(source, destination, limit=100):
    contents = source.read_bytes()
    if PRIVATE_KEY.search(contents):
        raise RuntimeError(
            f"Refusing to export private key material from {source.name}"
        )
    lines = contents.decode("utf-8", errors="replace").splitlines()
    errors = [
        {"line": number, "text": line}
        for number, line in enumerate(lines, 1)
        if any(marker in line for marker in ERROR_MARKERS)
    ]
    write_json(
        destination,
        {
            "name": source.name,
            "sha256": sha256(source),
            "line_count": len(lines),
            "unclassified_error_lines": errors,
            "tail": lines[-limit:],
        },
    )


def optional_json(path, missing):
    if not path.exists():
        return missing
    return json.loads(path.read_text())


def main():
    artifacts = Path(os.environ["CCF_RPC_DIAGNOSTIC_ARTIFACTS"]).resolve()
    data, logs = artifacts / "data", artifacts / "logs"
    data.mkdir(parents=True, exist_ok=False)
    logs.mkdir(parents=True, exist_ok=False)
    for name in (
        "build-state.json",
        "build-manifest.json",
        "measurement-state.json",
        "results.json",
        "paired-summary.json",
        "quiet-gate.jsonl",
    ):
        source = ROOT / name
        if source.is_file():
            safe_copy(source, data / name)
    for directory in ("fingerprints", "probes"):
        for source in sorted((ROOT / directory).glob("*.json")):
            safe_copy(source, data / directory / source.name)
    for source in sorted((ROOT / "build-logs").glob("*.log")):
        log_summary(source, logs / "build" / f"{source.stem}.json")
    for run_dir in sorted((ROOT / "runs").glob("*")):
        if not run_dir.is_dir():
            continue
        for name in (
            "command.json",
            "processes.json",
            "process-samples.jsonl",
            "result.json",
        ):
            source = run_dir / name
            if source.is_file():
                safe_copy(source, data / "runs" / run_dir.name / name)
        if (run_dir / "stdout.log").is_file():
            safe_copy(run_dir / "stdout.log", logs / run_dir.name / "stdout.log")
        for pattern in ("locust_*.csv", "*.config.json"):
            for source in sorted((run_dir / "workspace").rglob(pattern)):
                relative = source.relative_to(run_dir / "workspace")
                safe_copy(source, data / "runs" / run_dir.name / "network" / relative)
        for pattern in ("out", "err"):
            for source in sorted((run_dir / "workspace").rglob(pattern)):
                if source.is_file():
                    relative = source.relative_to(run_dir / "workspace")
                    log_summary(
                        source,
                        logs / run_dir.name / "node" / relative.with_suffix(".json"),
                        limit=40,
                    )
    build = optional_json(ROOT / "build-state.json", {"status": "not_started"})
    measurement = optional_json(
        ROOT / "measurement-state.json", {"status": "not_started", "completed_runs": 0}
    )
    comparisons = optional_json(ROOT / "paired-summary.json", [])
    expected = len(measurement_plan())
    success = (
        build["status"] == "complete"
        and measurement["status"] == "complete"
        and measurement["completed_runs"] == expected
        and len(comparisons) == 4
        and all(item["complete"] for item in comparisons)
    )
    summary = [
        "## RPC #8117 isolated diagnostic",
        "",
        (
            f"**Operational success: {'yes' if success else 'no'}.** "
            f"Build: {build['status']}; measurement: {measurement['status']}; "
            f"accepted runs: {measurement['completed_runs']}/{expected}."
        ),
        "",
        "Exact baseline: `31f5f9fe14972cda34f7f44e258557f4dc574b51`.",
        "Exact PR: `1e050d85a9ce04838a0d73e70cb834bf7b2f8f72`.",
        "",
        (
            "**Performance conclusions are not automatic.** Only paired pristine "
            "runs estimate the regression. Cache-only and read-ahead-only runs are "
            "counterfactuals, not presumed fixes. Queue-instrumented throughput must "
            "not be compared with pristine throughput as an estimate of overhead or recovery."
        ),
        "",
        (
            "Raw CSV, process/thread CPU and read/write counters, warm-window gates, "
            "configuration, exact source/patch/compiler/binary fingerprints and "
            "histogram bins are retained. /proc I/O counts are not named syscall "
            "counts; TCP counters and CPU state counters are host-wide."
        ),
        "",
        (
            "Stage timings describe queued tasks/drives, not per-request additive "
            "latency. TLS RX/TX dispatch classification uses absence/presence of "
            "output commands. TLS work is the whole drive, not exclusively crypto. "
            "Long operations crossing a gate boundary are excluded by the probe."
        ),
        "",
        "| Comparison | Signature interval | Complete pairs | Geometric ratio |",
        "| --- | --- | --- | --- |",
    ]
    for item in comparisons:
        ratio = item["geometric_ratio"]
        summary.append(
            f"| {item['comparison']} / {item['baseline']} ({item['category']}) "
            f"| {item['interval_ms']}ms "
            f"| {len(item['pairs'])}/{item['required_pairs']} "
            f"| {ratio:.4f} |"
            if ratio is not None
            else f"| {item['category']} | {item['interval_ms']}ms | 0 | unavailable |"
        )
    for stage, state in (("Build", build), ("Measurement", measurement)):
        if "error" in state:
            summary.extend(["", f"**{stage} blocker:** `{state['error']}`"])
    summary.extend(
        [
            "",
            (
                "Artifacts: `rpc-performance-ci-data` and `rpc-performance-ci-logs` "
                "(7-day retention). No private keys, ledgers, node workspaces, "
                "perf stacks, or unrelated source trees are exported."
            ),
        ]
    )
    text = "\n".join(summary) + "\n"
    write_json(
        data / "operational-summary.json",
        {
            "operational_success": success,
            "expected_runs": expected,
            "build": build,
            "measurement": measurement,
            "performance_conclusion": "Requires analysis of retained paired evidence.",
        },
    )
    (logs / "operational-summary.log").write_text(text, encoding="utf-8")
    inventory = [
        {
            "path": str(path.relative_to(artifacts)),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(artifacts.rglob("*"))
        if path.is_file()
    ]
    write_json(data / "artifact-inventory.json", inventory)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as output:
        output.write(text)
    print(text)


if __name__ == "__main__":
    main()
