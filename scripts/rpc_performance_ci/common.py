# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Fixed inputs and fingerprints for the temporary PR #8117 diagnostic."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ["CCF_RPC_DIAGNOSTIC_ROOT"]).resolve()
REVISIONS = {
    "base": "31f5f9fe14972cda34f7f44e258557f4dc574b51",
    "pr": "1e050d85a9ce04838a0d73e70cb834bf7b2f8f72",
}
SOURCES = {name: ROOT / "sources" / name for name in REVISIONS}
VENV = SOURCES["base"] / "build" / "env"
DRIVER = SOURCES["base"] / "tests" / "basicperf_locust.py"
VARIANTS = {
    "base": ("base", "basic", None),
    "pr": ("pr", "basic", None),
    "base_queue": ("base", "basic_queue_probe", "queue_base.patch"),
    "pr_queue": ("pr", "basic_queue_probe", "queue_pr.patch"),
    "pr_cached": ("pr", "basic_poll_cached", "poll_interest_cache.patch"),
    "pr_read_ahead": ("pr", "basic_read_ahead", "read_ahead.patch"),
}
BUILD_OPTIONS = {
    "CMAKE_BUILD_TYPE": "RelWithDebInfo",
    "WORKER_THREADS": "2",
    "CCF_ENABLE_RELEASE_HARDENING": "ON",
    "SAN": "OFF",
    "TSAN": "OFF",
    "COVERAGE": "OFF",
    "FUZZING": "OFF",
    "CLANG_TIDY": "OFF",
    "GLIBCXX_DEBUG": "OFF",
    "VERBOSE_LOGGING": "OFF",
    "USE_SNMALLOC": "ON",
}
MEASURE_SECONDS = 20
MAX_EXTERNAL_CORES = 0.3
SHARED_STAGES = {"rx_queue", "rx_work", "commit_wait", "send_queue", "send_work"}
PR_STAGES = {
    "tls_rx_queue",
    "tls_tx_queue",
    "tls_work",
    "out_loop_wait",
    "completion_loop_wait",
    "loop_drain_work",
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path):
    with path.open("rb") as contents:
        return hashlib.file_digest(contents, "sha256").hexdigest()


def git(source, *arguments):
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={source}", "-C", str(source), *arguments],
        text=True,
    ).strip()


def assert_clean(source):
    status = git(source, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise RuntimeError(f"Source is not pristine: {source}\n{status}")


def binary_path(variant):
    source, executable, _ = VARIANTS[variant]
    return SOURCES[source] / "build" / "samples" / "apps" / "basic" / executable


def client_fingerprint():
    source = SOURCES["base"]
    files = git(
        source,
        "ls-files",
        "tests",
        "python",
        "samples/constitutions/default",
    ).splitlines()
    hashes = {name: sha256(source / name) for name in files}
    digest = hashlib.sha256(
        json.dumps(hashes, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {"sha256": digest, "files": hashes}


def measurement_plan():
    plan = []

    def append(category, pair, interval, variants):
        for variant in variants:
            plan.append(
                {
                    "category": category,
                    "pair": pair,
                    "interval_ms": interval,
                    "variant": variant,
                }
            )

    for pair in range(3):
        intervals = [2, 20] if pair == 0 else [20, 2] if pair == 1 else [2]
        for interval in intervals:
            append(
                "pristine",
                pair,
                interval,
                ["base", "pr"] if pair % 2 == 0 else ["pr", "base"],
            )
    for pair in range(2):
        append(
            "cache",
            pair,
            2,
            ["pr", "pr_cached"] if pair % 2 == 0 else ["pr_cached", "pr"],
        )
    for pair in range(2):
        append(
            "read_ahead",
            pair,
            2,
            ["pr", "pr_read_ahead"] if pair % 2 == 0 else ["pr_read_ahead", "pr"],
        )
    append("queue", 0, 2, ["base_queue", "pr_queue"])
    append("queue", 0, 20, ["pr_queue", "base_queue"])
    return plan
