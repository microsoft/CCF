# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raft-driver", required=True)
    parser.add_argument("--tla-dir", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    args = parser.parse_args()

    output_dir = args.output_dir
    shutil.rmtree(output_dir, ignore_errors=True)
    trace_dir = (output_dir / "traces").resolve()
    seed_dir = (output_dir / "seeds").resolve()
    trace_dir.mkdir(parents=True)
    seed_dir.mkdir()

    repo = pathlib.Path(__file__).parents[1]
    scenario = repo / "tests" / "raft_scenarios" / "marked_startup"
    run(
        sys.executable,
        str(repo / "tests" / "raft_scenarios_runner.py"),
        args.raft_driver,
        str(scenario),
        "--output",
        str(trace_dir),
    )

    trace = trace_dir / "marked_startup.ndjson"
    markers = [
        json.loads(line)
        for line in trace.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("msg", {}).get("function") == "mark_seed"
    ]
    assert [marker["msg"]["name"] for marker in markers] == ["after_signature"]

    tla_dir = args.tla_dir.resolve()
    run(
        str(tla_dir / "tlc.py"),
        "--workers",
        "1",
        "tv",
        "--disable-dfs",
        "--ccf-raft-trace",
        str(trace),
        "--seed-output-dir",
        str(seed_dir),
        "consensus/Traceccfraft.tla",
        cwd=tla_dir,
    )

    seed_module = seed_dir / "RaftSeeds.tla"
    text = seed_module.read_text(encoding="utf-8")
    assert "MODULE RaftSeeds" in text
    assert '/\\ seedId = "marked_startup_after_signature"' in text
    assert "/\\ currentTerm =" in text
    assert "/\\ log =" in text


if __name__ == "__main__":
    main()
