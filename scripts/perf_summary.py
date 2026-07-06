# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import os
import sys
from typing import List

from perf_report import CHART_MAX_POINTS, METRIC_GROUPS
from perf_report import METADATA_KEY
from perf_report import PerfRun
from perf_report import commit_url, run_url
from perf_report import benchmarks_with_metric, jobid_sort_key
from perf_report import list_perf_files, load_bencher_file, load_perf_data
from perf_report import render_metric_group, render_runs_table
from perf_report import render_perf_summary

MAIN_HISTORY_POINTS = 10


def comparison_sort_key(name: str) -> tuple:
    stem = name[:-5] if name.endswith(".json") else name
    index = stem.rsplit("-", 1)[-1]
    return (0, int(index)) if index.isdigit() else jobid_sort_key(name)


def list_comparison_files(path: str) -> List[str]:
    if os.path.isdir(path):
        files = [
            os.path.join(path, name)
            for name in sorted(os.listdir(path), key=comparison_sort_key)
            if name.endswith(".json") and os.path.isfile(os.path.join(path, name))
        ]
        if files:
            return files
        raise FileNotFoundError(f"No JSON files found in {path}")
    return [path]


def load_comparison_data(path: str, label: str) -> List[PerfRun]:
    files = list_comparison_files(path)
    count = len(files)
    runs = []
    for index, file_path in enumerate(files, 1):
        data = load_bencher_file(file_path)
        metadata = data.get(METADATA_KEY, {})
        if not isinstance(metadata, dict):
            metadata = {}
        run_id = metadata.get("run_id")
        run_label = label if count == 1 else f"{label} {index}"
        run = run_url(f"{run_id}.json") if isinstance(run_id, str) else None
        runs.append((run_label, run, commit_url(metadata), data))
    return runs


def render_comparison(main_runs: List[PerfRun], comparison_runs: List[PerfRun]) -> str:
    main_history = main_runs[-MAIN_HISTORY_POINTS:]
    loaded = [*main_history, *comparison_runs]
    comparison_benchmarks = {
        metric: benchmarks_with_metric(comparison_runs, metric)
        for metric, _, _ in METRIC_GROUPS
    }
    if not any(comparison_benchmarks.values()):
        raise ValueError("No supported metrics found in comparison results")

    lines = [
        "# Performance summary",
        "",
        "_Each chart shows run values, an EWMA baseline, and +/-1 sigma reference lines._",
        "",
        render_runs_table(loaded),
    ]
    for metric, title, unit in METRIC_GROUPS:
        benchmarks = comparison_benchmarks[metric]
        if not benchmarks:
            continue
        lines.append(
            render_metric_group(
                loaded,
                metric,
                title,
                unit,
                benchmarks=benchmarks,
                reference_loaded=main_history if main_history else None,
            )
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarise perf data files as markdown for a job summary."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="perf",
        help="Directory containing the perf data files (default: perf)",
    )
    parser.add_argument(
        "--compare",
        help="PR bencher JSON file or directory to append after main history",
    )
    parser.add_argument(
        "--label",
        default="PR",
        help="Label for comparison results (default: PR)",
    )
    args = parser.parse_args()

    files = list_perf_files(args.directory)
    recent = files[-CHART_MAX_POINTS:]
    main_runs = load_perf_data(args.directory, recent)
    if args.compare:
        try:
            comparison_runs = load_comparison_data(args.compare, args.label)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        print(render_comparison(main_runs, comparison_runs))
    else:
        print(render_perf_summary(main_runs))


if __name__ == "__main__":
    sys.exit(main())
