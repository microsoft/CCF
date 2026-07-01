# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import os
import sys
from typing import Dict, List

from perf_report import METRIC_GROUPS
from perf_report import benchmarks_with_metric, list_perf_files, load_perf_data
from perf_report import render_metric_group
from perf_report import render_runs_table
from perf_report import jobid_sort_key

MAIN_HISTORY_POINTS = 10


def load_bencher_file(filepath: str) -> Dict:
    """Load a bencher.json file."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File {filepath} not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {filepath}")
        sys.exit(1)


def list_pr_files(path: str) -> List[str]:
    """Return one or more PR result files in display order."""
    if os.path.isdir(path):
        files = [
            os.path.join(path, name)
            for name in sorted(os.listdir(path), key=jobid_sort_key)
            if name.endswith(".json") and os.path.isfile(os.path.join(path, name))
        ]
        if files:
            return files
        print(f"Error: No JSON files found in {path}")
        sys.exit(1)

    return [path]


def pr_run_label(label: str, index: int, count: int, separator: bool) -> str:
    text = label if count == 1 else f"{label} {index}"
    return f">> {text}" if separator and index == 1 else text


def render_comparison(main_perf_dir: str, pr_path: str, pr_label: str) -> str:
    """Render PR results as final points after main history."""
    main_files = list_perf_files(main_perf_dir)
    main_runs = load_perf_data(main_perf_dir, main_files)
    pr_files = list_pr_files(pr_path)
    pr_runs = [
        (
            pr_run_label(pr_label, index, len(pr_files), bool(main_runs)),
            None,
            None,
            load_bencher_file(pr_file),
        )
        for index, pr_file in enumerate(pr_files, 1)
    ]
    loaded = [*main_runs, *pr_runs]
    pr_metrics = {
        metric: benchmarks_with_metric(pr_runs, metric)
        for metric, _, _ in METRIC_GROUPS
    }
    if not any(pr_metrics.values()):
        print("Error: No supported metrics found in PR results", file=sys.stderr)
        sys.exit(1)

    main_history = main_runs[-MAIN_HISTORY_POINTS:]
    lines = []
    if main_history:
        lines.append(render_runs_table(main_history))

    lines.extend(
        (
            render_metric_group(
                loaded,
                metric,
                title,
                unit,
                benchmarks=pr_metrics[metric],
                reference_lines=True,
                reference_loaded=main_runs or None,
                reference_limit=MAIN_HISTORY_POINTS,
            )
        )
        for metric, title, unit in METRIC_GROUPS
        if pr_metrics[metric]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create Markdown benchmark plots from main history and PR results."
    )
    parser.add_argument(
        "main_perf_dir", help="Directory containing main perf JSON files"
    )
    parser.add_argument("pr_path", help="PR bencher.json file or directory")
    parser.add_argument("--label2", default="PR", help="Label for PR result")

    args = parser.parse_args()

    print(render_comparison(args.main_perf_dir, args.pr_path, args.label2))


if __name__ == "__main__":
    main()
