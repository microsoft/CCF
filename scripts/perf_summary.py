# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from typing import List, Tuple

# Benchmark metric to chart over time. Start with a single series for now; this
# can be extended to cover more benchmarks or metrics later.
CHART_BENCHMARK = "Basic"
CHART_METRIC = "throughput"
CHART_MAX_POINTS = 10


def jobid_sort_key(name: str) -> Tuple[int, object]:
    """Order perf files chronologically by their numeric job id.

    File names have the form ``<run_id>-<run_number>-<run_attempt>.json`` where
    each component increases over time, so ordering by the integer components
    gives chronological order. Falls back to the name for unexpected formats.
    """
    stem = name[:-5] if name.endswith(".json") else name
    try:
        return (0, tuple(int(part) for part in stem.split("-")))
    except ValueError:
        return (1, name)


def list_perf_files(directory: str) -> List[str]:
    """Return perf files in the directory, ordered chronologically (oldest first)."""
    if not os.path.isdir(directory):
        return []
    files = [
        name
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    ]
    return sorted(files, key=jobid_sort_key)


def render_markdown_table(directory: str, files: List[str]) -> str:
    """Render a markdown table listing the files available in the directory."""
    lines = [f"## Perf data files in `{directory}`", ""]

    if not files:
        lines.append("_No perf data files found._")
        lines.append("")
        return "\n".join(lines)

    lines.append("| File | Size (bytes) | Modified (UTC) |")
    lines.append("| --- | --- | --- |")
    for name in files:
        path = os.path.join(directory, name)
        size = os.path.getsize(path)
        modified = datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"| {name} | {size} | {modified} |")

    lines.append("")
    lines.append(f"Total: {len(files)} file(s)")
    lines.append("")
    return "\n".join(lines)


def run_label(name: str) -> str:
    """Short x-axis label for a perf file: the run number when available."""
    stem = name[:-5] if name.endswith(".json") else name
    parts = stem.split("-")
    return parts[1] if len(parts) >= 2 else stem


def extract_metric_series(
    directory: str, files: List[str], benchmark: str, metric: str
) -> List[Tuple[str, float]]:
    """Extract (label, value) points for a benchmark metric from the given files."""
    series: List[Tuple[str, float]] = []
    for name in files:
        try:
            with open(os.path.join(directory, name), "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        value = data.get(benchmark, {}).get(metric, {}).get("value")
        if isinstance(value, (int, float)):
            series.append((run_label(name), value))
    return series


def render_mermaid_xychart(
    series: List[Tuple[str, float]], benchmark: str, metric: str
) -> str:
    """Render a Mermaid xychart-beta line chart of a metric over time."""
    if not series:
        return (
            f"## `{benchmark}` {metric}\n\n"
            f"_No `{metric}` data found for benchmark `{benchmark}`._\n"
        )

    labels = ", ".join(f'"{label}"' for label, _ in series)
    values = ", ".join(f"{value}" for _, value in series)
    lines = [
        f"## `{benchmark}` {metric} over the last {len(series)} run(s)",
        "",
        "```mermaid",
        "xychart-beta",
        f'    title "{benchmark} {metric}"',
        f'    x-axis "run" [{labels}]',
        f'    y-axis "{metric}"',
        f"    line [{values}]",
        "```",
        "",
    ]
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
    args = parser.parse_args()

    files = list_perf_files(args.directory)
    print(render_markdown_table(args.directory, files))

    recent = files[-CHART_MAX_POINTS:]
    series = extract_metric_series(
        args.directory, recent, CHART_BENCHMARK, CHART_METRIC
    )
    print(render_mermaid_xychart(series, CHART_BENCHMARK, CHART_METRIC))


if __name__ == "__main__":
    sys.exit(main())
