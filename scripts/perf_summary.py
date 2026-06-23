# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from typing import List, Optional, Tuple

# Metric to chart over time, with its unit, and how many recent runs to include.
# A chart is produced for every benchmark that reports this metric.
CHART_METRIC = "throughput"
CHART_METRIC_UNIT = "tx/s"
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


def load_perf_data(directory: str, files: List[str]) -> List[Tuple[str, dict]]:
    """Load (label, data) for each readable JSON perf file, preserving order."""
    loaded: List[Tuple[str, dict]] = []
    for name in files:
        try:
            with open(os.path.join(directory, name), "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            loaded.append((run_label(name), data))
    return loaded


def metric_value(data: dict, benchmark: str, metric: str) -> Optional[float]:
    """Return the numeric value of a benchmark metric, or None if absent."""
    metrics = data.get(benchmark)
    if not isinstance(metrics, dict):
        return None
    entry = metrics.get(metric)
    if not isinstance(entry, dict):
        return None
    value = entry.get("value")
    return value if isinstance(value, (int, float)) else None


def benchmarks_with_metric(loaded: List[Tuple[str, dict]], metric: str) -> List[str]:
    """Sorted names of benchmarks that report the given metric in any run."""
    names = set()
    for _, data in loaded:
        for benchmark in data:
            if metric_value(data, benchmark, metric) is not None:
                names.add(benchmark)
    return sorted(names)


def render_mermaid_xychart(
    series: List[Tuple[str, float]], benchmark: str, metric: str, unit: str
) -> str:
    """Render a Mermaid xychart-beta line chart for a single benchmark metric."""
    labels = ", ".join(f'"{label}"' for label, _ in series)
    values = ", ".join(f"{value}" for _, value in series)
    lines = [
        f"### {benchmark}",
        "",
        "```mermaid",
        "xychart-beta",
        f'    title "{benchmark} {metric}"',
        f'    x-axis "run" [{labels}]',
        f'    y-axis "{metric} ({unit})"',
        f"    line [{values}]",
        "```",
        "",
    ]
    return "\n".join(lines)


def render_metric_charts(loaded: List[Tuple[str, dict]], metric: str, unit: str) -> str:
    """Render one chart per benchmark that reports the given metric."""
    benchmarks = benchmarks_with_metric(loaded, metric)
    lines = [f"## {metric.capitalize()} per benchmark ({unit})", ""]
    if not benchmarks:
        lines.append(f"_No benchmarks with a `{metric}` metric found._")
        lines.append("")
        return "\n".join(lines)

    for benchmark in benchmarks:
        series = [
            (label, value)
            for label, data in loaded
            if (value := metric_value(data, benchmark, metric)) is not None
        ]
        lines.append(render_mermaid_xychart(series, benchmark, metric, unit))
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
    loaded = load_perf_data(args.directory, recent)
    print(render_metric_charts(loaded, CHART_METRIC, CHART_METRIC_UNIT))


if __name__ == "__main__":
    sys.exit(main())
