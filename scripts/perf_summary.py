# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json
import argparse
import html
from typing import List, Optional, Tuple

# Metric groups to chart over time. A chart is produced for every benchmark that
# reports each metric.
METRIC_GROUPS = [
    ("throughput", "Throughput", "tx/s"),
    ("latency", "Latency", "ms"),
    ("memory", "Memory", "bytes"),
    ("rate", "Rate", "ops/s"),
]
CHART_MAX_POINTS = 30
CHART_COLUMNS = 3
DEFAULT_REPOSITORY = "microsoft/CCF"
METADATA_KEY = "__metadata"

PerfRun = Tuple[str, Optional[str], Optional[str], dict]


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


def run_label(name: str) -> str:
    """Short x-axis label for a perf file: the run number when available."""
    stem = name[:-5] if name.endswith(".json") else name
    parts = stem.split("-")
    return parts[1] if len(parts) >= 2 else stem


def run_url(name: str) -> Optional[str]:
    """GitHub Actions URL for a perf file, when the run id can be parsed."""
    stem = name[:-5] if name.endswith(".json") else name
    parts = stem.split("-")
    if not parts or not parts[0].isdigit():
        return None

    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip(
        "/"
    )
    repository = os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY)
    return f"{server_url}/{repository}/actions/runs/{parts[0]}"


def commit_url(metadata: dict) -> Optional[str]:
    """GitHub commit URL from perf metadata, when available."""
    commit = metadata.get("commit")
    if not isinstance(commit, str) or not commit:
        return None

    server_url = metadata.get("server_url") or os.environ.get(
        "GITHUB_SERVER_URL", "https://github.com"
    )
    repository = metadata.get("repository") or os.environ.get(
        "GITHUB_REPOSITORY", DEFAULT_REPOSITORY
    )
    if not isinstance(server_url, str) or not isinstance(repository, str):
        return None
    return f"{server_url.rstrip('/')}/{repository}/commit/{commit}"


def load_perf_data(directory: str, files: List[str]) -> List[PerfRun]:
    """Load (label, run_url, commit_url, data) for each readable perf file."""
    loaded: List[PerfRun] = []
    for name in files:
        try:
            with open(os.path.join(directory, name), "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            metadata = data.get(METADATA_KEY, {})
            if not isinstance(metadata, dict):
                metadata = {}
            loaded.append(
                (run_label(name), run_url(name), commit_url(metadata), data)
            )
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


def benchmarks_with_metric(loaded: List[PerfRun], metric: str) -> List[str]:
    """Sorted names of benchmarks that report the given metric in any run."""
    names = set()
    for _, _, _, data in loaded:
        for benchmark in data:
            if benchmark == METADATA_KEY:
                continue
            if metric_value(data, benchmark, metric) is not None:
                names.add(benchmark)
    return sorted(names)


def render_mermaid_xychart(
    series: List[Tuple[str, Optional[str], Optional[str], float]],
    benchmark: str,
    metric: str,
    unit: str,
) -> str:
    """Render a Mermaid xychart line chart for a single benchmark metric."""
    ordered_series = list(reversed(series))
    labels = ", ".join(f'"{label}"' for label, _, _, _ in ordered_series)
    raw_values = [value for _, _, _, value in ordered_series]
    values = ", ".join(f"{value:.2f}" for value in raw_values)
    lines = [
        f"<h4>{html.escape(benchmark)}</h4>",
        "",
        "```mermaid",
        "---",
        "config:",
        "    xyChart:",
        "        width: 300",
        "        height: 320",
        "        showTitle: false",
        "        xAxis:",
        "            labelFontSize: 10",
        "            titleFontSize: 12",
        "        yAxis:",
        "            labelFontSize: 8",
        "            titleFontSize: 12",
        "            showTitle: false",
        "    themeVariables:",
        "        xyChart:",
        "            plotColorPalette: \"#107C10\"",
        "---",
        "xychart horizontal",
        f"    x-axis [{labels}]",
        f'    y-axis "{metric} ({unit})"',
        f"    line [{values}]",
        "```",
        "",
    ]
    return "\n".join(lines)


def render_chart_table(
    loaded: List[PerfRun], benchmarks: List[str], metric: str, unit: str
) -> str:
    """Render benchmark charts in a three-column table."""
    lines = ['<table width="100%">']
    for index, benchmark in enumerate(benchmarks):
        if index % CHART_COLUMNS == 0:
            lines.append("<tr>")
        lines.append('<td valign="top" width="33%">')
        series = [
            (label, run, commit, value)
            for label, run, commit, data in loaded
            if (value := metric_value(data, benchmark, metric)) is not None
        ]
        lines.append(render_mermaid_xychart(series, benchmark, metric, unit))
        lines.append("</td>")
        if index % CHART_COLUMNS == CHART_COLUMNS - 1:
            lines.append("</tr>")
    remaining = len(benchmarks) % CHART_COLUMNS
    if remaining:
        for _ in range(CHART_COLUMNS - remaining):
            lines.append('<td valign="top" width="33%"></td>')
        lines.append("</tr>")
    lines.append("</table>")
    lines.append("")
    return "\n".join(lines)


def run_links(label: str, run: Optional[str], commit: Optional[str]) -> str:
    """Markdown links for a chart point's Actions run and commit."""
    if run and commit:
        return f"[{label}]({run}) ([commit]({commit}))"
    if run:
        return f"[{label}]({run})"
    if commit:
        return f"{label} ([commit]({commit}))"
    return label


def render_runs_table(loaded: List[PerfRun]) -> str:
    """Render a compact table of run labels, Actions runs, and commits."""
    lines = ["### Runs", "", "| Run | Actions | Commit |", "| --- | --- | --- |"]
    for label, run, commit, data in reversed(loaded):
        metadata = data.get(METADATA_KEY, {})
        commit_sha = metadata.get("commit") if isinstance(metadata, dict) else None
        short_commit = commit_sha[:8] if isinstance(commit_sha, str) else ""
        run_link = f"[run]({run})" if run else ""
        commit_link = f"[{short_commit}]({commit})" if commit and short_commit else ""
        lines.append(f"| {label} | {run_link} | {commit_link} |")
    lines.append("")
    return "\n".join(lines)


def render_metric_group(
    loaded: List[PerfRun], metric: str, title: str, unit: str
) -> str:
    """Render one chart per benchmark that reports the given metric."""
    benchmarks = benchmarks_with_metric(loaded, metric)
    lines = [f"## {title} ({unit})", ""]
    if not benchmarks:
        lines.append(f"_No benchmarks with a `{metric}` metric found._")
        lines.append("")
        return "\n".join(lines)

    lines.append(render_chart_table(loaded, benchmarks, metric, unit))
    return "\n".join(lines)


def render_perf_summary(loaded: List[PerfRun]) -> str:
    """Render all perf metric groups as markdown."""
    lines = ["# Performance summary", "", render_runs_table(loaded)]
    for metric, title, unit in METRIC_GROUPS:
        lines.append(render_metric_group(loaded, metric, title, unit))
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

    recent = files[-CHART_MAX_POINTS:]
    loaded = load_perf_data(args.directory, recent)
    print(render_perf_summary(loaded))


if __name__ == "__main__":
    sys.exit(main())
