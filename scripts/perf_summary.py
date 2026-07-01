# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json
import argparse
import math
import re
import statistics
from typing import List, Optional, Tuple

# Metric groups to chart over time. A radar chart is produced for every metric,
# with each benchmark as a radar axis.
METRIC_GROUPS = [
    ("throughput", "Throughput", "tx/s"),
    ("latency", "Latency", "ms"),
    ("memory", "Memory", "bytes"),
    ("rate", "Rate", "ops/s"),
]
CHART_MAX_POINTS = 30
EWMA_ALPHA = 0.3
DEFAULT_REPOSITORY = "microsoft/CCF"
METADATA_KEY = "__metadata"
MAX_AXIS_LABEL_LENGTH = 32
SIG_MS_INTERVAL_RE = re.compile(r"\s*\(sig_ms_interval=([^)]+)\)")
RADAR_CONFIG = {
    "width": 620,
    "height": 620,
    "marginTop": 90,
    "marginRight": 220,
    "marginBottom": 120,
    "marginLeft": 220,
    "axisLabelFactor": 1.12,
    "axisScaleFactor": 1.0,
    "axisLabelFontSize": 13,
    "legendFontSize": 13,
    "curveTension": 0.08,
}
RADAR_THEME_CSS = (
    ".radarCurve-0 { fill: #F59E0B !important; fill-opacity: 0.22 !important; "
    "stroke: #F59E0B !important; stroke-opacity: 0.30 !important; stroke-width: 1px !important; }",
    ".radarLegendBox-0 { fill: #F59E0B !important; fill-opacity: 0.22 !important; stroke: #F59E0B !important; }",
    ".radarCurve-1 { fill: #FFFFFF !important; fill-opacity: 0.86 !important; "
    "stroke: #FFFFFF !important; stroke-opacity: 0 !important; stroke-width: 0 !important; }",
    ".radarLegendBox-1 { fill: #FFFFFF !important; fill-opacity: 0.86 !important; stroke: #FFFFFF !important; }",
    ".radarCurve-2 { fill-opacity: 0 !important; stroke: #6B7280 !important; "
    "stroke-width: 2px !important; stroke-dasharray: 6 5; }",
    ".radarLegendBox-2 { fill-opacity: 0 !important; stroke: #6B7280 !important; }",
    ".radarCurve-3 { fill-opacity: 0 !important; stroke: #2563EB !important; stroke-width: 3px !important; }",
    ".radarLegendBox-3 { fill-opacity: 0 !important; stroke: #2563EB !important; }",
    ".radarAxisLine { stroke: #9CA3AF !important; stroke-width: 1px !important; }",
    ".radarGraticule { fill: #F9FAFB !important; fill-opacity: 0.65 !important; "
    "stroke: #E5E7EB !important; stroke-width: 1px !important; }",
    ".radarAxisLabel, .radarLegendText { fill: #374151 !important; color: #374151 !important; "
    "font-family: Arial, sans-serif !important; font-size: 13px !important; }",
    ".radarTitle { fill: #111827 !important; color: #111827 !important; "
    "font-family: Arial, sans-serif !important; font-weight: 600; }",
)

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

    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
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
            loaded.append((run_label(name), run_url(name), commit_url(metadata), data))
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


def ewma(values: List[float], alpha: float = EWMA_ALPHA) -> float:
    """Return the exponentially weighted moving average of the values."""
    average = values[0]
    for value in values[1:]:
        average = alpha * value + (1 - alpha) * average
    return average


def mermaid_label(label: str) -> str:
    """Return a Mermaid label literal."""
    return json.dumps(label)


def axis_label(benchmark: str) -> str:
    """Shorten benchmark labels so Mermaid axes do not overlap or clip."""
    label = SIG_MS_INTERVAL_RE.sub(r" \1", benchmark)
    if len(label) <= MAX_AXIS_LABEL_LENGTH:
        return label
    return f"{label[:MAX_AXIS_LABEL_LENGTH - 3]}..."


def normalized_percent(value: float, baseline: float) -> float:
    """Return value as a percentage of the baseline."""
    return (value / baseline) * 100


def render_mermaid_radar_chart(
    loaded: List[PerfRun], benchmarks: List[str], metric: str, title: str, unit: str
) -> str:
    """Render one Mermaid radar chart for a metric across benchmarks."""
    latest_label, _, _, latest_data = loaded[-1]
    axes = []
    latest_values = []
    ewma_values = []
    low_values = []
    high_values = []

    for index, benchmark in enumerate(benchmarks):
        latest_value = metric_value(latest_data, benchmark, metric)
        if latest_value is None:
            continue

        chronological_values = [
            value
            for _, _, _, data in loaded
            if (value := metric_value(data, benchmark, metric)) is not None
        ]
        if not chronological_values:
            continue

        baseline = ewma(chronological_values)
        if baseline <= 0:
            continue

        sigma = (
            statistics.pstdev(chronological_values)
            if len(chronological_values) > 1
            else 0
        )
        axes.append(f"b{index}[{mermaid_label(axis_label(benchmark))}]")
        latest_values.append(normalized_percent(latest_value, baseline))
        ewma_values.append(100.0)
        low_values.append(max(0.0, normalized_percent(baseline - sigma, baseline)))
        high_values.append(normalized_percent(baseline + sigma, baseline))

    if not axes:
        return f"_No latest-run benchmarks with a `{metric}` metric found._\n"

    chart_max = max(latest_values + ewma_values + low_values + high_values)
    chart_max = max(100, math.ceil(chart_max * 1.1 / 10) * 10)

    lines = [
        "```mermaid",
        "---",
        f"title: {mermaid_label(f'{title} ({unit})')}",
        "config:",
        "  radar:",
        *[f"    {key}: {value}" for key, value in RADAR_CONFIG.items()],
        "  theme: base",
        "  themeCSS: |",
        *[f"    {line}" for line in RADAR_THEME_CSS],
        "  themeVariables:",
        '    cScale0: "#F59E0B"',
        '    cScale1: "#FFFFFF"',
        '    cScale2: "#6B7280"',
        '    cScale3: "#2563EB"',
        "    radar:",
        '      axisColor: "#9CA3AF"',
        '      graticuleColor: "#E5E7EB"',
        "      graticuleOpacity: 0.65",
        "      axisStrokeWidth: 1",
        "      curveOpacity: 0",
        "      curveStrokeWidth: 2",
        "---",
        "radar-beta",
    ]
    lines.extend(f"  axis {axis}" for axis in axes)
    lines.extend(
        [
            render_radar_curve("stddev_high", "EWMA + 1 std dev", high_values),
            render_radar_curve("stddev_low", "EWMA - 1 std dev", low_values),
            render_radar_curve("ewma", "EWMA so far", ewma_values),
            render_radar_curve("latest", latest_label, latest_values),
            "  graticule polygon",
            f"  max {chart_max}",
            "  min 0",
            "  ticks 0",
            "  showLegend false",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def repeated_values_for_radar(values: List[float]) -> str:
    """Render radar curve values."""
    return ", ".join(f"{value:.2f}" for value in values)


def render_radar_curve(curve_id: str, label: str, values: List[float]) -> str:
    """Render a Mermaid radar curve line."""
    rendered_values = repeated_values_for_radar(values)
    return f"  curve {curve_id}[{mermaid_label(label)}]{{{rendered_values}}}"


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
    """Render a radar chart for benchmarks that report the given metric."""
    benchmarks = benchmarks_with_metric(loaded, metric)
    lines = [f"## {title} ({unit})", ""]
    if not benchmarks:
        lines.append(f"_No benchmarks with a `{metric}` metric found._")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "_Values are normalized per benchmark: 100 is the EWMA so far. "
        "For throughput and rate, higher is better; for latency and memory, lower is better. "
        "The amber band shows the EWMA +/- 1 std dev range._"
    )
    lines.append("")
    latest_label = loaded[-1][0]
    lines.extend(
        [
            (
                f"Legend: latest run `{latest_label}` is blue, "
                "EWMA so far is dashed gray, and EWMA +/- 1 std dev is the amber band."
            ),
            "",
        ]
    )
    lines.append(render_mermaid_radar_chart(loaded, benchmarks, metric, title, unit))
    return "\n".join(lines)


def render_perf_summary(loaded: List[PerfRun]) -> str:
    """Render all perf metric groups as markdown."""
    lines = [
        "# Performance summary",
        "",
        "_Each chart compares the latest run with the EWMA so far and a shaded +/-1 std dev range._",
        "",
        render_runs_table(loaded),
    ]
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
