# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json
import argparse
import html
import statistics
from typing import List, NamedTuple, Optional, Tuple

from perf_stats import EWMA_HALF_LIFE, ewma

# Metric groups to chart over time. A chart is produced for every benchmark that
# reports each metric.
METRIC_GROUPS = [
    ("throughput", "Throughput", "tx/s"),
    ("latency", "Latency", "ms"),
    ("memory", "Memory", "bytes"),
    ("rate", "Rate", "ops/s"),
]
CHART_MAX_POINTS = 30
DEFAULT_REPOSITORY = "microsoft/CCF"
METADATA_KEY = "__metadata"

PerfRun = Tuple[str, Optional[str], Optional[str], dict]
ChartSeries = List[Tuple[str, float]]


class MetricSummary(NamedTuple):
    benchmark: str
    metric: str
    unit: str
    latest: float
    baseline: float
    delta_percent: float
    sigma_percent: float


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


def compact_number(value: float) -> str:
    """Format a number compactly for summary tables."""
    abs_value = abs(value)
    if abs_value == 0:
        return "0"
    if abs_value >= 1000:
        return f"{value:,.0f}"
    if abs_value >= 100:
        return f"{value:.0f}"
    if abs_value >= 10:
        return f"{value:.1f}".rstrip("0").rstrip(".")
    if abs_value >= 1:
        return f"{value:.2f}".rstrip("0").rstrip(".")
    return f"{value:.3g}"


def metric_label_value(value: float, unit: str) -> str:
    """Format a metric value with its display unit."""
    if unit != "bytes":
        return f"{compact_number(value)} {unit}"

    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    scaled = value
    unit_index = 0
    while abs(scaled) >= 1024 and unit_index < len(units) - 1:
        scaled /= 1024
        unit_index += 1
    return f"{compact_number(scaled)} {units[unit_index]}"


def metric_summaries(
    loaded: List[PerfRun], metric: str, unit: str
) -> List[MetricSummary]:
    """Summarise one metric in the latest run against its historical baselines."""
    if not loaded:
        return []

    latest_data = loaded[-1][3]
    summaries: List[MetricSummary] = []
    for benchmark in sorted(latest_data):
        if benchmark == METADATA_KEY:
            continue
        latest = metric_value(latest_data, benchmark, metric)
        if latest is None:
            continue

        values = [
            value
            for _, _, _, data in loaded
            if (value := metric_value(data, benchmark, metric)) is not None
        ]
        baseline = ewma(values)
        if baseline <= 0:
            continue

        sigma = statistics.pstdev(values) if len(values) > 1 else 0.0
        summaries.append(
            MetricSummary(
                benchmark,
                metric,
                unit,
                latest,
                baseline,
                ((latest / baseline) - 1) * 100,
                (sigma / baseline) * 100,
            )
        )

    return sorted(
        summaries,
        key=lambda summary: summary.benchmark,
    )


def repeated_values(value: float, count: int) -> str:
    """Render a constant series for every chart category."""
    return ", ".join(f"{value:.2f}" for _ in range(count))


def render_mermaid_xychart(series: ChartSeries, metric: str, unit: str) -> str:
    """Render a Mermaid xychart line chart for a single benchmark metric."""
    ordered_series = list(reversed(series))
    labels = ", ".join(json.dumps(label) for label, _ in ordered_series)
    raw_values = [value for _, value in ordered_series]
    values = ", ".join(f"{value:.2f}" for value in raw_values)
    chronological_values = [value for _, value in series]
    baseline = ewma(chronological_values)
    sigma = (
        statistics.pstdev(chronological_values) if len(chronological_values) > 1 else 0
    )
    lines = [
        "```mermaid",
        "---",
        "config:",
        "    xyChart:",
        "        width: 700",
        "        height: 400",
        "        showTitle: false",
        "        xAxis:",
        "            labelFontSize: 10",
        "            labelRotation: -45",
        "            titleFontSize: 12",
        "        yAxis:",
        "            labelFontSize: 8",
        "            titleFontSize: 12",
        "            showTitle: false",
        "    themeVariables:",
        "        xyChart:",
        '            plotColorPalette: "#003E7E, #62B5E5, #C7E9FB, #C7E9FB"',
        "---",
        "xychart",
        f"    x-axis [{labels}]",
        f'    y-axis "{metric} ({unit})"',
        f"    line [{values}]",
        f"    line [{repeated_values(baseline, len(raw_values))}]",
        f"    line [{repeated_values(baseline - sigma, len(raw_values))}]",
        f"    line [{repeated_values(baseline + sigma, len(raw_values))}]",
        "```",
        "",
    ]
    return "\n".join(lines)


def render_metric_table(loaded: List[PerfRun], summaries: List[MetricSummary]) -> str:
    """Render metric values with each historical chart in a spanning row."""
    lines = [
        '<table width="100%">',
        "<thead>",
        "<tr>",
        "<th>Benchmark</th>",
        "<th>Metric</th>",
        '<th align="right">Latest</th>',
        '<th align="right">EWMA</th>',
        '<th align="right">Change</th>',
        '<th align="right">1 sigma</th>',
        "</tr>",
        "</thead>",
        "<tbody>",
    ]
    for summary in summaries:
        benchmark = html.escape(summary.benchmark)
        series = [
            (label, value)
            for label, _, _, data in loaded
            if (value := metric_value(data, summary.benchmark, summary.metric))
            is not None
        ]
        lines.extend(
            [
                "<tr>",
                f"<td>{benchmark}</td>",
                f"<td>{summary.metric.title()}</td>",
                f'<td align="right">{metric_label_value(summary.latest, summary.unit)}</td>',
                f'<td align="right">{metric_label_value(summary.baseline, summary.unit)}</td>',
                f'<td align="right">{summary.delta_percent:+.1f}%</td>',
                f'<td align="right">{summary.sigma_percent:.1f}%</td>',
                "</tr>",
                "<tr>",
                '<td colspan="6">',
                "<details>",
                "<summary>History</summary>",
                "",
                render_mermaid_xychart(series, summary.metric, summary.unit),
                "</details>",
                "</td>",
                "</tr>",
                "",
            ]
        )
    lines.extend(["</tbody>", "</table>", ""])
    return "\n".join(lines)


def render_runs_table(loaded: List[PerfRun]) -> str:
    """Render a compact table of run labels, Actions runs, and commits."""
    lines = [
        "### Runs",
        "",
        '<table width="100%">',
        "<thead>",
        "<tr>",
        "<th>Run</th>",
        "<th>Actions</th>",
        "<th>Commit</th>",
        "</tr>",
        "</thead>",
        "<tbody>",
    ]
    for label, run, commit, data in reversed(loaded):
        metadata = data.get(METADATA_KEY, {})
        commit_sha = metadata.get("commit") if isinstance(metadata, dict) else None
        short_commit = commit_sha[:8] if isinstance(commit_sha, str) else ""
        run_link = f'<a href="{html.escape(run, quote=True)}">run</a>' if run else ""
        commit_link = (
            f'<a href="{html.escape(commit, quote=True)}">{short_commit}</a>'
            if commit and short_commit
            else ""
        )
        lines.extend(
            [
                "<tr>",
                f"<td>{html.escape(label)}</td>",
                f"<td>{run_link}</td>",
                f"<td>{commit_link}</td>",
                "</tr>",
            ]
        )
    lines.extend(["</tbody>", "</table>", ""])
    return "\n".join(lines)


def render_metric_group(
    loaded: List[PerfRun], metric: str, title: str, unit: str
) -> str:
    """Render the summary and charts for benchmarks that report one metric."""
    summaries = metric_summaries(loaded, metric, unit)
    lines = [f"## {title} ({unit})", ""]
    if not summaries:
        lines.append(f"_No benchmarks with a `{metric}` metric found._")
        lines.append("")
        return "\n".join(lines)

    lines.append(render_metric_table(loaded, summaries))
    return "\n".join(lines)


def render_perf_summary(loaded: List[PerfRun]) -> str:
    """Render all perf metric groups as markdown."""
    lines = [
        "# Performance summary",
        "",
        (
            "_Each section compares its latest values with an EWMA baseline using a "
            f"{EWMA_HALF_LIFE}-run half-life, followed by historical charts with "
            "+/-1 sigma reference lines. One sigma is the population standard "
            "deviation across the displayed runs._"
        ),
        "",
    ]
    for metric, title, unit in METRIC_GROUPS:
        lines.append(render_metric_group(loaded, metric, title, unit))
    lines.append(render_runs_table(loaded))
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
