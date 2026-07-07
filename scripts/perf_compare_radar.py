# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Render Mermaid radar charts comparing a branch's benchmark run against the
recent trend on ``main``.

For each metric, benchmarks form the radar axes. The shaded band is the median
+/- 1 standard deviation of the most recent ``main`` runs, and the highlighted
curve is the branch's latest run. Values are normalized per benchmark so that
100 is the ``main`` median.
"""

import os
import sys
import json
import argparse
import math
import re
import statistics
from typing import List, Optional, Tuple

# Metric groups to chart. A radar chart is produced for every metric, with each
# benchmark as a radar axis.
METRIC_GROUPS = [
    ("throughput", "Throughput", "tx/s"),
    ("latency", "Latency", "ms"),
    ("memory", "Memory", "bytes"),
    ("rate", "Rate", "ops/s"),
]
TREND_MAX_POINTS = 20
# Preferred number of main runs for a stable band. Fewer than this still works,
# but the median and std dev are noted as based on limited data.
MIN_TREND_POINTS = 10
METADATA_KEY = "__metadata"
MAX_AXIS_LABEL_LENGTH = 44
SIG_MS_INTERVAL_RE = re.compile(r"\s*\(sig_ms_interval=([^)]+)\)")
RADAR_CONFIG = {
    "width": 620,
    "height": 620,
    "marginTop": 90,
    "marginRight": 220,
    "marginBottom": 120,
    "marginLeft": 220,
    "axisLabelFactor": 1.12,
    "curveTension": 0.08,
}
RADAR_THEME_CSS = (
    ".radarCurve-0{fill-opacity:.28!important;stroke:#62B5E5!important;stroke-opacity:.7!important;stroke-width:1px!important}",
    ".radarCurve-1{fill:var(--color-canvas-default,var(--bgColor-default,#fff))!important;fill-opacity:1!important;stroke:#62B5E5!important;stroke-opacity:.7!important;stroke-width:1px!important}",
    ".radarCurve-2{stroke-width:3px!important}",
    ".radarAxisLabel,.radarTitle{fill:var(--color-fg-default,var(--fgColor-default,#111827))!important;color:var(--color-fg-default,var(--fgColor-default,#111827))!important}",
)


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


def list_trend_files(directory: str) -> List[str]:
    """Return perf files in the directory, ordered chronologically (oldest first)."""
    if not os.path.isdir(directory):
        return []
    files = [
        name
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    ]
    return sorted(files, key=jobid_sort_key)


def load_json(path: str) -> Optional[dict]:
    """Load a JSON object from a file, or None if it cannot be read."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_trend(directory: str, max_points: int) -> List[dict]:
    """Load the most recent ``max_points`` main runs (oldest first)."""
    files = list_trend_files(directory)
    files = files[-max_points:] if max_points > 0 else []
    trend: List[dict] = []
    for name in files:
        data = load_json(os.path.join(directory, name))
        if data is not None:
            trend.append(data)
    return trend


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


def benchmarks_with_metric(runs: List[dict], metric: str) -> List[str]:
    """Sorted names of benchmarks that report the given metric in any run."""
    names = set()
    for data in runs:
        for benchmark in data:
            if benchmark == METADATA_KEY:
                continue
            if metric_value(data, benchmark, metric) is not None:
                names.add(benchmark)
    return sorted(names)


def mermaid_label(label: str) -> str:
    """Return a Mermaid label literal."""
    return json.dumps(label)


def compact_number(value: float) -> str:
    """Format a number compactly for chart labels."""
    if not math.isfinite(value):
        return str(value)

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


def compact_bytes(value: float) -> str:
    """Format bytes with binary units for chart labels."""
    if not math.isfinite(value):
        return str(value)

    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    scaled = value
    unit_index = 0
    while abs(scaled) >= 1024 and unit_index < len(units) - 1:
        scaled /= 1024
        unit_index += 1
    return f"{compact_number(scaled)} {units[unit_index]}"


def metric_label_value(value: float, unit: str) -> str:
    """Format a metric value with its real unit for chart labels."""
    if unit == "bytes":
        return compact_bytes(value)
    return f"{compact_number(value)} {unit}"


def axis_label(benchmark: str, value: float, percent: float, unit: str) -> str:
    """Shorten benchmark labels and include the branch real and normalized values."""
    label = SIG_MS_INTERVAL_RE.sub(r" \1", benchmark)
    suffix = f" {metric_label_value(value, unit)} ({percent:.0f}%)"
    max_label_length = MAX_AXIS_LABEL_LENGTH - len(suffix)
    if len(label) <= max_label_length:
        return f"{label}{suffix}"
    return f"{label[:max_label_length - 3]}...{suffix}"


def normalized_percent(value: float, baseline: float) -> float:
    """Return value as a percentage of the baseline."""
    return (value / baseline) * 100


def repeated_values_for_radar(values: List[float]) -> str:
    """Render radar curve values."""
    return ", ".join(f"{value:.2f}" for value in values)


def render_radar_curve(curve_id: str, label: str, values: List[float]) -> str:
    """Render a Mermaid radar curve line."""
    rendered_values = repeated_values_for_radar(values)
    return f"  curve {curve_id}[{mermaid_label(label)}]{{{rendered_values}}}"


def render_mermaid_radar_chart(
    trend: List[dict],
    branch_data: dict,
    benchmarks: List[str],
    metric: str,
    title: str,
    unit: str,
    branch_label: str,
) -> str:
    """Render one Mermaid radar chart comparing the branch run with the main trend."""
    axes = []
    branch_values = []
    low_values = []
    high_values = []

    for index, benchmark in enumerate(benchmarks):
        branch_value = metric_value(branch_data, benchmark, metric)
        if branch_value is None:
            continue

        main_values = [
            value
            for data in trend
            if (value := metric_value(data, benchmark, metric)) is not None
        ]
        if not main_values:
            continue

        baseline = statistics.median(main_values)
        if baseline <= 0:
            continue

        sigma = statistics.pstdev(main_values) if len(main_values) > 1 else 0
        branch_percent = normalized_percent(branch_value, baseline)
        axes.append(
            f"b{index}[{mermaid_label(axis_label(benchmark, branch_value, branch_percent, unit))}]"
        )
        branch_values.append(branch_percent)
        low_values.append(max(0.0, normalized_percent(baseline - sigma, baseline)))
        high_values.append(normalized_percent(baseline + sigma, baseline))

    if not axes:
        return (
            f"_No benchmarks with a `{metric}` metric found in both the branch "
            "run and the recent main runs._\n"
        )

    chart_max = max(branch_values + low_values + high_values + [100.0])
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
        '    cScale0: "#62B5E5"',
        '    cScale1: "#62B5E5"',
        '    cScale2: "#008FD3"',
        "    radar:",
        '      axisColor: "#9CA3AF"',
        '      graticuleColor: "#E5E7EB"',
        "      graticuleOpacity: 0",
        "      axisStrokeWidth: 1",
        "      curveOpacity: 0",
        "---",
        "radar-beta",
    ]
    lines.extend(f"  axis {axis}" for axis in axes)
    lines.extend(
        [
            render_radar_curve("stddev_high", "main median + 1 std dev", high_values),
            render_radar_curve("stddev_low", "main median - 1 std dev", low_values),
            render_radar_curve("branch", branch_label, branch_values),
            "  graticule polygon",
            f"  max {chart_max}",
            "  ticks 0",
            "  showLegend false",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def render_metric_group(
    trend: List[dict],
    branch_data: dict,
    branch_label: str,
    metric: str,
    title: str,
    unit: str,
) -> str:
    """Render a radar chart for benchmarks that report the given metric."""
    benchmarks = benchmarks_with_metric([branch_data, *trend], metric)
    lines = [f"## {title} ({unit})", ""]
    if not benchmarks:
        lines.append(f"_No benchmarks with a `{metric}` metric found._")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "_Values are normalized per benchmark: 100 is the median of recent main runs. "
        "For throughput and rate, higher is better; for latency and memory, lower is better. "
        "The light blue band shows the main median +/- 1 std dev range. "
        "Axis labels show this branch's value as a real number and percentage of the main median._"
    )
    lines.append("")
    lines.extend(
        [
            (
                f"Legend: this branch `{branch_label}` is the blue line, "
                "and the main median +/- 1 std dev is the light blue band."
            ),
            "",
        ]
    )
    lines.append(
        render_mermaid_radar_chart(
            trend, branch_data, benchmarks, metric, title, unit, branch_label
        )
    )
    return "\n".join(lines)


def render_comparison(trend: List[dict], branch_data: dict, branch_label: str) -> str:
    """Render all metric groups comparing the branch run with the main trend."""
    lines = [
        "# Benchmark A/B",
        "",
        (
            f"_Comparing this branch (`{branch_label}`) against the trend of the "
            f"last {len(trend)} `main` runs._"
        ),
        "",
        (
            "_Each chart shades the median +/- 1 std dev on `main` and highlights "
            "this branch's latest run._"
        ),
        "",
    ]
    if not trend:
        lines.append("_No recent `main` benchmark runs were found to compare against._")
        lines.append("")
    elif len(trend) < MIN_TREND_POINTS:
        lines.append(
            f"_Only {len(trend)} `main` run(s) were available (fewer than the "
            f"{MIN_TREND_POINTS} preferred for a stable band), so the median and "
            "std dev may not be representative._"
        )
        lines.append("")
    for metric, title, unit in METRIC_GROUPS:
        lines.append(
            render_metric_group(trend, branch_data, branch_label, metric, title, unit)
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Render radar charts comparing a branch benchmark run against the "
            "recent trend on main, as markdown for a job summary."
        )
    )
    parser.add_argument(
        "main_directory",
        help="Directory containing the recent main perf data files.",
    )
    parser.add_argument(
        "branch_file",
        help="Path to the branch bencher.json file.",
    )
    parser.add_argument(
        "--branch-label",
        default="branch",
        help="Label for the branch curve (default: branch).",
    )
    parser.add_argument(
        "--max-points",
        type=int,
        default=TREND_MAX_POINTS,
        help=f"Number of recent main runs to include (default: {TREND_MAX_POINTS}).",
    )
    args = parser.parse_args()

    branch_data = load_json(args.branch_file)
    if branch_data is None:
        print(f"_No benchmark data found for the branch at `{args.branch_file}`._")
        return

    trend = load_trend(args.main_directory, args.max_points)
    print(render_comparison(trend, branch_data, args.branch_label))


if __name__ == "__main__":
    sys.exit(main())
