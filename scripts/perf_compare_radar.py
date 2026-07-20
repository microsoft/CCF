# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Render Mermaid radar charts comparing a branch's benchmark run against the
recent trend on ``main``.

For each metric, benchmarks form the radar axes. Two nested shaded bands show the
EWMA baseline +/- 1 and +/- 2 standard deviations of the most recent ``main``
runs, and the highlighted curve is the branch's latest run. Values are normalized
per benchmark so that 100 is the ``main`` EWMA baseline.
"""

import os
import json
import argparse
import math
import re
import statistics
from typing import Any

from perf_stats import EWMA_HALF_LIFE, ewma

PerfData = dict[str, Any]

# Metric groups to chart. A radar chart is produced for every metric, with each
# benchmark as a radar axis.
METRIC_GROUPS = [
    ("throughput", "Throughput", "tx/s"),
    ("latency", "Latency", "ms"),
    ("memory", "Memory", "bytes"),
    ("rate", "Rate", "ops/s"),
]
# Metrics for which a higher value is an improvement. The rest (latency, memory)
# are better when lower, which flips the meaning of an increase.
HIGHER_IS_BETTER = {"throughput", "rate"}
# Margin left inside and outside the plotted ring when zooming the radial scale
# to the data: a fraction of the data spread, but at least a few percent so a
# very flat chart still shows a visible ring rather than collapsing to a point.
ZOOM_PAD_FACTOR = 0.35
ZOOM_MIN_PAD = 4.0
# Preferred number of main runs for a stable band. Fewer than this still works,
# but the EWMA baseline and std dev are noted as based on limited data.
MIN_TREND_POINTS = 10
METADATA_KEY = "__metadata"
MAX_AXIS_LABEL_LENGTH = 44
SIG_MS_INTERVAL_RE = re.compile(r"\s*\(sig_ms_interval=([^)]+)\)")
RADAR_CONFIG = {
    "width": 620,
    "height": 620,
    "marginTop": 90,
    "marginRight": 220,
    "marginBottom": 60,
    "marginLeft": 220,
    "axisLabelFactor": 1.12,
    "curveTension": 0.08,
}
# The band is drawn as nested opaque rings using overlaid polygons, from the
# outermost edge inwards: +2 std dev, +1 std dev, -1 std dev, -2 std dev. Each
# fill is the blue tint mixed over the canvas colour, so it stays theme-adaptive
# while remaining opaque. Opaque fills let the darker 1 std dev ring paint
# cleanly on top of the lighter 2 std dev ring, and a final canvas-coloured
# polygon punches out the centre below -2 std dev. The last curve is the branch
# line, drawn on top of both bands.
_CANVAS = "var(--color-canvas-default,var(--bgColor-default,#fff))"
_BLUE = "#62B5E5"
_BAND_1SIGMA = f"color-mix(in srgb, {_BLUE} 40%, {_CANVAS})"
_BAND_2SIGMA = f"color-mix(in srgb, {_BLUE} 13%, {_CANVAS})"
RADAR_THEME_CSS = (
    f".radarCurve-0{{fill:{_BAND_2SIGMA}!important;fill-opacity:1!important;stroke:none!important;stroke-width:0!important}}",
    f".radarCurve-1{{fill:{_BAND_1SIGMA}!important;fill-opacity:1!important;stroke:none!important;stroke-width:0!important}}",
    f".radarCurve-2{{fill:{_BAND_2SIGMA}!important;fill-opacity:1!important;stroke:none!important;stroke-width:0!important}}",
    f".radarCurve-3{{fill:{_CANVAS}!important;fill-opacity:1!important;stroke:none!important;stroke-width:0!important}}",
    ".radarCurve-4{stroke-width:2px!important}",
    ".radarAxisLabel,.radarTitle{fill:var(--color-fg-default,var(--fgColor-default,#111827))!important;color:var(--color-fg-default,var(--fgColor-default,#111827))!important}",
)


def jobid_sort_key(name: str) -> tuple[int, object]:
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


def list_trend_files(directory: str) -> list[str]:
    """Return perf files in the directory, ordered chronologically (oldest first)."""
    if not os.path.isdir(directory):
        return []
    files = [
        name
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    ]
    return sorted(files, key=jobid_sort_key)


def load_json(path: str) -> PerfData | None:
    """Load a JSON object from a file, or None if it cannot be read."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_trend(directory: str) -> list[PerfData]:
    """Load all main runs in chronological order (oldest first)."""
    files = list_trend_files(directory)
    trend: list[PerfData] = []
    for name in files:
        data = load_json(os.path.join(directory, name))
        if data is not None:
            trend.append(data)
    return trend


def metric_value(data: PerfData, benchmark: str, metric: str) -> float | None:
    """Return the numeric value of a benchmark metric, or None if absent."""
    metrics = data.get(benchmark)
    if not isinstance(metrics, dict):
        return None
    entry = metrics.get(metric)
    if not isinstance(entry, dict):
        return None
    value = entry.get("value")
    return value if isinstance(value, (int, float)) else None


def benchmarks_with_metric(runs: list[PerfData], metric: str) -> list[str]:
    """Sorted names of benchmarks that report the given metric in any run."""
    names: set[str] = set()
    for data in runs:
        for benchmark in data:
            if benchmark == METADATA_KEY:
                continue
            if metric_value(data, benchmark, metric) is not None:
                names.add(benchmark)
    return sorted(names)


def mermaid_label(label: str) -> str:
    """Return a Mermaid label literal."""
    return json.dumps(label, ensure_ascii=False)


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


# Solid triangles used as very visible up/down indicators in axis labels. Written
# as escapes so the source stays ASCII while the rendered label shows the glyph.
UP_TRIANGLE = "\u25b2"  # U+25B2 BLACK UP-POINTING TRIANGLE
DOWN_TRIANGLE = "\u25bc"  # U+25BC BLACK DOWN-POINTING TRIANGLE
FLAT_BAR = "\u25ac"  # U+25AC BLACK RECTANGLE


def within_noise_band(percent: float, sigma_percent: float) -> bool:
    """Whether the branch value is within one std dev of the main baseline.

    ``sigma_percent`` is the main run standard deviation expressed as a
    percentage of the baseline. A value that rounds to the baseline (100%) is also
    treated as within noise, so a tiny difference is never flagged as a change
    even when the band is very narrow.
    """
    delta = percent - 100
    return abs(delta) <= sigma_percent or round(delta) == 0


def format_delta_percent(percent: float, within_noise: bool) -> str:
    """Format the branch value as a signed difference from the main baseline (100%).

    A result within one standard deviation of the baseline is treated as noise and
    marked with a flat bar rather than an up or down triangle.
    """
    delta = round(percent - 100)
    if within_noise:
        return f"{FLAT_BAR} {delta:+d}%" if delta else f"{FLAT_BAR} 0%"
    if delta > 0:
        return f"{UP_TRIANGLE} {delta}%"
    if delta < 0:
        return f"{DOWN_TRIANGLE} {abs(delta)}%"
    return f"{FLAT_BAR} 0%"


# Axis label colours by whether the branch improved on, regressed against, or
# matched the main baseline. Chosen to stay legible on both light and dark themes.
LABEL_GOOD = "#2DA44E"  # green: improvement
LABEL_BAD = "#E5484D"  # red: regression
LABEL_FLAT = "#808A94"  # grey: no change


def axis_label_color(percent: float, higher_is_better: bool, within_noise: bool) -> str:
    """Colour an axis label by whether the branch improved on the main baseline.

    Differences within one standard deviation of the baseline are within noise and
    are coloured as unchanged.
    """
    if within_noise:
        return LABEL_FLAT
    improved = (percent > 100) == higher_is_better
    return LABEL_GOOD if improved else LABEL_BAD


def axis_label(
    benchmark: str, value: float, percent: float, unit: str, within_noise: bool
) -> str:
    """Shorten benchmark labels and include the branch real value and delta."""
    label = SIG_MS_INTERVAL_RE.sub(r" \1", benchmark)
    suffix = (
        f": {metric_label_value(value, unit)} "
        f"{format_delta_percent(percent, within_noise)}"
    )
    max_label_length = MAX_AXIS_LABEL_LENGTH - len(suffix)
    if len(label) <= max_label_length:
        return f"{label}{suffix}"
    return f"{label[:max_label_length - 3]}...{suffix}"


def normalized_percent(value: float, baseline: float) -> float:
    """Return value as a percentage of the baseline."""
    return (value / baseline) * 100


def render_radar_curve(curve_id: str, label: str, values: list[float]) -> str:
    """Render a Mermaid radar curve line."""
    rendered_values = ", ".join(f"{value:.2f}" for value in values)
    return f"  curve {curve_id}[{mermaid_label(label)}]{{{rendered_values}}}"


def render_mermaid_radar_chart(
    trend: list[PerfData],
    branch_data: PerfData,
    benchmarks: list[str],
    metric: str,
    unit: str,
    branch_label: str,
) -> str:
    """Render one Mermaid radar chart comparing the branch run with the main trend."""
    higher_better = metric in HIGHER_IS_BETTER
    axes: list[str] = []
    axis_colors: list[str] = []
    branch_values: list[float] = []
    low_values: list[float] = []
    high_values: list[float] = []
    low2_values: list[float] = []
    high2_values: list[float] = []

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

        baseline = ewma(main_values)
        if baseline <= 0:
            continue

        sigma = statistics.pstdev(main_values) if len(main_values) > 1 else 0.0
        branch_percent = normalized_percent(branch_value, baseline)
        sigma_percent = normalized_percent(sigma, baseline)
        within_noise = within_noise_band(branch_percent, sigma_percent)
        axes.append(
            f"b{index}[{mermaid_label(axis_label(benchmark, branch_value, branch_percent, unit, within_noise))}]"
        )
        branch_values.append(branch_percent)
        axis_colors.append(
            axis_label_color(branch_percent, higher_better, within_noise)
        )
        low_values.append(max(0.0, normalized_percent(baseline - sigma, baseline)))
        high_values.append(normalized_percent(baseline + sigma, baseline))
        low2_values.append(max(0.0, normalized_percent(baseline - 2 * sigma, baseline)))
        high2_values.append(normalized_percent(baseline + 2 * sigma, baseline))

    if not axes:
        return (
            f"_No benchmarks with a `{metric}` metric found in both the branch "
            "run and the recent main runs._\n"
        )

    # Zoom the radial scale to the data instead of starting at 0, so the rings
    # fill the chart rather than hugging the outer edge. The margin keeps the
    # innermost ring off the centre and the outermost ring inside the frame.
    data_values = branch_values + low_values + high_values + low2_values + high2_values
    data_low = min(data_values)
    data_high = max(data_values)
    pad = max((data_high - data_low) * ZOOM_PAD_FACTOR, ZOOM_MIN_PAD)
    chart_min = max(0, math.floor(data_low - pad))
    chart_max = math.ceil(data_high + pad)

    # Colour each axis label by improvement or regression. Mermaid renders axis
    # labels as sibling <text> elements in axis order, so nth-of-type targets
    # each one individually.
    label_color_css = [
        f".radarAxisLabel:nth-of-type({position}){{fill:{color}!important}}"
        for position, color in enumerate(axis_colors, start=1)
    ]

    lines = [
        "```mermaid",
        "---",
        "config:",
        "  radar:",
        *[f"    {key}: {value}" for key, value in RADAR_CONFIG.items()],
        "  theme: base",
        "  themeCSS: |",
        *[f"    {line}" for line in RADAR_THEME_CSS],
        *[f"    {line}" for line in label_color_css],
        "  themeVariables:",
        '    cScale0: "#62B5E5"',
        '    cScale1: "#62B5E5"',
        '    cScale2: "#62B5E5"',
        '    cScale3: "#62B5E5"',
        '    cScale4: "#008FD3"',
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
            render_radar_curve("stddev2_high", "main EWMA + 2 std dev", high2_values),
            render_radar_curve("stddev1_high", "main EWMA + 1 std dev", high_values),
            render_radar_curve("stddev1_low", "main EWMA - 1 std dev", low_values),
            render_radar_curve("stddev2_low", "main EWMA - 2 std dev", low2_values),
            render_radar_curve("branch", branch_label, branch_values),
            "  graticule polygon",
            f"  max {chart_max}",
            *([f"  min {chart_min}"] if chart_min > 0 else []),
            "  ticks 0",
            "  showLegend false",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def render_metric_group(
    trend: list[PerfData],
    branch_data: PerfData,
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
        render_mermaid_radar_chart(
            trend, branch_data, benchmarks, metric, unit, branch_label
        )
    )
    return "\n".join(lines)


def render_comparison(
    trend: list[PerfData], branch_data: PerfData, branch_label: str
) -> str:
    """Render all metric groups comparing the branch run with the main trend."""
    lines = [
        "<details>",
        "<summary>Description</summary>",
        "",
        (
            f"_Comparing this branch ({branch_label}) against the trend of the "
            f"last {len(trend)} `main` runs._"
        ),
        "",
        (
            "_Each chart plots every benchmark as an axis, with values normalized so "
            f"100 is the EWMA baseline of recent `main` runs, using a "
            f"{EWMA_HALF_LIFE}-run half-life. The blue line is this branch's latest "
            "run; the darker blue band is the main baseline +/- 1 std dev and the "
            "lighter blue band around it is +/- 2 std dev._"
        ),
        "",
        (
            "_Axis labels show this branch's value and its difference from the main "
            "EWMA baseline, where 0% is on the baseline. They are coloured green "
            "where this branch improves on the baseline, red where it regresses, "
            "and grey where the difference is within one std dev of the baseline "
            "(within noise). "
            "Higher is better for throughput and rate, lower for latency and memory._"
        ),
        "",
        "</details>",
        "",
    ]
    if not trend:
        lines.append("_No recent `main` benchmark runs were found to compare against._")
        lines.append("")
    elif len(trend) < MIN_TREND_POINTS:
        lines.append(
            f"_Only {len(trend)} `main` run(s) were available (fewer than the "
            f"{MIN_TREND_POINTS} preferred for a stable band), so the EWMA baseline "
            "and std dev may not be representative._"
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
    args = parser.parse_args()

    branch_data = load_json(args.branch_file)
    if branch_data is None:
        print(f"_No benchmark data found for the branch at `{args.branch_file}`._")
        return

    trend = load_trend(args.main_directory)
    print(render_comparison(trend, branch_data, args.branch_label))


if __name__ == "__main__":
    main()
