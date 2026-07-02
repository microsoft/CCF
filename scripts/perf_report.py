# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import html
import json
import os
import statistics
from typing import List, Optional, Tuple

METRIC_GROUPS = [
    ("throughput", "Throughput", "tx/s"),
    ("latency", "Latency", "ms"),
    ("memory", "Memory", "bytes"),
    ("rate", "Rate", "ops/s"),
]
CHART_MAX_POINTS = 30
CHART_COLUMNS = 3
CHART_WIDTH = 1100
CHART_HEIGHT = 560
CHART_CELL_WIDTH = str(CHART_WIDTH)
EWMA_ALPHA = 0.3
DEFAULT_REPOSITORY = "microsoft/CCF"
METADATA_KEY = "__metadata"

PerfRun = Tuple[str, Optional[str], Optional[str], dict]
ChartSeries = List[Tuple[str, float]]


def jobid_sort_key(name: str) -> Tuple[int, object]:
    """Order perf files chronologically by their numeric job id."""
    stem = name[:-5] if name.endswith(".json") else name
    try:
        return (0, tuple(int(part) for part in stem.split("-")))
    except ValueError:
        return (1, name)


def list_perf_files(directory: str) -> List[str]:
    """Return perf files in the directory, ordered chronologically."""
    if not os.path.isdir(directory):
        return []
    files = [
        name
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    ]
    return sorted(files, key=jobid_sort_key)


def run_label(name: str) -> str:
    """Short x-axis label for a perf file."""
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
    if isinstance(entry, dict):
        value = entry.get("value")
    else:
        value = entry
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


def repeated_values(value: float, count: int) -> str:
    """Render a constant series for every chart category."""
    return ", ".join(f"{value:.2f}" for _ in range(count))


def chart_scale(values: List[float], unit: str) -> Tuple[float, str]:
    """Scale large chart values to keep axis labels readable."""
    if values and max(abs(value) for value in values) >= 1000:
        return 1000, f"K {unit}"
    return 1, unit


def mermaid_string(value: str) -> str:
    """Render a Mermaid string literal."""
    return json.dumps(value, ensure_ascii=True)


def render_mermaid_xychart(
    series: ChartSeries,
    benchmark: str,
    metric: str,
    unit: str,
    *,
    reverse_series: bool = False,
    reference_lines: bool = True,
    reference_series: Optional[ChartSeries] = None,
) -> str:
    """Render a Mermaid xychart line chart for a single benchmark metric."""
    ordered_series = list(reversed(series)) if reverse_series else list(series)
    labels = ", ".join(mermaid_string(label) for label, _ in ordered_series)
    raw_values = [value for _, value in ordered_series]
    values_for_scale = list(raw_values)
    baseline = None
    sigma = None
    if reference_lines:
        reference_values = [
            value for _, value in (reference_series if reference_series else series)
        ]
        baseline = ewma(reference_values)
        sigma = statistics.pstdev(reference_values) if len(reference_values) > 1 else 0
        values_for_scale.extend([baseline, baseline - sigma, baseline + sigma])
    scale, chart_unit = chart_scale(values_for_scale, unit)
    values = ", ".join(f"{value / scale:.2f}" for value in raw_values)
    lines = [
        f"<h4>{html.escape(benchmark)}</h4>",
        "",
        "```mermaid",
        "---",
        "config:",
        "    xyChart:",
        f"        width: {CHART_WIDTH}",
        f"        height: {CHART_HEIGHT}",
        "        showTitle: false",
        "        xAxis:",
        "            labelFontSize: 24",
        "            titleFontSize: 28",
        "        yAxis:",
        "            labelFontSize: 22",
        "            titleFontSize: 28",
        "            showTitle: false",
        "    themeVariables:",
        "        xyChart:",
        '            plotColorPalette: "#003E7E, #62B5E5, #C7E9FB, #C7E9FB"',
        "---",
        "xychart",
        f"    x-axis [{labels}]",
        f'    y-axis "{metric} ({chart_unit})"',
        f"    line [{values}]",
    ]
    if reference_lines:
        assert baseline is not None
        assert sigma is not None
        lines.extend(
            [
                f"    line [{repeated_values(baseline / scale, len(raw_values))}]",
                f"    line [{repeated_values((baseline - sigma) / scale, len(raw_values))}]",
                f"    line [{repeated_values((baseline + sigma) / scale, len(raw_values))}]",
            ]
        )
    lines.extend(["```", ""])
    return "\n".join(lines)


def render_chart_table(
    loaded: List[PerfRun],
    benchmarks: List[str],
    metric: str,
    unit: str,
    *,
    reverse_series: bool = False,
    reference_lines: bool = True,
    reference_loaded: Optional[List[PerfRun]] = None,
    reference_limit: Optional[int] = None,
) -> str:
    """Render benchmark charts in a table."""
    lines = ["<table>"]
    for index, benchmark in enumerate(benchmarks):
        if index % CHART_COLUMNS == 0:
            lines.append("<tr>")
        lines.append(f'<td valign="top" width="{CHART_CELL_WIDTH}">')
        reference_series = None
        chart_reference_lines = reference_lines
        if reference_loaded is not None:
            limited_reference_series = [
                (label, value)
                for label, _, _, data in reference_loaded
                if (value := metric_value(data, benchmark, metric)) is not None
            ]
            if reference_limit is not None:
                limited_reference_series = limited_reference_series[-reference_limit:]
            if limited_reference_series:
                reference_series = limited_reference_series
            else:
                chart_reference_lines = False
            series = [
                *limited_reference_series,
                *[
                    (label, value)
                    for label, _, _, data in loaded[len(reference_loaded) :]
                    if (value := metric_value(data, benchmark, metric)) is not None
                ],
            ]
        else:
            series = [
                (label, value)
                for label, _, _, data in loaded
                if (value := metric_value(data, benchmark, metric)) is not None
            ]
        lines.append(
            render_mermaid_xychart(
                series,
                benchmark,
                metric,
                unit,
                reverse_series=reverse_series,
                reference_lines=chart_reference_lines,
                reference_series=reference_series,
            )
        )
        lines.append("</td>")
        if index % CHART_COLUMNS == CHART_COLUMNS - 1:
            lines.append("</tr>")
            lines.append(f'<tr><td colspan="{CHART_COLUMNS}"><br><br></td></tr>')
    remaining = len(benchmarks) % CHART_COLUMNS
    if remaining:
        for _ in range(CHART_COLUMNS - remaining):
            lines.append(f'<td valign="top" width="{CHART_CELL_WIDTH}"></td>')
        lines.append("</tr>")
    lines.append("</table>")
    lines.append("")
    return "\n".join(lines)


def render_runs_table(loaded: List[PerfRun]) -> str:
    """Render a compact x-axis label to commit map."""
    labels = [label for label, _, _, _ in loaded]
    commit_links = []
    for _, _, commit, data in loaded:
        metadata = data.get(METADATA_KEY, {})
        commit_sha = metadata.get("commit") if isinstance(metadata, dict) else None
        short_commit = commit_sha[:8] if isinstance(commit_sha, str) else ""
        commit_links.append(
            f"[{short_commit}]({commit})" if commit and short_commit else short_commit
        )

    if not labels:
        return ""

    return "\n".join(
        [
            "### Commits",
            "",
            f"| Seq | {' | '.join(labels)} |",
            f"| --- | {' | '.join('---' for _ in labels)} |",
            f"| Commit | {' | '.join(commit_links)} |",
            "",
        ]
    )


def render_metric_group(
    loaded: List[PerfRun],
    metric: str,
    title: str,
    unit: str,
    *,
    benchmarks: Optional[List[str]] = None,
    reverse_series: bool = False,
    reference_lines: bool = True,
    reference_loaded: Optional[List[PerfRun]] = None,
    reference_limit: Optional[int] = None,
) -> str:
    """Render one chart per benchmark that reports the given metric."""
    benchmarks = (
        benchmarks if benchmarks is not None else benchmarks_with_metric(loaded, metric)
    )
    lines = [f"## {title} ({unit})", ""]
    if not benchmarks:
        lines.append(f"_No benchmarks with a `{metric}` metric found._")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        render_chart_table(
            loaded,
            benchmarks,
            metric,
            unit,
            reverse_series=reverse_series,
            reference_lines=reference_lines,
            reference_loaded=reference_loaded,
            reference_limit=reference_limit,
        )
    )
    return "\n".join(lines)


def render_perf_summary(loaded: List[PerfRun]) -> str:
    """Render all perf metric groups as markdown."""
    lines = [
        "# Performance summary",
        "",
        "_Each chart shows run values, an EWMA baseline, and +/-1 sigma reference lines._",
        "",
        render_runs_table(loaded),
    ]
    for metric, title, unit in METRIC_GROUPS:
        lines.append(render_metric_group(loaded, metric, title, unit))
    return "\n".join(lines)
