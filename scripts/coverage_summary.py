# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Render a combined coverage trend chart for the coverage job summary.

The coverage workflow stores llvm-cov reports in a per-branch artifact. This
script extracts the overall line and branch coverage percentages from the
previous reports and renders a Mermaid xychart with line and branch coverage
on the same percentage scale, including the current run.

It also aggregates the per-file rows of the current report by source area
(directory) and lists the files with the most uncovered lines, so that the job
summary shows where coverage is missing and which areas moved since the
previous run.
"""

import argparse
import json
import math
import os
import re
import sys
from typing import Dict, List, NamedTuple, Optional, Tuple

# Maximum number of runs to include in the trend, including the current run.
# Overridable via the environment to match the workflow's artifact retention.
HISTORY_POINTS: int = int(os.environ.get("COVERAGE_HISTORY_POINTS") or 30)
DEFAULT_REPOSITORY = "microsoft/CCF"

# The llvm-cov ``report`` TOTAL line lists, for each of Regions, Functions,
# Lines and Branches, a count, a missed count and a coverage percentage, e.g.:
#   TOTAL  123860 19651 84.13%  4579 1274 72.18%  84414 26245 68.91%  ...
# Line coverage is therefore the third percentage on the line, and branch
# coverage the fourth.
_PERCENT_RE = re.compile(r"(\d+(?:\.\d+)?)%")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Optional leading ISO-8601 timestamp on lines from older job logs.
_TIMESTAMP_RE = re.compile(r"^\S+T\S+Z\s+")
_LINE_COVERAGE_INDEX = 2
_BRANCH_COVERAGE_INDEX = 3

# Per-file rows of the llvm-cov ``report`` have the same shape as the TOTAL
# line, prefixed with the file path:
#   src/kv/store.h  1046 216 79.35%  85 3 96.47%  1046 216 79.35%  322 102 68.32%
# Token indices of the line and branch counts within such a row.
_FILE_ROW_TOKENS = 13
_LINES_INDEX = 7
_MISSED_LINES_INDEX = 8
_BRANCHES_INDEX = 10
_MISSED_BRANCHES_INDEX = 11

# Number of leading path components used to group files into areas, e.g.
# ``src/node/rpc`` or ``include/ccf/ds``.
_AREA_DEPTH = 3
# Number of files listed in the "most uncovered lines" table.
_TOP_FILES = 5

_LINE_COVERAGE_COLOR = "#333333"
_BRANCH_COVERAGE_COLOR = "#4c78a8"


class CoveragePoint(NamedTuple):
    run_id: int
    label: str
    line_coverage: float
    branch_coverage: Optional[float]


class FileCoverage(NamedTuple):
    path: str
    lines: int
    missed_lines: int
    branches: int
    missed_branches: int


class AreaCoverage(NamedTuple):
    area: str
    lines: int
    missed_lines: int
    branches: int
    missed_branches: int

    @property
    def line_coverage(self) -> Optional[float]:
        return _percentage(self.lines, self.missed_lines)

    @property
    def branch_coverage(self) -> Optional[float]:
        return _percentage(self.branches, self.missed_branches)


def _percentage(total: int, missed: int) -> Optional[float]:
    if total == 0:
        return None
    return 100.0 * (total - missed) / total


def _clean_line(line: str) -> str:
    stripped: str = _ANSI_RE.sub("", line)
    return _TIMESTAMP_RE.sub("", stripped).strip()


def extract_coverage(text: str) -> Optional[Tuple[float, Optional[float]]]:
    """Return the (line, branch) coverage percentages from an llvm-cov report.

    Branch coverage is ``None`` when the report does not include a branch
    column.
    """
    for line in text.splitlines():
        stripped: str = _clean_line(line)
        if not stripped.startswith("TOTAL"):
            continue
        percentages: List[str] = _PERCENT_RE.findall(stripped)
        if len(percentages) > _LINE_COVERAGE_INDEX:
            line_coverage: float = float(percentages[_LINE_COVERAGE_INDEX])
            branch_coverage: Optional[float] = None
            if len(percentages) > _BRANCH_COVERAGE_INDEX:
                branch_coverage = float(percentages[_BRANCH_COVERAGE_INDEX])
            return line_coverage, branch_coverage
    return None


def extract_file_coverage(text: str) -> List[FileCoverage]:
    """Return the per-file line and branch counts from an llvm-cov report.

    Rows are recognised by their shape rather than by position.
    """
    files: List[FileCoverage] = []
    for line in text.splitlines():
        tokens: List[str] = _clean_line(line).split()
        if len(tokens) != _FILE_ROW_TOKENS:
            continue
        path: str = tokens[0]
        if "/" not in path or path == "TOTAL":
            continue
        counts: List[str] = tokens[1:]
        if not all(
            token.isdigit() or token.endswith("%") or token == "-" for token in counts
        ):
            continue
        try:
            lines: int = int(tokens[_LINES_INDEX])
            missed_lines: int = int(tokens[_MISSED_LINES_INDEX])
            branches: int = int(tokens[_BRANCHES_INDEX])
            missed_branches: int = int(tokens[_MISSED_BRANCHES_INDEX])
        except ValueError:
            continue
        files.append(FileCoverage(path, lines, missed_lines, branches, missed_branches))
    return files


def area_of(path: str) -> str:
    """Return the area (leading directory components) a file belongs to."""
    directory: List[str] = path.split("/")[:-1]
    return "/".join(directory[:_AREA_DEPTH]) or "."


def aggregate_by_area(files: List[FileCoverage]) -> List[AreaCoverage]:
    """Sum per-file counts by area, most missed lines first."""
    totals: Dict[str, List[int]] = {}
    for entry in files:
        counts: List[int] = totals.setdefault(area_of(entry.path), [0, 0, 0, 0])
        counts[0] += entry.lines
        counts[1] += entry.missed_lines
        counts[2] += entry.branches
        counts[3] += entry.missed_branches
    areas: List[AreaCoverage] = [
        AreaCoverage(area, *counts) for area, counts in totals.items()
    ]
    areas.sort(key=lambda area: (-area.missed_lines, area.area))
    return areas


def _format_percentage(value: Optional[float]) -> str:
    return f"{value:.2f}%" if value is not None else "-"


def _format_delta(current: Optional[float], previous: Optional[float]) -> str:
    if current is None or previous is None:
        return "-"
    return f"{current - previous:+.2f}"


def render_areas(
    current: List[AreaCoverage], previous: Optional[List[AreaCoverage]]
) -> str:
    """Render a per-area table, with changes relative to the previous run."""
    previous_by_area: Dict[str, AreaCoverage] = {
        area.area: area for area in (previous or [])
    }
    lines: List[str] = [
        "## Coverage by area",
        "",
        (
            "Sorted by uncovered lines. Changes are in percentage points relative "
            "to the previous run on this branch."
        ),
        "",
        (
            "| Area | Lines | Missed | Line coverage | Change "
            "| Branches | Missed | Branch coverage | Change |"
        ),
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for area in current:
        before: Optional[AreaCoverage] = previous_by_area.get(area.area)
        lines.append(
            f"| `{area.area}` | {area.lines} | {area.missed_lines} "
            f"| {_format_percentage(area.line_coverage)} "
            f"| {_format_delta(area.line_coverage, before.line_coverage if before else None)} "
            f"| {area.branches} | {area.missed_branches} "
            f"| {_format_percentage(area.branch_coverage)} "
            f"| {_format_delta(area.branch_coverage, before.branch_coverage if before else None)} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_top_files(files: List[FileCoverage]) -> str:
    """Render the files with the most uncovered lines."""
    ranked: List[FileCoverage] = sorted(
        files, key=lambda entry: (-entry.missed_lines, entry.path)
    )[:_TOP_FILES]
    lines: List[str] = [
        f"## Files with most uncovered lines (top {len(ranked)})",
        "",
        "| File | Lines | Missed | Line coverage | Branch coverage |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for entry in ranked:
        lines.append(
            f"| `{entry.path}` | {entry.lines} | {entry.missed_lines} "
            f"| {_format_percentage(_percentage(entry.lines, entry.missed_lines))} "
            f"| {_format_percentage(_percentage(entry.branches, entry.missed_branches))} |"
        )
    lines.append("")
    return "\n".join(lines)


def _parse_history_name(name: str) -> Optional[Tuple[int, str]]:
    """Return (run_id, label) from a ``<run_id>-<run_number>.txt`` name."""
    match: Optional[re.Match[str]] = re.fullmatch(r"(\d+)-(\d+)\.txt", name)
    if match is None:
        return None
    return int(match.group(1)), match.group(2)


def load_history(directory: str) -> List[CoveragePoint]:
    """Load coverage points from previous-run reports in a directory."""
    points: List[CoveragePoint] = []
    if not os.path.isdir(directory):
        return points
    for name in os.listdir(directory):
        path: str = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        parsed: Optional[Tuple[int, str]] = _parse_history_name(name)
        if parsed is None:
            continue
        run_id, label = parsed
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                coverage: Optional[Tuple[float, Optional[float]]] = extract_coverage(
                    f.read()
                )
        except OSError:
            continue
        if coverage is not None:
            line_coverage, branch_coverage = coverage
            points.append(CoveragePoint(run_id, label, line_coverage, branch_coverage))
    return points


def previous_file_coverage(directory: str) -> List[FileCoverage]:
    """Return the per-file rows of the most recent complete previous report.

    The most recent report may be empty or truncated. Reports are tried from
    the highest run id down, and the first with per-file rows and a TOTAL line
    (which llvm-cov prints after them) is used.
    """
    candidates: List[Tuple[int, str]] = []
    if not os.path.isdir(directory):
        return []
    for name in os.listdir(directory):
        path: str = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        parsed: Optional[Tuple[int, str]] = _parse_history_name(name)
        if parsed is not None:
            candidates.append((parsed[0], path))
    for _, path in sorted(candidates, reverse=True):
        text: Optional[str] = _read_text(path)
        if text is None or extract_coverage(text) is None:
            continue
        files: List[FileCoverage] = extract_file_coverage(text)
        if files:
            return files
    return []


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def run_url(run_id: int) -> str:
    server_url: str = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip(
        "/"
    )
    repository: str = os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY)
    return f"{server_url}/{repository}/actions/runs/{run_id}"


def _axis_bounds(values: List[float]) -> Tuple[float, float]:
    """Frame both series with bounds rounded out to five percentage points."""
    lowest: float = min(values)
    highest: float = max(values)
    axis_min: float = max(0.0, 5 * math.floor((lowest - 1) / 5))
    axis_max: float = min(100.0, 5 * math.ceil((highest + 1) / 5))
    return axis_min, axis_max


def _render_chart(
    labels: List[str], line_values: List[float], branch_values: List[float]
) -> List[str]:
    """Render aligned coverage series with restrained, GitHub-safe styling."""
    if len(line_values) != len(labels) or (
        branch_values and len(branch_values) != len(labels)
    ):
        raise ValueError("Coverage series must have one value per run label")
    joined_labels: str = ", ".join(f'"{label}"' for label in labels)
    axis_min, axis_max = _axis_bounds(line_values + branch_values)
    axis_config: Dict[str, object] = {
        "showAxisLine": False,
        "showTick": False,
        "labelFontSize": 12,
        "titleFontSize": 14,
    }
    config: Dict[str, object] = {
        "theme": "base",
        "fontFamily": "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
        # Inset axes and plots together, leaving the white background unchanged.
        "themeCSS": (
            ".main .plot, .main .bottom-axis, .main .left-axis "
            "{ transform: translate(10px, 20px) scale(0.93); } "
            ".plot .line-plot-1 .labels text "
            "{ text-anchor: end; translate: -20px 20px; }"
        ),
        "xyChart": {
            "width": 700,
            "height": 300,
            "showTitle": False,
            "xAxis": axis_config,
            "yAxis": axis_config,
        },
        "themeVariables": {
            "xyChart": {
                "backgroundColor": "#ffffff",
                "xAxisLabelColor": "#666666",
                "xAxisTitleColor": "#666666",
                "yAxisLabelColor": "#666666",
                "yAxisTitleColor": "#666666",
                "plotColorPalette": (
                    f"{_LINE_COVERAGE_COLOR}, {_BRANCH_COVERAGE_COLOR}"
                ),
            },
        },
    }
    lines: List[str] = [
        "```mermaid",
        "%%{init: " + json.dumps(config, separators=(",", ":")) + "}%%",
        "xychart-beta",
        "    accTitle: Coverage trend",
        (
            "    accDescr: Line coverage is charcoal; branch coverage is blue "
            "when available. Both use the same percentage scale. "
            "Exact values and run links are in the table below."
        ),
        f'    x-axis "Run" [{joined_labels}]',
        f'    y-axis "Coverage (%)" {axis_min:g} --> {axis_max:g}',
    ]
    for name, values in (("Line", line_values), ("Branch", branch_values)):
        if values:
            rendered_values: List[str] = [f"{value:.2f}" for value in values]
            rendered_values[-1] += f' "{name}"'
            joined_values: str = ", ".join(rendered_values)
            lines.append(f"    line [{joined_values}]")
    return lines + ["```", ""]


def render_trend(points: List[CoveragePoint]) -> str:
    """Render a shared-scale trend chart and a complete, newest-first table."""
    if not points:
        return ""

    latest: CoveragePoint = points[-1]
    caption: str = f"Latest run: **{latest.line_coverage:.2f}% line coverage**."
    if latest.branch_coverage is not None:
        caption += f" **{latest.branch_coverage:.2f}% branch coverage**."
    else:
        caption += " Branch coverage was not reported."
    lines: List[str] = ["## Coverage trend", "", caption, ""]

    paired: List[CoveragePoint] = [
        point for point in points if point.branch_coverage is not None
    ]
    chart_points: List[CoveragePoint] = paired if paired else points
    omitted: int = len(points) - len(chart_points)
    if omitted:
        lines += [
            (
                f"The chart omits {omitted} "
                f"run{'s' if omitted != 1 else ''} without branch coverage; "
                "all runs remain in the table."
            ),
            "",
        ]
    if len(chart_points) > 1:
        lines += _render_chart(
            [point.label for point in chart_points],
            [point.line_coverage for point in chart_points],
            [
                point.branch_coverage
                for point in chart_points
                if point.branch_coverage is not None
            ],
        )
    else:
        lines += ["At least two comparable runs are needed for a trend chart.", ""]

    lines += ["| Run | Line coverage | Branch coverage |", "| --- | ---: | ---: |"]
    for point in reversed(points):
        branch: str = (
            f"{point.branch_coverage:.2f}%"
            if point.branch_coverage is not None
            else "-"
        )
        lines.append(
            f"| [{point.label}]({run_url(point.run_id)}) "
            f"| {point.line_coverage:.2f}% | {branch} |"
        )
    lines.append("")
    return "\n".join(lines)


def build_points(
    history: List[CoveragePoint], current: Optional[CoveragePoint]
) -> List[CoveragePoint]:
    """Order history chronologically and keep the latest runs, including current."""
    ordered: List[CoveragePoint] = sorted(history, key=lambda point: point.run_id)
    if current is not None:
        ordered = [point for point in ordered if point.run_id != current.run_id]
        ordered.append(current)
    return ordered[-HISTORY_POINTS:]


def current_point(report_path: str) -> Optional[CoveragePoint]:
    try:
        with open(report_path, "r", encoding="utf-8", errors="replace") as f:
            coverage: Optional[Tuple[float, Optional[float]]] = extract_coverage(
                f.read()
            )
    except OSError:
        return None
    if coverage is None:
        return None
    line_coverage, branch_coverage = coverage
    run_id: int = int(os.environ.get("GITHUB_RUN_ID") or 0)
    label: str = os.environ.get("GITHUB_RUN_NUMBER") or str(run_id)
    return CoveragePoint(run_id, label, line_coverage, branch_coverage)


def main() -> int:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Render a combined coverage trend chart for the job summary."
    )
    parser.add_argument(
        "report",
        help="Path to the current run's llvm-cov coverage report (text).",
    )
    parser.add_argument(
        "history",
        nargs="?",
        default="coverage_history",
        help="Directory of previous-run reports (default: coverage_history).",
    )
    args: argparse.Namespace = parser.parse_args()

    current: Optional[CoveragePoint] = current_point(args.report)
    history: List[CoveragePoint] = load_history(args.history)
    points: List[CoveragePoint] = build_points(history, current)

    if points:
        print(render_trend(points))

    report_text: Optional[str] = _read_text(args.report)
    if report_text is None:
        return 0
    files: List[FileCoverage] = extract_file_coverage(report_text)
    if not files:
        return 0

    previous_files: List[FileCoverage] = previous_file_coverage(args.history)
    previous_areas: Optional[List[AreaCoverage]] = (
        aggregate_by_area(previous_files) if previous_files else None
    )

    print(render_areas(aggregate_by_area(files), previous_areas))
    print(render_top_files(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
