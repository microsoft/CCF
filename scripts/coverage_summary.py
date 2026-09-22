# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Render line and branch coverage trend charts for the coverage job summary.

The coverage workflow writes an llvm-cov report to its job summary (and, via
``tee``, to the job logs). GitHub does not expose an API to download a job
summary directly, so the trend is reconstructed from the logs of previous
Coverage runs on the same branch, which contain the same report. This script
extracts the overall line and branch coverage percentages from each of those
reports and renders Mermaid xychart trend charts, including the current run.

It also aggregates the per-file rows of the current report by source area
(directory) and lists the files with the most uncovered lines, so that the job
summary shows where coverage is missing and which areas moved since the
previous run.
"""

import argparse
import math
import os
import re
import sys
from typing import Dict, List, NamedTuple, Optional, Tuple

# Number of previous runs to include in the trend, in addition to the current
# run. Overridable via the environment so the coverage workflow can keep this in
# sync with the number of previous-run logs it downloads.
HISTORY_POINTS: int = int(os.environ.get("COVERAGE_HISTORY_POINTS") or 9)
DEFAULT_REPOSITORY = "microsoft/CCF"

# The llvm-cov ``report`` TOTAL line lists, for each of Regions, Functions,
# Lines and Branches, a count, a missed count and a coverage percentage, e.g.:
#   TOTAL  123860 19651 84.13%  4579 1274 72.18%  84414 26245 68.91%  ...
# Line coverage is therefore the third percentage on the line, and branch
# coverage the fourth.
_PERCENT_RE = re.compile(r"(\d+(?:\.\d+)?)%")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Optional leading ISO-8601 timestamp, as prefixed to each GitHub Actions log
# line (e.g. "2026-07-07T18:12:43.968Z ").
_TIMESTAMP_RE = re.compile(r"^\S+T\S+Z\s+")
_LINE_COVERAGE_INDEX = 2
_BRANCH_COVERAGE_INDEX = 3

# Per-file rows of the llvm-cov ``report`` have the same shape as the TOTAL
# line, prefixed with the file path:
#   src/kv/store.h  1046 216 79.35%  85 3 96.47%  1046 216 79.35%  322 102 68.32%
# Token indices of the line and branch counts within such a row.
_FILE_ROW_TOKENS = 13
_FILE_ROW_TOKENS_NO_BRANCHES = 10
_LINES_INDEX = 7
_MISSED_LINES_INDEX = 8
_BRANCHES_INDEX = 10
_MISSED_BRANCHES_INDEX = 11

# Number of leading path components used to group files into areas, e.g.
# ``src/node/rpc`` or ``include/ccf/ds``.
_AREA_DEPTH = 3
# Number of files listed in the "most uncovered lines" table.
_TOP_FILES = 15

# Plot colours for the trend charts: bright green for line coverage, bright
# blue for branch coverage.
_LINE_COVERAGE_COLOR = "#00ff00"
_BRANCH_COVERAGE_COLOR = "#0000ff"


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

    Rows are recognised by their shape rather than by position, as the report
    is embedded in a job log alongside other output. Files without branch
    columns are recorded with zero branches.
    """
    files: List[FileCoverage] = []
    for line in text.splitlines():
        tokens: List[str] = _clean_line(line).split()
        if len(tokens) not in (_FILE_ROW_TOKENS, _FILE_ROW_TOKENS_NO_BRANCHES):
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
            branches: int = 0
            missed_branches: int = 0
            if len(tokens) == _FILE_ROW_TOKENS:
                branches = int(tokens[_BRANCHES_INDEX])
                missed_branches = int(tokens[_MISSED_BRANCHES_INDEX])
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
    """Return (run_id, label) parsed from a ``<run_id>-<run_number>.log`` name."""
    stem: str = name[:-4] if name.endswith(".log") else name
    run_id, _, run_number = stem.partition("-")
    if not run_id.isdigit():
        return None
    label: str = run_number if run_number else run_id
    return int(run_id), label


def load_history(directory: str) -> List[CoveragePoint]:
    """Load coverage points from previous-run log files in a directory."""
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


def latest_history_path(directory: str) -> Optional[str]:
    """Return the previous-run log with the highest run id, if any."""
    latest: Optional[Tuple[int, str]] = None
    if not os.path.isdir(directory):
        return None
    for name in os.listdir(directory):
        path: str = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        parsed: Optional[Tuple[int, str]] = _parse_history_name(name)
        if parsed is None:
            continue
        if latest is None or parsed[0] > latest[0]:
            latest = (parsed[0], path)
    return latest[1] if latest is not None else None


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
    """Return (min, max) y-axis bounds framing the given coverage values."""
    lowest: float = min(values)
    highest: float = max(values)
    axis_min: float = max(0.0, math.floor(lowest - 1))
    axis_max: float = min(100.0, math.ceil(highest + 1))
    if axis_min >= axis_max:
        axis_min = max(0.0, axis_max - 1)
    return axis_min, axis_max


def _render_chart(
    title: str, color: str, labels: List[str], values: List[float]
) -> List[str]:
    """Render a single Mermaid xychart line plot in the given colour."""
    joined_labels: str = ", ".join(f'"{label}"' for label in labels)
    joined_values: str = ", ".join(f"{value:.2f}" for value in values)
    axis_min, axis_max = _axis_bounds(values)
    # Mermaid draws xychart plots using the colours in ``xyChart.plotColorPalette``;
    # set it so the single line is drawn in the requested colour.
    init_directive: str = (
        '%%{init: {"themeVariables": {"xyChart": '
        '{"plotColorPalette": "' + color + '"}}}}%%'
    )
    return [
        "```mermaid",
        init_directive,
        "xychart-beta",
        f'    title "{title}"',
        f"    x-axis [{joined_labels}]",
        f'    y-axis "{title}" {axis_min:g} --> {axis_max:g}',
        f"    line [{joined_values}]",
        "```",
        "",
    ]


def render_trend(points: List[CoveragePoint]) -> str:
    """Render line and branch coverage trend charts and a runs table."""
    line_labels: List[str] = [point.label for point in points]
    line_values: List[float] = [point.line_coverage for point in points]

    branch_labels: List[str] = []
    branch_values: List[float] = []
    for point in points:
        if point.branch_coverage is not None:
            branch_labels.append(point.label)
            branch_values.append(point.branch_coverage)

    lines: List[str] = ["## Line coverage trend", ""]
    lines += _render_chart(
        "Line coverage (%)", _LINE_COVERAGE_COLOR, line_labels, line_values
    )
    if branch_values:
        lines += ["## Branch coverage trend", ""]
        lines += _render_chart(
            "Branch coverage (%)",
            _BRANCH_COVERAGE_COLOR,
            branch_labels,
            branch_values,
        )

    lines += ["| Run | Line coverage | Branch coverage |", "| --- | --- | --- |"]
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
    """Order history chronologically, keep the most recent, append current."""
    ordered: List[CoveragePoint] = sorted(history, key=lambda point: point.run_id)
    if current is not None:
        ordered = [point for point in ordered if point.run_id != current.run_id]
    ordered = ordered[-HISTORY_POINTS:]
    if current is not None:
        ordered.append(current)
    return ordered


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
        description="Render line and branch coverage trend charts for the job summary."
    )
    parser.add_argument(
        "report",
        help="Path to the current run's llvm-cov coverage report (text).",
    )
    parser.add_argument(
        "history",
        nargs="?",
        default="coverage_history",
        help="Directory of previous-run log files (default: coverage_history).",
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

    previous_areas: Optional[List[AreaCoverage]] = None
    previous_path: Optional[str] = latest_history_path(args.history)
    if previous_path is not None:
        previous_text: Optional[str] = _read_text(previous_path)
        if previous_text is not None:
            previous_files: List[FileCoverage] = extract_file_coverage(previous_text)
            if previous_files:
                previous_areas = aggregate_by_area(previous_files)

    print(render_areas(aggregate_by_area(files), previous_areas))
    print(render_top_files(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
