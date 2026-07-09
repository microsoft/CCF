# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Render line and branch coverage trend charts for the coverage job summary.

The coverage workflow writes an llvm-cov report to its job summary (and, via
``tee``, to the job logs). GitHub does not expose an API to download a job
summary directly, so the trend is reconstructed from the logs of previous
Coverage runs on the same branch, which contain the same report. This script
extracts the overall line and branch coverage percentages from each of those
reports and renders Mermaid xychart trend charts, including the current run.
"""

import argparse
import math
import os
import re
import sys
from typing import List, NamedTuple, Optional, Tuple

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

# Plot colours for the trend charts: bright green for line coverage, bright
# blue for branch coverage.
_LINE_COVERAGE_COLOR = "#00ff00"
_BRANCH_COVERAGE_COLOR = "#0000ff"


class CoveragePoint(NamedTuple):
    run_id: int
    label: str
    line_coverage: float
    branch_coverage: Optional[float]


def extract_coverage(text: str) -> Optional[Tuple[float, Optional[float]]]:
    """Return the (line, branch) coverage percentages from an llvm-cov report.

    Branch coverage is ``None`` when the report does not include a branch
    column.
    """
    for line in text.splitlines():
        stripped: str = _ANSI_RE.sub("", line)
        stripped = _TIMESTAMP_RE.sub("", stripped).strip()
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

    if not points:
        return 0

    print(render_trend(points))
    return 0


if __name__ == "__main__":
    sys.exit(main())
