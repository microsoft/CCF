# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Render a line coverage trend chart for the coverage job summary.

The coverage workflow writes an llvm-cov report to its job summary (and, via
``tee``, to the job logs). GitHub does not expose an API to download a job
summary directly, so the trend is reconstructed from the logs of previous
Coverage runs on the same branch, which contain the same report. This script
extracts the overall line coverage percentage from each of those reports and
renders a Mermaid xychart showing the trend, including the current run.
"""

import argparse
import math
import os
import re
import sys
from typing import List, NamedTuple, Optional, Tuple

# Number of previous runs to include in the trend, in addition to the current
# run.
HISTORY_POINTS = 9
DEFAULT_REPOSITORY = "microsoft/CCF"

# The llvm-cov ``report`` TOTAL line lists, for each of Regions, Functions,
# Lines and Branches, a count, a missed count and a coverage percentage, e.g.:
#   TOTAL  123860 19651 84.13%  4579 1274 72.18%  84414 26245 68.91%  ...
# Line coverage is therefore the third percentage on the line.
_PERCENT_RE = re.compile(r"(\d+(?:\.\d+)?)%")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Optional leading ISO-8601 timestamp, as prefixed to each GitHub Actions log
# line (e.g. "2026-07-07T18:12:43.968Z ").
_TIMESTAMP_RE = re.compile(r"^\S+T\S+Z\s+")
_LINE_COVERAGE_INDEX = 2


class CoveragePoint(NamedTuple):
    run_id: int
    label: str
    coverage: float


def extract_line_coverage(text: str) -> Optional[float]:
    """Return the overall line coverage percentage from an llvm-cov report."""
    for line in text.splitlines():
        stripped: str = _ANSI_RE.sub("", line)
        stripped = _TIMESTAMP_RE.sub("", stripped).strip()
        if not stripped.startswith("TOTAL"):
            continue
        percentages: List[str] = _PERCENT_RE.findall(stripped)
        if len(percentages) > _LINE_COVERAGE_INDEX:
            return float(percentages[_LINE_COVERAGE_INDEX])
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
                coverage: Optional[float] = extract_line_coverage(f.read())
        except OSError:
            continue
        if coverage is not None:
            points.append(CoveragePoint(run_id, label, coverage))
    return points


def run_url(run_id: int) -> str:
    server_url: str = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip(
        "/"
    )
    repository: str = os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY)
    return f"{server_url}/{repository}/actions/runs/{run_id}"


def render_trend(points: List[CoveragePoint]) -> str:
    """Render the line coverage trend as a Mermaid xychart and a runs table."""
    labels: str = ", ".join(f'"{point.label}"' for point in points)
    values: str = ", ".join(f"{point.coverage:.2f}" for point in points)

    coverages: List[float] = [point.coverage for point in points]
    lowest: float = min(coverages)
    highest: float = max(coverages)
    axis_min: float = max(0.0, math.floor(lowest - 1))
    axis_max: float = min(100.0, math.ceil(highest + 1))
    if axis_min >= axis_max:
        axis_min = max(0.0, axis_max - 1)

    lines: List[str] = [
        "## Line coverage trend",
        "",
        "```mermaid",
        "xychart-beta",
        '    title "Line coverage (%)"',
        f"    x-axis [{labels}]",
        f'    y-axis "Line coverage (%)" {axis_min:g} --> {axis_max:g}',
        f"    line [{values}]",
        "```",
        "",
        "| Run | Line coverage |",
        "| --- | --- |",
    ]
    for point in reversed(points):
        lines.append(
            f"| [{point.label}]({run_url(point.run_id)}) | {point.coverage:.2f}% |"
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
            coverage: Optional[float] = extract_line_coverage(f.read())
    except OSError:
        return None
    if coverage is None:
        return None
    run_id: int = int(os.environ.get("GITHUB_RUN_ID") or 0)
    label: str = os.environ.get("GITHUB_RUN_NUMBER") or str(run_id)
    return CoveragePoint(run_id, label, coverage)


def main() -> int:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Render a line coverage trend chart for the job summary."
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
