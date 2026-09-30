#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compute distinct-line coverage from an ``llvm-cov export -format=lcov`` report.

llvm-cov computes line coverage per function, then sums per file (``report``'s
totals, the HTML index, and ``llvm-cov export``'s own ``LF``/``LH`` records).
This distorts C++ totals two ways:

1. Function templates are grouped into "instantiation groups" and merged with
   ``LineCoverageInfo::merge``, which takes the *maximum* covered/total line
   count across instantiations rather than their union, so lines covered only
   by *different* instantiations never add up even though every line ran.
   See llvm/tools/llvm-cov/CoverageSummaryInfo.h/.cpp.
2. Each function's line count includes lines of nested lambdas, which have
   their own summary too, so a lambda's body is counted once for it and again
   for its enclosing function.

The per-line ``DA:`` records (and ``llvm-cov show``'s source view) are not
affected: each physical line is reported once. Only the ``LF``/``LH`` summary
fields copy the distorted per-function totals instead of being derived from
the ``DA`` records alongside them. This module recomputes line totals from
``DA:`` directly, counting each physical line once. This does move what
counts as "one line" for macros: a macro's definition gets one aggregate
``DA:`` record (summed across expansions) plus one per expansion site, since
these are different physical lines -- matching ``llvm-cov show``.

Branch coverage is deliberately NOT recomputed here. ``BranchCoverageInfo::
merge`` has the same max()-merge problem, but counting ``BRDA:`` records
directly does not fix it: unlike ``DA:``, a macro/template expansion adds an
aggregate ``BRDA:`` record at the definition line *in addition to* one per
expansion/instantiation site, all describing the same branch, so counting
them all over-counts found/missed branches (verified: a two-line macro
invoked twice moves llvm-cov's correct 4/2 to a naive 6/3). CCF's headers use
branching macros heavily (LOG_*_FMT, CCF_ASSERT*, RAFT_TRACE_JSON_OUT), so
this is not a corner case. Treat llvm-cov's own branch numbers (``report``,
or this export's ``BRF``/``BRH``) as authoritative until a correct
per-branch-region reconciliation is implemented and verified.
"""

import argparse
import sys
from typing import Dict, List, NamedTuple, Optional, TextIO


def _percentage(hit: int, found: int) -> Optional[float]:
    if found == 0:
        return None
    return 100.0 * hit / found


class FileLineCoverage(NamedTuple):
    lines_found: int
    lines_hit: int

    @property
    def line_coverage(self) -> Optional[float]:
        return _percentage(self.lines_hit, self.lines_found)


def parse_lcov(text: str) -> Dict[str, FileLineCoverage]:
    """Return per-file distinct line counts from LCOV text.

    Counts each ``DA:`` record as one found line (hit if its count is
    non-zero), ignoring the file's own ``LF``/``LH`` and all ``BRDA:``
    records; see the module docstring for why.
    """
    files: Dict[str, FileLineCoverage] = {}
    current_file: Optional[str] = None
    lines_found = lines_hit = 0

    def flush() -> None:
        nonlocal current_file, lines_found, lines_hit
        if current_file is not None:
            files[current_file] = FileLineCoverage(lines_found, lines_hit)
        current_file = None
        lines_found = lines_hit = 0

    for line in text.splitlines():
        if line.startswith("SF:"):
            flush()
            current_file = line[len("SF:") :]
        elif line.startswith("DA:"):
            fields = line[len("DA:") :].split(",")
            count = int(fields[1])
            lines_found += 1
            if count > 0:
                lines_hit += 1
        elif line.startswith("end_of_record"):
            flush()
    # A trailing section without "end_of_record" is unexpected for llvm-cov's
    # output, but handle it rather than silently dropping the last file.
    flush()
    return files


def aggregate(files: Dict[str, FileLineCoverage]) -> FileLineCoverage:
    lines_found = sum(f.lines_found for f in files.values())
    lines_hit = sum(f.lines_hit for f in files.values())
    return FileLineCoverage(lines_found, lines_hit)


def _format_percentage(value: Optional[float]) -> str:
    return f"{value:.2f}%" if value is not None else "-"


def render_report(files: Dict[str, FileLineCoverage], total: FileLineCoverage) -> str:
    """Render a line-coverage-only report table in the style of ``llvm-cov report``.

    The ``TOTAL-DISTINCT`` row is deliberately distinct from llvm-cov's own
    ``TOTAL`` row, so callers such as ``coverage_summary.py`` can tell them
    apart in historical logs. No branch column: see the module docstring.
    """
    header = f"{'Filename':<50} {'Lines':>10} {'Missed Lines':>14} {'Cover':>9}"
    separator = "-" * len(header)
    lines: List[str] = [header, separator]
    for path in sorted(files):
        file_cov = files[path]
        lines.append(
            f"{path:<50} {file_cov.lines_found:>10} "
            f"{file_cov.lines_found - file_cov.lines_hit:>14} "
            f"{_format_percentage(file_cov.line_coverage):>9}"
        )
    lines.append(separator)
    lines.append(
        f"{'TOTAL-DISTINCT':<50} {total.lines_found:>10} "
        f"{total.lines_found - total.lines_hit:>14} "
        f"{_format_percentage(total.line_coverage):>9}"
    )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute distinct-line coverage from an "
            "'llvm-cov export -format=lcov' report, counting each physical "
            "source line once regardless of how many template instantiations "
            "or enclosing lambdas cover it. Branch coverage is not "
            "recomputed; use llvm-cov's own branch numbers."
        )
    )
    parser.add_argument(
        "lcov_file",
        nargs="?",
        help="Path to an LCOV file produced by 'llvm-cov export -format=lcov' "
        "(default: read from stdin)",
    )
    args = parser.parse_args(argv)

    text: str
    if args.lcov_file:
        with open(args.lcov_file, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        stream: TextIO = sys.stdin
        text = stream.read()

    files = parse_lcov(text)
    if not files:
        print("No LCOV records found.", file=sys.stderr)
        return 1
    total = aggregate(files)
    print(render_report(files, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
