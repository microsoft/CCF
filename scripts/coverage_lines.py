#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compute distinct-line coverage from an ``llvm-cov export -format=lcov`` report.

llvm-cov's ``report`` command (and the summary totals in its HTML index and
in ``llvm-cov export``'s own ``LF``/``LH`` records) compute line coverage per
function, then sum per file. For C++ this distorts the totals in two ways:

1. Function templates are grouped into "instantiation groups", and each
   group's line summary is computed by ``LineCoverageInfo::merge``, which
   takes the *maximum* covered/total line counts across instantiations rather
   than their union. Lines covered only by *different* instantiations of the
   same template therefore never add up, even though every line was executed
   by some instantiation.
   See llvm/tools/llvm-cov/CoverageSummaryInfo.h and .cpp in the LLVM source.

2. Each function's line count includes every line lexically inside it,
   including nested lambdas. Since a lambda is itself a function with its own
   summary, its body lines are counted once for the lambda and again for the
   enclosing function, inflating the file (and total) line count. A lambda
   that never runs still counts as "covered" through its enclosing function's
   region.

The per-line data itself (the ``DA:`` records in the LCOV export, and the
source view in ``llvm-cov show``) is not affected by either distortion: each
physical line is reported once, correctly merged across instantiations. Only
the ``LF``/``LH`` summary records (and everything derived from them: llvm-cov
``report``'s totals, the HTML index, and ``llvm-cov export``'s own summary
fields) copy the distorted per-function summary instead of being derived from
the ``DA`` records shown alongside them in the same export.

This module recomputes line totals directly from the ``DA:`` records,
counting each physical source line once. This does change what counts as one
"line": a macro's definition gets a single aggregate ``DA:`` record (summed
across all its expansions), on top of one record per expansion site, since
those are different physical lines. A macro body that is never executed by
any expansion (e.g. a disabled ``LOG_DEBUG`` branch) therefore shows up as one
uncovered line at the definition, in addition to whatever is at each call
site; this matches ``llvm-cov show``'s source view, which marks the
definition line itself with the aggregate count.

Branch coverage is deliberately NOT recomputed here, and this module does not
touch it. llvm-cov's per-function branch summary has the same max()-merge
problem as lines (``BranchCoverageInfo::merge``), but counting ``BRDA:``
records directly does not fix it: unlike ``DA:``, a macro or template
expansion produces an aggregate ``BRDA:`` record at the definition line *in
addition to* one at each expansion/instantiation site, all describing the
same source branch. Counting them all as distinct branches over-counts found
and missed branches (verified: a two-line macro invoked twice moves llvm-cov
report's correct 4 branches/2 missed to 6 branches/3 missed when counted this
way). CCF's headers make heavy use of branching macros (LOG_*_FMT,
CCF_ASSERT*, RAFT_TRACE_JSON_OUT, ...), so this is not a corner case. Treat
llvm-cov's own branch numbers (from ``report``, or this export's ``BRF``/
``BRH``) as authoritative until a correct per-branch-region reconciliation
(e.g. from the JSON export's region/expansion metadata) is implemented and
verified.
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

    Counts each ``DA:`` record as one found line (hit if its execution count
    is non-zero). This ignores the file's own ``LF``/``LH`` records, which
    copy llvm-cov's per-function summary rather than being derived from the
    ``DA`` records in the same section. ``BRDA:`` records are ignored
    entirely; see the module docstring for why branch coverage is not
    recomputed here.
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

    The ``TOTAL-DISTINCT`` row (rather than plain ``TOTAL``) is deliberately
    distinct from llvm-cov's own summary row, so callers such as
    ``coverage_summary.py`` can tell the corrected metric apart from the
    older, distorted one when reading historical logs that predate this
    change. There is no branch column: see the module docstring for why
    branch coverage is not recomputed here.
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
