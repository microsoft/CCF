#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Patch an ``llvm-cov report``'s per-file and TOTAL line coverage to count
each physical source line once, instead of llvm-cov's own per-function
summary.

llvm-cov computes line coverage per function, then sums per file (``report``,
the HTML index, and ``llvm-cov export``'s own ``LF``/``LH`` records). This
distorts C++ totals two ways:

1. Function templates are grouped into "instantiation groups" and merged
   with ``LineCoverageInfo::merge``, which takes the *maximum*
   covered/total line count across instantiations rather than their union,
   so lines covered only by *different* instantiations never add up even
   though every line ran. See llvm/tools/llvm-cov/CoverageSummaryInfo.h/.cpp.
2. Each function's line count includes lines of nested lambdas, which have
   their own summary too, so a lambda's body is counted once for it and
   again for its enclosing function.

The per-line ``DA:`` records (and ``llvm-cov show``'s source view) are not
affected: each physical line is reported once. This module recomputes each
file's line counts, and their total, from ``DA:`` records and substitutes
them into the per-file and TOTAL rows of an ``llvm-cov report`` text,
leaving every other column as llvm-cov printed it. This does move what
counts as "one line" for macros: a macro's definition gets one aggregate
``DA:`` record (summed across expansions) plus one per expansion site,
since these are different physical lines -- matching ``llvm-cov show``.

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
import re
import sys
from typing import Dict, Iterable, List, NamedTuple, Optional


def _percentage(hit: int, found: int) -> Optional[float]:
    if found == 0:
        return None
    return 100.0 * hit / found


def _format_percentage(value: Optional[float]) -> str:
    return f"{value:.2f}%" if value is not None else "-"


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


# Token indices of an ``llvm-cov report`` row's Lines group, after splitting
# on runs of whitespace while keeping the whitespace itself (so every other
# column's original spacing survives untouched), e.g.:
#   TOTAL  123860 19651 84.13%  4579 1274 72.18%  84414 26245 68.91%  ...
# Index 0 is the file name, or "TOTAL"; 2/4/6 are Regions, 8/10/12
# Functions, 14/16/18 Lines (replaced below), 20/22/24 Branches (if present).
_LINES_FOUND_INDEX = 14
_MISSED_LINES_INDEX = 16
_LINE_COVER_INDEX = 18


def _paths_by_suffix(paths: Iterable[str]) -> Dict[str, str]:
    """Map each path, and each suffix of it that starts after a ``/``, to the
    shortest of the paths it is a suffix of.

    ``llvm-cov report`` names each file by its path with the leading
    components common to all files removed, so a row's name is one of these
    suffixes of its LCOV ``SF:`` path. Other paths ending with the same
    suffix are in subdirectories of the common prefix, so are longer.
    """
    by_suffix: Dict[str, str] = {}
    for path in paths:
        suffixes = [path] + [path[i + 1 :] for i, c in enumerate(path) if c == "/"]
        for suffix in suffixes:
            if suffix not in by_suffix or len(path) < len(by_suffix[suffix]):
                by_suffix[suffix] = path
    return by_suffix


def patch_report(report_text: str, files: Dict[str, FileLineCoverage]) -> str:
    """Replace the Lines/Missed Lines/Cover columns of each per-file row, and
    of the TOTAL row, of an ``llvm-cov report`` text with the corrected
    distinct-line counts.

    Every other column is returned unmodified. Raises ``ValueError`` if a row
    with lines has no LCOV record, rather than leave it uncorrected.
    """
    by_suffix: Dict[str, str] = _paths_by_suffix(files)
    total: FileLineCoverage = aggregate(files)
    patched_total = False
    lines: List[str] = report_text.splitlines()
    for i, line in enumerate(lines):
        tokens: List[str] = re.split(r"(\s+)", line)
        if len(tokens) <= _LINE_COVER_INDEX or not tokens[_LINES_FOUND_INDEX].isdigit():
            continue
        name: str = tokens[0]
        if name == "TOTAL":
            coverage = total
            patched_total = True
        elif name in by_suffix:
            coverage = files[by_suffix[name]]
        elif tokens[_LINES_FOUND_INDEX] == "0":
            continue
        else:
            raise ValueError(f"No LCOV record found for {name}")
        replacements = {
            _LINES_FOUND_INDEX: str(coverage.lines_found),
            _MISSED_LINES_INDEX: str(coverage.lines_found - coverage.lines_hit),
            _LINE_COVER_INDEX: _format_percentage(coverage.line_coverage),
        }
        for index, value in replacements.items():
            tokens[index] = value.rjust(max(len(tokens[index]), len(value)))
        lines[i] = "".join(tokens)
    if not patched_total:
        raise ValueError("No TOTAL row found in llvm-cov report output")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Patch an 'llvm-cov report''s per-file and TOTAL line coverage "
            "from an 'llvm-cov export -format=lcov' report, counting each "
            "physical source line once regardless of how many template "
            "instantiations or enclosing lambdas cover it. Every other "
            "column is left unmodified. Branch coverage is not recomputed; "
            "see the module docstring for why."
        )
    )
    parser.add_argument("report_file", help="Path to 'llvm-cov report' text output")
    parser.add_argument(
        "lcov_file",
        nargs="?",
        help="Path to an LCOV file produced by 'llvm-cov export -format=lcov' "
        "(default: read from stdin)",
    )
    args = parser.parse_args(argv)

    with open(args.report_file, "r", encoding="utf-8") as f:
        report_text = f.read()

    if args.lcov_file:
        with open(args.lcov_file, "r", encoding="utf-8") as f:
            lcov_text = f.read()
    else:
        lcov_text = sys.stdin.read()

    files = parse_lcov(lcov_text)
    if not files:
        print("No LCOV records found.", file=sys.stderr)
        return 1
    print(patch_report(report_text, files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
