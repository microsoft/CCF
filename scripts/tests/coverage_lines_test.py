#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Unit tests for scripts/coverage_lines.py and the distinct-line handling in
scripts/coverage_summary.py.

Covers the two llvm-cov distortions that motivate the distinct-line count:
function template instantiations merged with max() rather than union, and
lines inside lambdas counted once for the lambda and again for the enclosing
function. Synthetic LCOV inputs below reproduce both, based on real
'llvm-cov export -format=lcov' output observed for equivalent C++ sources.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parents[1]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


coverage_lines = _load("coverage_lines", "coverage_lines.py")
coverage_summary = _load("coverage_summary", "coverage_summary.py")


# Reproduces a function template f<T> instantiated as f<int> and f<double>,
# called with values that take opposite branches of an if/else. llvm-cov's
# per-function summary merges the two instantiations with max(), reporting
# only 16 of 21 lines hit even though every line is covered by some
# instantiation, and only 1 of 2 branches hit even though both were taken.
# The DA/BRDA records themselves are correctly unioned (no DA with count 0),
# matching real 'llvm-cov export -format=lcov' output for this case.
TEMPLATE_LCOV = """\
SF:/src/template.cpp
FN:23,main
FN:5,_Z1fIiEiT_
FN:5,_Z1fIdEiT_
FNDA:1,main
FNDA:1,_Z1fIiEiT_
FNDA:1,_Z1fIdEiT_
FNF:2
FNH:2
DA:5,2
DA:6,2
DA:7,2
DA:8,1
DA:9,1
DA:10,1
DA:11,1
DA:12,1
DA:13,1
DA:14,1
DA:15,1
DA:16,1
DA:17,1
DA:18,1
DA:19,2
DA:20,2
DA:23,1
DA:24,1
DA:25,1
DA:26,1
DA:27,1
BRDA:7,0,0,1
BRDA:7,0,1,1
BRF:2
BRH:1
LF:21
LH:16
end_of_record
"""

# Reproduces a lambda body (lines 6-13) nested inside make() (lines 5-20).
# llvm-cov's per-function summary counts the lambda's lines both for the
# lambda and for the enclosing make(), reporting 20 lines total although
# only 14 physical lines exist and are all covered. LF/LH copy that inflated
# summary rather than being derived from the (correctly deduplicated) DA
# records shown in the same section.
LAMBDA_LCOV = """\
SF:/src/lambda.cpp
FN:5,_Z4makev
FN:16,main
FN:6,lambda.cpp:_ZZ4makevENK3$_0clEi
FNDA:1,_Z4makev
FNDA:1,main
FNDA:1,lambda.cpp:_ZZ4makevENK3$_0clEi
FNF:3
FNH:3
DA:5,1
DA:6,1
DA:7,1
DA:8,1
DA:9,1
DA:10,1
DA:11,1
DA:12,1
DA:13,1
DA:16,1
DA:17,1
DA:18,1
DA:19,1
DA:20,1
BRF:0
BRH:0
LF:20
LH:20
end_of_record
"""


class ParseLcovTests(unittest.TestCase):
    def test_template_instantiations_are_unioned_not_maxed(self):
        files = coverage_lines.parse_lcov(TEMPLATE_LCOV)
        cov = files["/src/template.cpp"]
        # All 21 DA records are hit; llvm-cov's own summary says only 16.
        self.assertEqual(cov.lines_found, 21)
        self.assertEqual(cov.lines_hit, 21)
        # Both branch records are hit; llvm-cov's own summary says only 1.
        self.assertEqual(cov.branches_found, 2)
        self.assertEqual(cov.branches_hit, 2)

    def test_lambda_lines_are_not_double_counted(self):
        files = coverage_lines.parse_lcov(LAMBDA_LCOV)
        cov = files["/src/lambda.cpp"]
        # 14 distinct DA records, not the 20 llvm-cov's own summary reports.
        self.assertEqual(cov.lines_found, 14)
        self.assertEqual(cov.lines_hit, 14)

    def test_partially_covered_branch(self):
        text = (
            "SF:/src/partial.cpp\n"
            "DA:1,1\n"
            "DA:2,0\n"
            "BRDA:1,0,0,1\n"
            "BRDA:1,0,1,-\n"
            "BRDA:1,0,2,0\n"
            "LF:2\n"
            "LH:1\n"
            "end_of_record\n"
        )
        files = coverage_lines.parse_lcov(text)
        cov = files["/src/partial.cpp"]
        self.assertEqual((cov.lines_found, cov.lines_hit), (2, 1))
        # Only the branch with a positive count is hit; '-' means the
        # containing line never executed, and 0 means it executed but this
        # branch outcome was not taken.
        self.assertEqual((cov.branches_found, cov.branches_hit), (3, 1))

    def test_multiple_files_and_aggregate(self):
        files = coverage_lines.parse_lcov(TEMPLATE_LCOV + LAMBDA_LCOV)
        self.assertEqual(set(files), {"/src/template.cpp", "/src/lambda.cpp"})
        total = coverage_lines.aggregate(files)
        self.assertEqual(total.lines_found, 21 + 14)
        self.assertEqual(total.lines_hit, 21 + 14)
        self.assertEqual(total.branches_found, 2)
        self.assertEqual(total.branches_hit, 2)

    def test_empty_input_yields_no_files(self):
        self.assertEqual(coverage_lines.parse_lcov(""), {})


class RenderReportTests(unittest.TestCase):
    def test_total_distinct_row_present_and_correct(self):
        files = coverage_lines.parse_lcov(TEMPLATE_LCOV)
        total = coverage_lines.aggregate(files)
        report = coverage_lines.render_report(files, total)
        self.assertIn("TOTAL-DISTINCT", report)
        # No line in the report should be a bare "TOTAL" row (which would be
        # ambiguous with llvm-cov's own summary when both are concatenated).
        self.assertNotIn("\nTOTAL ", "\n" + report)
        distinct_line = next(
            line for line in report.splitlines() if line.startswith("TOTAL-DISTINCT")
        )
        self.assertIn("21", distinct_line)
        self.assertIn("100.00%", distinct_line)

    def test_zero_branches_render_as_dash(self):
        files = coverage_lines.parse_lcov(LAMBDA_LCOV)
        total = coverage_lines.aggregate(files)
        report = coverage_lines.render_report(files, total)
        self.assertIn("-", report)


class ExtractCoverageMetricTests(unittest.TestCase):
    def test_prefers_total_distinct_over_legacy_total(self):
        text = (
            "=== Coverage Summary (llvm-cov per-function summary) ===\n"
            "TOTAL 100 20 80.00% 50 10 80.00% 200 40 80.00% 20 5 75.00%\n"
            "=== Coverage Summary (distinct lines) ===\n"
            "TOTAL-DISTINCT 190 30 84.21% 20 5 75.00%\n"
        )
        result = coverage_summary.extract_coverage(text)
        self.assertIsNotNone(result)
        line_coverage, branch_coverage, metric = result
        self.assertEqual(line_coverage, 84.21)
        self.assertEqual(branch_coverage, 75.0)
        self.assertEqual(metric, coverage_summary.METRIC_DISTINCT)

    def test_falls_back_to_legacy_total_for_old_logs(self):
        text = "TOTAL 100 20 80.00% 50 10 80.00% 200 40 68.91% 20 5 75.00%\n"
        result = coverage_summary.extract_coverage(text)
        self.assertIsNotNone(result)
        line_coverage, branch_coverage, metric = result
        self.assertEqual(line_coverage, 68.91)
        self.assertEqual(branch_coverage, 75.0)
        self.assertEqual(metric, coverage_summary.METRIC_LEGACY)

    def test_no_total_row_returns_none(self):
        self.assertIsNone(coverage_summary.extract_coverage("no coverage here"))


class TrendTransitionTests(unittest.TestCase):
    def test_legacy_points_are_marked_in_trend(self):
        points = [
            coverage_summary.CoveragePoint(
                1, "1", 68.91, 75.0, coverage_summary.METRIC_LEGACY
            ),
            coverage_summary.CoveragePoint(
                2, "2", 84.21, 75.0, coverage_summary.METRIC_DISTINCT
            ),
        ]
        rendered = coverage_summary.render_trend(points)
        self.assertIn("older per-function summary metric", rendered)
        self.assertIn(")\\*", rendered)

    def test_no_note_when_all_points_share_a_metric(self):
        points = [
            coverage_summary.CoveragePoint(
                1, "1", 84.0, 75.0, coverage_summary.METRIC_DISTINCT
            ),
            coverage_summary.CoveragePoint(
                2, "2", 84.21, 75.0, coverage_summary.METRIC_DISTINCT
            ),
        ]
        rendered = coverage_summary.render_trend(points)
        self.assertNotIn("older per-function summary metric", rendered)


if __name__ == "__main__":
    unittest.main()
