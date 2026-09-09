# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "coverage_report.py"
SPEC = importlib.util.spec_from_file_location("coverage_report", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


def summary(lines=10, covered_lines=4, branches=2, covered_branches=1):
    return {
        "lines": {"count": lines, "covered": covered_lines},
        "branches": {"count": branches, "covered": covered_branches},
    }


def export(files, root):
    return {
        "type": "llvm.coverage.json.export",
        "data": [
            {
                "files": [
                    {"filename": str(root / name), "summary": counts}
                    for name, counts in files.items()
                ]
            }
        ],
    }


class CoverageReportTest(unittest.TestCase):
    def test_scopes_preserve_combined_counts(self):
        files = {
            "src/crypto/base64.cpp": summary(),
            "include/ccf/crypto/base64.h": summary(3, 1, 0, 0),
            "samples/apps/logging/logging.cpp": summary(7, 2),
            "/external/src/example.h": summary(2, 1, 2, 0),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            normalised = REPORT.coverage_files(export(files, root), root)
        self.assertEqual(normalised, files)
        totals = REPORT.scoped_totals(normalised)
        self.assertEqual(totals["Framework"]["lines"], {"count": 13, "covered": 5})
        self.assertEqual(totals["Samples"]["lines"], {"count": 7, "covered": 2})
        self.assertEqual(totals["Other"]["lines"], {"count": 2, "covered": 1})
        self.assertEqual(
            totals["All reported C++"]["lines"], {"count": 22, "covered": 8}
        )
        self.assertEqual(
            totals["All reported C++"]["branches"], {"count": 6, "covered": 2}
        )

    def test_rejects_duplicate_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = export({"src/crypto/base64.cpp": summary()}, root)
            document["data"].append(document["data"][0])
            with self.assertRaisesRegex(ValueError, "Duplicate coverage file"):
                REPORT.coverage_files(document, root)

    def test_rejects_invalid_or_empty_exports(self):
        for document in (
            {"type": "unknown", "data": [{}]},
            {"type": "llvm.coverage.json.export", "data": []},
            {"type": "llvm.coverage.json.export", "data": [{"files": []}]},
        ):
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    REPORT.coverage_files(document, Path.cwd())

    def test_checks_every_sentinel(self):
        files = {name: summary() for name in REPORT.INSTRUMENTATION_SENTINELS}
        self.assertEqual(REPORT.instrumentation_failures(files), [])
        for filename in REPORT.INSTRUMENTATION_SENTINELS:
            with self.subTest(filename=filename):
                for replacement in (None, summary(covered_lines=0), summary(0, 0)):
                    changed = files.copy()
                    if replacement is None:
                        del changed[filename]
                    else:
                        changed[filename] = replacement
                    failures = REPORT.instrumentation_failures(changed)
                    self.assertEqual(len(failures), 1)
                    self.assertIn(filename, failures[0])

    def test_labels_denominator_change_and_empty_scopes(self):
        text = REPORT.render_report({"src/crypto/base64.cpp": summary()})
        self.assertIn("| Framework | 4/10 (40.00%) | 1/2 (50.00%) |", text)
        self.assertIn("| Samples | 0/0 (n/a) | 0/0 (n/a) |", text)
        self.assertIn("denominator is not comparable", text)
        self.assertIn("Rust is not instrumented", text)

    def test_cli_only_checks_sentinels_when_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "coverage.json"
            report.write_text(
                json.dumps(export({"src/crypto/base64.cpp": summary()}, root)),
                encoding="utf-8",
            )
            command = [
                sys.executable,
                str(SCRIPT),
                str(report),
                "--source-dir",
                str(root),
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertIn("Native C++ coverage scope", result.stdout)
            checked = subprocess.run(
                command + ["--check-instrumentation"], capture_output=True, text=True
            )
            self.assertEqual(checked.returncode, 1)
            self.assertIn(
                "src/host/run.cpp: missing from coverage report", checked.stderr
            )


if __name__ == "__main__":
    unittest.main()
