# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "coverage_summary.py"
SPEC = importlib.util.spec_from_file_location("coverage_summary", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)

LLVM_COV_TOTAL = (
    "TOTAL 100 10 90.00% 20 5 75.00% "
    "80 20 75.00% 40 10 75.00%\n"
)


class CoverageSummaryTest(unittest.TestCase):
    def test_history_starts_at_instrumented_library_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "1-100.log").write_text(LLVM_COV_TOTAL, encoding="utf-8")
            (root / "2-101.log").write_text(
                f"{SUMMARY.HISTORY_FORMAT_MARKER}\n{LLVM_COV_TOTAL}",
                encoding="utf-8",
            )

            history = SUMMARY.load_history(str(root))

        self.assertEqual(
            history,
            [SUMMARY.CoveragePoint(2, "101", 75.0, 75.0)],
        )


if __name__ == "__main__":
    unittest.main()
