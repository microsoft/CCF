# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import unittest

from lts_compatibility import validate_compatibility_report


class CompatibilityReportTest(unittest.TestCase):
    def setUp(self):
        self.report = {
            "version": "ccf-7.0.20",
            "live compatibility": {
                "with previous LTS": "ccf-6.0.14",
                "with same LTS": "ccf-7.0.19",
            },
        }

    def test_tagged_development_branch(self):
        self.report["live compatibility"] = {
            "with previous LTS": "ccf-7.0.20",
            "with same LTS": None,
        }
        for branch in ("main", "feature", "ccf-8.0.0-dev0"):
            with self.subTest(branch=branch):
                validate_compatibility_report(self.report, branch)

    def test_development_version(self):
        self.report["version"] = "ccf-7.0.20-1-gabcdef"
        self.report["live compatibility"] = {}
        for branch in ("main", "release/7.x"):
            with self.subTest(branch=branch):
                validate_compatibility_report(self.report, branch)

    def test_release_context(self):
        for branch in ("release/7.x", "ccf-7.0.20", "backport/release/7.x"):
            with self.subTest(branch=branch):
                validate_compatibility_report(self.report, branch)

    def test_release_context_rejects_current_major_as_previous_lts(self):
        self.report["live compatibility"]["with previous LTS"] = "ccf-7.0.20"
        for branch in ("release/7.x", "ccf-7.0.20"):
            with self.subTest(branch=branch), self.assertRaisesRegex(
                AssertionError, "Expected previous LTS from major 6"
            ):
                validate_compatibility_report(self.report, branch)

    def test_release_context_requires_previous_patch(self):
        for same_lts in (None, "ccf-7.0.20"):
            with self.subTest(same_lts=same_lts):
                self.report["live compatibility"]["with same LTS"] = same_lts
                with self.assertRaisesRegex(
                    AssertionError, "Expected same LTS ccf-7.0.19"
                ):
                    validate_compatibility_report(self.report, "release/7.x")

    def test_release_context_requires_data_coverage(self):
        self.report["data compatibility"] = {
            "with previous ledger": ["ccf-6.0.14"],
            "with previous snapshots": ["ccf-6.0.14"],
        }
        with self.assertRaisesRegex(
            AssertionError, "Data compatibility did not cover releases"
        ):
            validate_compatibility_report(self.report, "release/7.x")


if __name__ == "__main__":
    unittest.main()
