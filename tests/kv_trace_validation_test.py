# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import kv_trace_validation as validation


class CheckerOutputTests(unittest.TestCase):
    def decode(self, status="accepted", returncode=0, **fields):
        record = {"status": status, "events": 4, "message": "result"}
        record.update(fields)
        return validation.decode_checker_result(json.dumps(record), returncode)

    def test_accept(self):
        self.assertEqual(self.decode()["status"], "accepted")

    def test_rejection_remains_failure(self):
        self.assertEqual(
            self.decode("rejected", 2, seq=3)["status"],
            "rejected",
        )

    def test_nonzero_accept_is_invalid(self):
        with self.assertRaises(ValueError):
            self.decode(returncode=1)

    def test_zero_rejection_is_invalid(self):
        with self.assertRaises(ValueError):
            self.decode("rejected")

    def test_unknown_status_is_invalid(self):
        with self.assertRaises(ValueError):
            self.decode("ignored", 2)

    def test_empty_accept_is_invalid(self):
        with self.assertRaises(ValueError):
            self.decode(events=0)

    def test_boolean_counts_are_invalid(self):
        with self.assertRaises(ValueError):
            self.decode(events=True)

    def test_negative_identifiers_are_invalid(self):
        with self.assertRaises(ValueError):
            self.decode("rejected", 2, tx=-1)

    def test_malformed_json_is_invalid(self):
        with self.assertRaises(ValueError):
            validation.decode_checker_result("not json", 0)


class CoverageTests(unittest.TestCase):
    def test_missing_case_is_error(self):
        with self.assertRaises(ValueError):
            validation.coverage({"exclusions": []}, ["existing"], ["missing"])

    def test_unclassified_tests_are_visible(self):
        result = validation.coverage({"exclusions": []}, ["A", "B"], ["A"])
        self.assertEqual(result["unclassified"], ["B"])
        self.assertFalse(result["complete_inventory"])

    def test_exclusion_requires_explicit_name(self):
        manifest = {"exclusions": [{"name": "B", "reason": "snapshot import"}]}
        result = validation.coverage(manifest, ["A", "B"], ["A"])
        self.assertTrue(result["complete_inventory"])
        self.assertEqual(result["excluded"], manifest["exclusions"])

    def test_explicit_selection_can_exercise_excluded_case(self):
        manifest = {"exclusions": [{"name": "B", "reason": "snapshot import"}]}
        result = validation.coverage(manifest, ["A", "B"], ["A", "B"])
        self.assertTrue(result["complete_inventory"])
        self.assertEqual(result["excluded"], [])

    def test_stale_exclusions_are_visible(self):
        manifest = {"exclusions": [{"name": "C", "reason": "snapshot import"}]}
        result = validation.coverage(manifest, ["A"], ["A"])
        self.assertEqual(result["stale_exclusions"], ["C"])
        self.assertFalse(result["complete_inventory"])

    def test_filter_metacharacters_are_rejected(self):
        for name in ["", "*", "A,B", "A?", "A\\B"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validation.test_arguments(name)

    def test_exact_test_filter(self):
        self.assertIn(
            "--test-case=Cross-map conflicts",
            validation.test_arguments("Cross-map conflicts"),
        )

    def test_incomplete_default_inventory_fails(self):
        self.assertEqual(validation.outcome([{"status": "accepted"}], False), 1)

    def test_explicit_subset_is_not_whole_suite(self):
        self.assertEqual(
            validation.outcome(
                [{"status": "accepted"}], False, explicit_selection=True
            ),
            0,
        )

    def test_discrepancies_are_not_conformance(self):
        for status in ["rejected", "unsupported"]:
            self.assertEqual(validation.outcome([{"status": status}], True), 2)

    def test_broken_capture_fails(self):
        self.assertEqual(validation.outcome([{"status": "capture_failed"}], True), 1)

    def test_no_cases_fails(self):
        self.assertEqual(validation.outcome([], True), 1)


class ArtifactTests(unittest.TestCase):
    def test_run_environment_is_isolated_and_trace_path_is_owned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            extra = {
                "CCF_KV_FUZZ_SEED": "17",
                "CCF_KV_TRACE_FILE": "not-the-output-path",
            }
            with patch.dict(os.environ, {"CCF_KV_FUZZ_SEED": "original"}), patch(
                "kv_trace_validation.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as run:
                result = validation.run_case(
                    Path("kv"), Path("lean"), "case", path, 30, extra_env=extra
                )
                environment = run.call_args.kwargs["env"]
                self.assertEqual(environment["CCF_KV_FUZZ_SEED"], "17")
                self.assertEqual(
                    environment["CCF_KV_TRACE_FILE"], str(path / "trace.ndjson")
                )
                self.assertEqual(os.environ["CCF_KV_FUZZ_SEED"], "original")
            self.assertEqual(result["status"], "capture_failed")
            self.assertEqual(extra["CCF_KV_TRACE_FILE"], "not-the-output-path")

    def test_prefix_preserves_original_events(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.ndjson"
            lines = [json.dumps({"seq": seq}) + "\n" for seq in range(4)]
            trace.write_text("".join(lines), encoding="utf-8")
            prefix = validation.preserve_prefix(trace, 2)
            self.assertEqual(
                (trace.parent / prefix).read_text(encoding="utf-8"),
                "".join(lines[:3]),
            )
            self.assertEqual(trace.read_text(encoding="utf-8"), "".join(lines))

    def test_prefix_requires_actual_event(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.ndjson"
            trace.write_text('{"seq":0}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                validation.preserve_prefix(trace, 8)

    def test_manifest_rejects_overlapping_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "cases": [{"name": "A", "features": ["get"]}],
                        "exclusions": [{"name": "A", "reason": "not captured"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                validation.load_manifest(path)

    def test_manifest_requires_features(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                json.dumps({"schema": 1, "cases": [{"name": "A"}], "exclusions": []}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                validation.load_manifest(path)

    def test_manifest_rejects_boolean_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": True,
                        "cases": [{"name": "A", "features": ["get"]}],
                        "exclusions": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                validation.load_manifest(path)


if __name__ == "__main__":
    unittest.main()
