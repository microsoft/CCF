# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import kv_fuzz as fuzz

DEFAULT_WORKLOAD = fuzz.Workload()


def recipe(seed=0, workload=DEFAULT_WORKLOAD):
    return {
        "version": 1,
        "seed": str(seed),
        "threads": workload.threads,
        "transactions": workload.transactions,
        "operations": workload.operations,
        "maps": 6,
        "keys": 8,
    }


def coverage(workload=DEFAULT_WORKLOAD):
    counts = dict.fromkeys(fuzz.REQUIRED_COUNTERS, 1)
    counts["max_live_workers"] = workload.threads
    return counts


class WorkloadTests(unittest.TestCase):
    def test_defaults_are_bounded(self):
        fuzz.Workload().validate()

    def test_invalid_dimensions(self):
        for workload in (
            fuzz.Workload(threads=0),
            fuzz.Workload(threads=17),
            fuzz.Workload(transactions=257),
            fuzz.Workload(operations=33),
            fuzz.Workload(threads=True),
        ):
            with self.subTest(workload=workload), self.assertRaises(ValueError):
                workload.validate()

    def test_total_budget(self):
        with self.assertRaises(ValueError):
            fuzz.Workload(16, 256, 32).validate()

    def test_seed_range(self):
        fuzz.validate_seed_range(0, 8)
        fuzz.validate_seed_range(fuzz.MAX_SEED, 1)
        for first, count in ((-1, 1), (0, 0), (0, 257), (fuzz.MAX_SEED, 2), (True, 1)):
            with self.subTest(first=first, count=count), self.assertRaises(ValueError):
                fuzz.validate_seed_range(first, count)

    def test_seed_is_exact_decimal_text(self):
        environment = fuzz.Workload().environment(fuzz.MAX_SEED)
        self.assertEqual(environment["CCF_KV_FUZZ_SEED"], str(fuzz.MAX_SEED))
        self.assertNotIn("CCF_KV_TRACE_FILE", environment)


class MetadataTests(unittest.TestCase):
    def test_metadata_survives_console_noise(self):
        parsed = fuzz.metadata_lines(
            [
                "ordinary output\n",
                "KV_FUZZ_RECIPE " + json.dumps(recipe()) + "\n",
                "KV_FUZZ_COVERAGE " + json.dumps(coverage()) + "\n",
            ]
        )
        self.assertEqual(parsed, (recipe(), coverage()))
        fuzz.validate_metadata(*parsed, 0, fuzz.Workload())

    def test_missing_completion_is_not_coverage(self):
        with self.assertRaises(ValueError):
            fuzz.metadata_lines(["KV_FUZZ_RECIPE " + json.dumps(recipe())])

    def test_duplicate_records(self):
        line = "KV_FUZZ_RECIPE " + json.dumps(recipe())
        with self.assertRaises(ValueError):
            fuzz.metadata_lines([line, line])

    def test_duplicate_fields(self):
        with self.assertRaises(ValueError):
            fuzz.metadata_lines(['KV_FUZZ_RECIPE {"seed":"0","seed":"1"}'])

    def test_wrong_seed(self):
        with self.assertRaises(ValueError):
            fuzz.validate_metadata(recipe(1), coverage(), 0, fuzz.Workload())

    def test_numeric_seed_is_not_lossless_metadata(self):
        value = recipe()
        value["seed"] = 0
        with self.assertRaises(ValueError):
            fuzz.validate_metadata(value, coverage(), 0, fuzz.Workload())

    def test_missing_behavior(self):
        value = coverage()
        del value["rollback"]
        with self.assertRaises(ValueError):
            fuzz.validate_metadata(recipe(), value, 0, fuzz.Workload())

    def test_zero_behavior(self):
        value = coverage()
        value["worker_operations"] = 0
        with self.assertRaises(ValueError):
            fuzz.validate_metadata(recipe(), value, 0, fuzz.Workload())

    def test_boolean_counter(self):
        value = coverage()
        value["put"] = True
        with self.assertRaises(ValueError):
            fuzz.validate_metadata(recipe(), value, 0, fuzz.Workload())

    def test_single_worker_is_explicit(self):
        workload = fuzz.Workload(threads=1)
        fuzz.validate_metadata(
            recipe(workload=workload), coverage(workload), 0, workload
        )

    def test_requested_concurrency_must_be_observed(self):
        for maximum in (1, 5):
            value = coverage()
            value["max_live_workers"] = maximum
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                fuzz.validate_metadata(recipe(), value, 0, fuzz.Workload())


class TraceCoverageTests(unittest.TestCase):
    def test_actual_events_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.ndjson"
            path.write_text('{"type":"get","value":null}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                fuzz.event_coverage(path)

    def test_complete_event_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.ndjson"
            events = [
                {"type": event, "value": None, "key": "00", "result": "success"}
                for event in fuzz.REQUIRED_EVENTS
            ]
            events.extend(
                [
                    {"type": "commit_result", "result": "conflict"},
                    {"type": "commit_result", "result": "no_replicate"},
                    {"type": "foreach_continue", "value": False},
                    {"type": "get", "value": "00"},
                    {"type": "get_global", "value": "00"},
                    {"type": "previous_write", "value": 1},
                    {"type": "put", "key": "", "value": ""},
                ]
            )
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            result = fuzz.event_coverage(path)
            self.assertTrue(
                all(result[name] > 0 for name in fuzz.REQUIRED_OBSERVATIONS)
            )

    def test_model_acceptance_does_not_hide_missing_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "test.stdout.txt").write_text("", encoding="utf-8")
            with patch.object(
                fuzz.trace,
                "run_case",
                return_value={"status": "accepted", "trace": "trace.ndjson"},
            ) as capture:
                result = fuzz.run_seed(
                    Path("kv"), Path("lean"), path, 7, fuzz.Workload(), 30
                )
            self.assertEqual(result["status"], "coverage_incomplete")
            self.assertEqual(
                capture.call_args.kwargs["extra_env"]["CCF_KV_FUZZ_SEED"], "7"
            )

    def test_existing_rejection_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "test.stdout.txt").write_text("", encoding="utf-8")
            with patch.object(
                fuzz.trace, "run_case", return_value={"status": "rejected"}
            ):
                result = fuzz.run_seed(
                    Path("kv"), Path("lean"), path, 7, fuzz.Workload(), 30
                )
            self.assertEqual(result["status"], "rejected")
            self.assertIn("coverage_error", result)


class CampaignTests(unittest.TestCase):
    def exercise(self, statuses, keep_going=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "kv_test"
            checker = root / "checker"
            binary.write_bytes(b"test binary")
            checker.write_bytes(b"test checker")
            args = argparse.Namespace(
                binary=binary,
                checker=checker,
                output=root / "results",
                seed_start=17,
                seeds=len(statuses),
                threads=4,
                transactions=24,
                operations=8,
                timeout=30,
                keep_going=keep_going,
            )
            with patch.object(
                fuzz.trace, "inventory", return_value=[fuzz.CASE]
            ), patch.object(
                fuzz,
                "run_seed",
                side_effect=[{"status": status} for status in statuses],
            ) as run_seed, contextlib.redirect_stdout(
                io.StringIO()
            ):
                result = fuzz.run(args)
            paths = list(args.output.glob("campaign-*/report.json"))
            self.assertEqual(len(paths), 1)
            report = json.loads(paths[0].read_text(encoding="utf-8"))
            return result, report, run_seed.call_count

    def test_first_failure_stops_without_claiming_full_campaign(self):
        result, report, calls = self.exercise(["rejected", "accepted"])
        self.assertEqual(result, 2)
        self.assertEqual(calls, 1)
        self.assertEqual(report["state"], "stopped")
        self.assertEqual(report["requested_seeds"], 2)
        self.assertEqual(report["accepted_seeds"], 0)

    def test_keep_going_retains_failure(self):
        result, report, calls = self.exercise(["unsupported", "accepted"], True)
        self.assertEqual(result, 2)
        self.assertEqual(calls, 2)
        self.assertEqual(report["state"], "complete")
        self.assertEqual(report["accepted_seeds"], 1)

    def test_complete_campaign(self):
        result, report, calls = self.exercise(["accepted", "accepted"])
        self.assertEqual(result, 0)
        self.assertEqual(calls, 2)
        self.assertEqual(report["state"], "complete")
        self.assertEqual(report["accepted_seeds"], 2)


if __name__ == "__main__":
    unittest.main()
