# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Regression checks for split KV capture and replay."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import kv_trace_validation as validation


class CaptureTests(unittest.TestCase):
    def run_capture(self, checker, statuses, coverage_error=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "trace.ndjson").touch()
            args = SimpleNamespace(
                output=directory, binary=Path("kv_test"), checker=checker, timeout=1
            )
            with (
                patch.object(validation.tempfile, "mkdtemp", return_value=temporary),
                patch.object(
                    validation,
                    "execute",
                    side_effect=[
                        subprocess.CompletedProcess([], status) for status in statuses
                    ],
                ) as execute,
                patch.object(
                    validation, "inspect_trace", side_effect=coverage_error
                ) as inspect,
            ):
                validation.check_trace(
                    args, "seed-0", validation.FUZZ_CASE, {validation.FUZZ_CASE}, seed=0
                )
                inspect.assert_called_once_with(
                    directory / "trace.ndjson", {validation.FUZZ_CASE}, True
                )
                return execute.call_args_list

    def test_capture_only_checks_coverage_without_checker(self):
        calls = self.run_capture(None, [0])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[0][0], "kv_test")
        self.assertEqual(calls[0].args[-1]["CCF_KV_FUZZ_SEED"], "0")

    def test_combined_mode_still_replays(self):
        calls = self.run_capture(Path("kv-replay"), [0, 0])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1].args[0][0], "kv-replay")

    def test_capture_only_rejects_failed_tests(self):
        with self.assertRaisesRegex(RuntimeError, "KV test 1"):
            self.run_capture(None, [1])

    def test_combined_mode_rejects_failed_tests(self):
        with self.assertRaisesRegex(RuntimeError, "KV test 1"):
            self.run_capture(Path("kv-replay"), [1, 0])

    def test_combined_mode_rejects_failed_replay(self):
        with self.assertRaisesRegex(RuntimeError, "Lean checker exited 1"):
            self.run_capture(Path("kv-replay"), [0, 1])

    def test_capture_only_rejects_missing_coverage(self):
        with self.assertRaisesRegex(RuntimeError, "missing coverage"):
            self.run_capture(None, [0], RuntimeError("missing coverage"))


if __name__ == "__main__":
    unittest.main()
