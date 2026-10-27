# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import raft_trace_capture
from raft_trace_capture_test import pack_record, write_driver


class ReplaySuiteTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)
        self.scenarios = self.root / "scenarios"
        self.raw = self.root / "raw"
        self.output = self.root / "output"
        for directory in (self.scenarios, self.raw, self.output):
            directory.mkdir()
        self.replayer = self.root / "replayer"
        self.replayer.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys, time\n"
            "text = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')\n"
            "if text == 'failure':\n"
            "    sys.exit('commitIndex: observed 1, model 2')\n"
            "if text == 'timeout':\n"
            "    time.sleep(30)\n"
            "if text == 'bad-output':\n"
            "    print('not JSON')\n"
            "    sys.exit(0)\n"
            "records = [json.loads(line) for line in text.splitlines()]\n"
            "print(json.dumps(dict(status='ok', instructions=3, actions=1, observations=2)))\n",
            encoding="utf-8",
        )
        self.replayer.chmod(0o755)

    def scenario(self, name, data=b"{}\n"):
        path = self.scenarios / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("state_all\n", encoding="utf-8")
        if data is not None:
            raw = self.raw / (name + ".stdout")
            raw.parent.mkdir(parents=True, exist_ok=True)
            raw.write_bytes(data)

    def run_suite(self, **kwargs):
        return raft_trace_capture.run_suite(
            self.scenarios,
            self.output,
            replayer=self.replayer,
            **kwargs,
        )

    def test_failures_do_not_skip_remaining_scenarios_or_leave_stale_success(self):
        for name, data in (
            ("01-missing", None),
            ("02-invalid-utf8", b"\xff\n"),
            ("03-mismatch", b"failure"),
            ("04-bad-output", b"bad-output"),
            ("05-valid", b"{}\n"),
        ):
            self.scenario(name, data)
            (self.output / (name + ".result.json")).write_text('{"status":"passed"}')
        summary = self.run_suite(raw_directory=self.raw)
        self.assertEqual((summary["passed"], summary["failed"]), (1, 4))
        self.assertIn(
            "commitIndex: observed 1, model 2", summary["results"][2]["error"]
        )
        self.assertEqual(summary["results"][-1]["status"], "passed")
        for result in summary["results"][:-1]:
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["stage"], "replay")
            stored = self.output / (result["scenario"] + ".result.json")
            self.assertEqual(json.loads(stored.read_text())["status"], "failed")

    def test_replayer_timeout_and_spawn_failure(self):
        self.scenario("one", b"timeout")
        summary = self.run_suite(raw_directory=self.raw, timeout=0.1)
        self.assertEqual(summary["failed"], 1)
        self.assertIn("timed out", summary["results"][0]["error"])
        self.replayer.unlink()
        summary = self.run_suite(raw_directory=self.raw)
        self.assertEqual(summary["failed"], 1)
        self.assertIn("No such file", summary["results"][0]["error"])

    def test_capture_failure_does_not_invoke_replay(self):
        self.scenario("one")
        (self.output / "one.stdout").write_text("stale success")
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        driver = write_driver(self.root, pack_record(record), b"partial", b"error", 3)
        self.replayer.unlink()
        summary = self.run_suite(driver=driver)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["results"][0]["stage"], "capture")
        self.assertIn("exited 3", summary["results"][0]["error"])
        self.assertFalse((self.output / "one.stdout").exists())
        self.assertTrue((self.output / "one.partial").exists())

    def test_invalid_inventory_removes_previous_summary(self):
        summary = self.output / "summary.json"
        for inventory in (self.scenarios, self.root / "missing"):
            summary.write_text('{"passed":56,"failed":0}')
            with self.assertRaises(ValueError):
                raft_trace_capture.run_suite(inventory, self.output, driver="unused")
            self.assertFalse(summary.exists())

    def test_artifact_collisions_are_rejected_before_changing_output(self):
        cases = [
            (False, ("one", "one.result.json/next")),
            (False, ("summary.json/next",)),
            (True, ("one", "one.result.json/next")),
            (True, ("one", "one.stdout/next")),
            (True, ("one", "one.partial/next")),
            (True, ("one", "one.stdout.driver.stdout/next")),
            (True, ("one", "one.stdout.driver.stderr/next")),
            (True, ("one", "one.stdout.driver.records.msgpack/next")),
            (True, ("one", "one.stdout.driver")),
            (True, ("summary.json/next",)),
        ]
        for capture, names in cases:
            with (
                self.subTest(capture=capture, names=names),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = pathlib.Path(directory)
                scenarios, output = root / "scenarios", root / "output"
                for name in names:
                    scenario = scenarios / name
                    scenario.parent.mkdir(parents=True, exist_ok=True)
                    scenario.write_text("state_all\n")
                source = (
                    {"driver": "unused"}
                    if capture
                    else {"raw_directory": self.raw, "replayer": self.replayer}
                )
                for existing in (False, True):
                    if existing:
                        output.mkdir()
                        (output / "summary.json").write_text("previous summary")
                    for _ in range(2):
                        with (
                            patch("raft_trace_capture.capture") as collect,
                            patch("raft_trace_capture.subprocess.run") as replay,
                            self.assertRaisesRegex(
                                ValueError, "Artifact path collision"
                            ),
                        ):
                            raft_trace_capture.run_suite(scenarios, output, **source)
                        collect.assert_not_called()
                        replay.assert_not_called()
                        if existing:
                            self.assertEqual(
                                list(output.iterdir()), [output / "summary.json"]
                            )
                            self.assertEqual(
                                (output / "summary.json").read_text(),
                                "previous summary",
                            )
                        else:
                            self.assertFalse(output.exists())

    def test_noncolliding_nested_artifacts_can_be_reused(self):
        names = [
            "nested/one",
            "nested/one.stdout",
            "nested/one.result.json",
            "summary.json",
        ]
        for name in names:
            self.scenario(name)
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        driver = write_driver(self.root, pack_record(record), b"", b"")
        for source in ({"raw_directory": self.raw}, {"driver": driver}):
            for _ in range(2):
                summary = self.run_suite(**source)
                self.assertEqual(
                    (summary["passed"], summary["failed"]), (len(names), 0)
                )
                for name in names:
                    result = self.output / (name + ".result.json")
                    self.assertEqual(json.loads(result.read_text())["status"], "passed")

    def test_output_overlap_is_rejected_before_modifying_inventory(self):
        self.scenario("summary.json")
        contents = (self.scenarios / "summary.json").read_bytes()
        alias = self.root / "alias"
        alias.symlink_to(self.scenarios, target_is_directory=True)
        for output in (
            self.scenarios,
            self.scenarios / "missing/nested",
            alias / "missing",
            self.root,
        ):
            with (
                self.subTest(output=output),
                self.assertRaisesRegex(ValueError, "disjoint"),
            ):
                raft_trace_capture.run_suite(self.scenarios, output, driver="unused")
            self.assertEqual((self.scenarios / "summary.json").read_bytes(), contents)
            self.assertFalse((self.scenarios / "missing").exists())

    def test_invalid_configuration(self):
        for kwargs in (
            {},
            {"driver": "unused", "raw_directory": self.raw},
            {"raw_directory": self.raw},
            {"driver": "unused", "timeout": 0},
            {"driver": "unused", "timeout": float("nan")},
            {"driver": "unused", "timeout": float("inf")},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                raft_trace_capture.run_suite(self.scenarios, self.output, **kwargs)

    def test_cli_returns_nonzero_for_any_failure(self):
        self.scenario("one", b"failure")
        result = subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(raft_trace_capture.__file__).resolve()),
                str(self.scenarios),
                str(self.output),
                "--raw-directory",
                str(self.raw),
                "--replayer",
                str(self.replayer),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("1/1 scenarios failed", result.stderr)
        self.assertEqual(
            json.loads((self.output / "summary.json").read_text())["failed"], 1
        )


class ReplayExecutableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = pathlib.Path(__file__).resolve().parents[1]
        package = source / "lean/ccf-raft"
        cls.replayer = pathlib.Path(
            os.environ.get(
                "CCF_RAFT_REPLAYER", package / ".lake/build/bin/ccfraft-replay"
            )
        ).resolve()
        if not cls.replayer.is_file():
            raise FileNotFoundError(
                "Build ccfraft-replay first, or set CCF_RAFT_REPLAYER to its executable"
            )

    def test_real_replayer_rejects_malformed_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scenarios, raw = root / "scenarios", root / "raw"
            scenarios.mkdir()
            raw.mkdir()
            for name, data in (
                ("encoding", b"\xff\n"),
                ("console", b"<RaftDriver> diagram\n"),
                ("empty", b""),
                ("legacy", b'{"tag":"raft_trace","cmd":"state_all"}\n'),
            ):
                (scenarios / name).write_text("scenario")
                (raw / (name + ".stdout")).write_bytes(data)
            summary = raft_trace_capture.run_suite(
                scenarios, root / "results", raw_directory=raw, replayer=self.replayer
            )
            self.assertEqual((summary["passed"], summary["failed"]), (0, 4))
            for result in summary["results"]:
                self.assertEqual(result["status"], "failed")
                self.assertIn(result["scenario"] + ".stdout", result["error"])

    def test_real_replayer_accepts_only_one_trace_argument(self):
        for args in ([], ["suite", "--output", "unused"]):
            result = subprocess.run(
                [str(self.replayer), *args], capture_output=True, check=False
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"usage: ccfraft-replay TRACE.ndjson", result.stderr)


if __name__ == "__main__":
    unittest.main()
