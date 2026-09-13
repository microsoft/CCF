# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Static/control-plane regression tests; no CCF process or benchmark is run."""

import contextlib
import copy
import importlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class DiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="ccf-rpc-static-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.environment = patch.dict(
            os.environ, {"CCF_RPC_DIAGNOSTIC_ROOT": cls.temporary.name}
        )
        cls.environment.start()
        cls.addClassCleanup(cls.environment.stop)
        cls.common = importlib.import_module("common")
        cls.measure = importlib.import_module("measure")
        cls.controller = importlib.import_module("run")
        cls.report = importlib.import_module("report")
        cls.addClassCleanup(cls.measure._run_lock.close)

    def statistics(self, users=320, duration=20, failures=0):
        rows = [
            {
                "Name": "Aggregated",
                "Request Count": str(duration * 10000),
                "Failure Count": str(failures),
                "Requests/s": "10000",
            }
        ]
        markers = [
            {
                "wall_time": 100,
                "line": f'All users spawned: {{"Writer": {users}}} ({users} total users)',
            },
            {"wall_time": 100.1, "line": "Resetting stats"},
        ]
        return rows, markers

    def probe(self, baseline=False):
        stages = {}
        for name in self.common.SHARED_STAGES | self.common.PR_STAGES:
            count = 0 if baseline and name in self.common.PR_STAGES else 10
            bins = [0] * 64
            bins[2] = count
            stages[name] = {
                "count": count,
                "bins": bins,
                "max_ns": 3 if count else 0,
                "total_ns": count * 3,
            }
        return {"errors": 0, "stages": stages}

    def test_fixed_revisions_and_matrix(self):
        self.assertEqual(
            self.common.REVISIONS,
            {
                "base": "31f5f9fe14972cda34f7f44e258557f4dc574b51",
                "pr": "1e050d85a9ce04838a0d73e70cb834bf7b2f8f72",
            },
        )
        plan = self.common.measurement_plan()
        self.assertEqual(len(plan), 22)
        expected = {
            ("pristine", 2): 6,
            ("pristine", 20): 4,
            ("cache", 2): 4,
            ("read_ahead", 2): 4,
        }
        for (category, interval), count in expected.items():
            selected = [
                item
                for item in plan
                if item["category"] == category and item["interval_ms"] == interval
            ]
            self.assertEqual(len(selected), count)
            self.assertNotEqual(selected[0]["variant"], selected[2]["variant"])
        for interval in (2, 20):
            self.assertEqual(
                {
                    item["variant"]
                    for item in plan
                    if item["category"] == "queue" and item["interval_ms"] == interval
                },
                {"base_queue", "pr_queue"},
            )

    def test_workflow_remains_one_manual_only_unprivileged_pool_job(self):
        yaml = importlib.import_module("yaml")
        repository = self.common.HERE.parents[1]
        document = yaml.load(
            (repository / ".github/workflows/bencher.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual(set(document["on"]), {"workflow_dispatch"})
        self.assertEqual(document["permissions"], "read-all")
        self.assertEqual(len(document["jobs"]), 1)
        job = next(iter(document["jobs"].values()))
        self.assertIn("self-hosted", job["runs-on"])
        self.assertIn("1ES.Pool=gha-vmss-d16av6-ci", job["runs-on"])
        self.assertEqual(
            job["container"]["image"], "mcr.microsoft.com/azurelinux/base/core:3.0"
        )
        self.assertEqual(job["container"]["options"], "--user root")
        self.assertLessEqual(int(job["timeout-minutes"]), 120)
        self.assertIn(
            "./.github/actions/install-ci-dependencies",
            [step.get("uses") for step in job["steps"]],
        )

    def test_statistics_reject_invalid_measurements(self):
        _, duration, marker = self.measure.validate_statistics(*self.statistics())
        self.assertEqual((duration, marker), (20, 100))
        for options in (
            {"users": 319},
            {"duration": 18},
            {"duration": 22},
            {"duration": 0},
            {"failures": 1},
        ):
            with self.subTest(options=options), self.assertRaises(RuntimeError):
                self.measure.validate_statistics(*self.statistics(**options))
        rows, markers = self.statistics()
        with self.assertRaises(RuntimeError):
            self.measure.validate_statistics(rows, markers[:1])

    def test_history_requires_steady_concurrency(self):
        rows = [
            {"Name": "Aggregated", "Timestamp": str(103 + n), "User Count": "320"}
            for n in range(8)
        ]
        self.assertEqual(
            self.measure.validate_history(rows, 100),
            {"interior_samples": 8, "user_count": 320},
        )
        rows[3]["User Count"] = "319"
        with self.assertRaises(RuntimeError):
            self.measure.validate_history(rows, 100)

    def test_stage_histograms_and_expected_baseline_absence(self):
        base = self.controller.stage_summary(self.probe(baseline=True), "base")
        self.assertEqual(set(base), self.common.SHARED_STAGES)
        pr = self.controller.stage_summary(self.probe(), "pr")
        self.assertEqual(set(pr), self.common.SHARED_STAGES | self.common.PR_STAGES)
        self.assertEqual(pr["rx_queue"]["p50_upper_ms"], 3 / 1e6)
        self.assertEqual(pr["rx_queue"]["p99_upper_ms"], 3 / 1e6)
        with self.assertRaises(RuntimeError):
            self.controller.stage_summary(self.probe(baseline=True), "pr")
        bad = self.probe()
        bad["stages"]["rx_queue"]["count"] += 1
        with self.assertRaises(RuntimeError):
            self.controller.stage_summary(bad, "pr")
        bad = self.probe()
        bad["errors"] = 1
        with self.assertRaises(RuntimeError):
            self.controller.stage_summary(bad, "pr")

    def test_pidfd_gates_only_the_identified_server_inside_the_window(self):
        sample = {"own": {42: {"role": "server"}, 43: {"role": "locust"}}}
        gate = self.controller.QueueGate(lambda *_: copy.deepcopy(sample))
        gate.marker_callback(40, {"wall_time": 100, "line": "All users spawned"})
        with (
            patch.object(self.controller.time, "time", return_value=102.5),
            patch.object(self.controller.os, "pidfd_open", return_value=99) as opened,
            patch.object(self.controller.signal, "pidfd_send_signal") as signalled,
            patch.object(self.controller.os, "close") as closed,
        ):
            gate.collect(40, {})
            opened.assert_called_once_with(42)
            signalled.assert_called_once_with(99, self.controller.signal.SIGRTMIN + 6)
            with patch.object(self.controller.time, "time", return_value=118.5):
                gate.collect(40, {})
            self.assertEqual(
                signalled.call_args.args, (99, self.controller.signal.SIGRTMIN + 7)
            )
            closed.assert_called_once_with(99)
        self.assertEqual(gate.state[40]["off"] - gate.state[40]["on"], 16)
        self.assertIsNone(gate.state[40]["pidfd"])

    def test_negative_counters_fail(self):
        with self.assertRaises(RuntimeError):
            self.measure.rates({"read_count": 10}, {"read_count": 9}, 1)

    def test_paired_summary_never_includes_probe_throughput(self):
        results = []
        for index, spec in enumerate(self.common.measurement_plan()):
            throughput = {
                "base": 100,
                "pr": 80,
                "pr_cached": 88,
                "pr_read_ahead": 84,
            }.get(spec["variant"], 100000)
            results.append(
                {**spec, "id": str(index), "throughput": throughput, "accepted": True}
            )
        summary = self.controller.paired_summary(results)
        self.assertTrue(all(item["complete"] for item in summary))
        self.assertAlmostEqual(summary[0]["geometric_ratio"], 0.8)
        self.assertAlmostEqual(summary[1]["geometric_ratio"], 0.8)
        self.assertAlmostEqual(summary[2]["geometric_ratio"], 1.1)
        self.assertAlmostEqual(summary[3]["geometric_ratio"], 1.05)

    def test_export_refuses_private_key_content(self):
        with tempfile.TemporaryDirectory(prefix="ccf-rpc-export-") as directory:
            root = Path(directory)
            source = root / "bad.log"
            source.write_text("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n")
            with self.assertRaises(RuntimeError):
                self.report.safe_copy(source, root / "artifact.log")
            self.assertFalse((root / "artifact.log").exists())
            source.write_text('{"private_key_file": "node_private_key.pem"}')
            self.report.safe_copy(source, root / "artifact.json")
            self.assertEqual(source.read_bytes(), (root / "artifact.json").read_bytes())

    def test_report_does_not_export_workspace_keys_or_ledgers(self):
        root = self.common.ROOT
        workspace = root / "runs" / "fixture" / "workspace" / "node"
        workspace.mkdir(parents=True)
        (workspace / "node_private_key.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n"
        )
        (workspace / "ledger").mkdir()
        (workspace / "ledger" / "ledger_1").write_text("not-for-export")
        (workspace / "node.config.json").write_text('{"worker_threads": 2}')
        with (
            tempfile.TemporaryDirectory(prefix="ccf-rpc-artifacts-") as directory,
            patch.dict(
                os.environ,
                {
                    "CCF_RPC_DIAGNOSTIC_ARTIFACTS": str(Path(directory) / "artifacts"),
                    "GITHUB_STEP_SUMMARY": str(Path(directory) / "summary.log"),
                },
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.report.main()
            exported = list((Path(directory) / "artifacts").rglob("*"))
            self.assertTrue(any(path.name == "node.config.json" for path in exported))
            self.assertFalse(any("ledger" in path.name for path in exported))
            self.assertFalse(any(path.suffix == ".pem" for path in exported))
            status = json.loads(
                (
                    Path(directory) / "artifacts/data/operational-summary.json"
                ).read_text()
            )
            self.assertFalse(status["operational_success"])

    def test_exact_revision_patches_apply_and_reverse_without_extra_changes(self):
        repository = self.common.HERE.parents[1]
        source_git = os.environ.get("CCF_DIAGNOSTIC_GIT", "git")
        for version, patch_name in (
            ("base", "queue_base.patch"),
            ("pr", "queue_pr.patch"),
            ("pr", "poll_interest_cache.patch"),
            ("pr", "read_ahead.patch"),
        ):
            with (
                self.subTest(patch=patch_name),
                tempfile.TemporaryDirectory(prefix="ccf-rpc-patch-") as directory,
            ):
                root = Path(directory)
                patch_path = self.common.HERE / patch_name
                paths = [
                    line.removeprefix("+++ b/")
                    for line in patch_path.read_text().splitlines()
                    if line.startswith("+++ b/")
                ]
                originals = {}
                for name in paths:
                    contents = subprocess.check_output(
                        [
                            source_git,
                            "show",
                            f"{self.common.REVISIONS[version]}:{name}",
                        ],
                        cwd=repository,
                    )
                    originals[name] = contents
                    destination = root / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(contents)
                for arguments in (
                    ["--check"],
                    [],
                    ["--reverse", "--check"],
                    ["--reverse"],
                ):
                    completed = subprocess.run(
                        [
                            "git",
                            "apply",
                            "--whitespace=error-all",
                            *arguments,
                            str(patch_path),
                        ],
                        cwd=root,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                for name, contents in originals.items():
                    self.assertEqual((root / name).read_bytes(), contents)

    def test_deferred_output_name_without_building_cpp(self):
        for output in ("basic_queue_probe", "basic_poll_cached", "basic_read_ahead"):
            with tempfile.TemporaryDirectory(prefix="ccf-rpc-cmake-") as directory:
                root = Path(directory)
                (root / "CMakeLists.txt").write_text(
                    "cmake_minimum_required(VERSION 3.24)\n"
                    "project(diagnostic_syntax NONE)\n"
                    "add_custom_target(basic)\n"
                    "function(check_output)\n"
                    "  get_target_property(actual basic OUTPUT_NAME)\n"
                    '  if(NOT actual STREQUAL "${CCF_DIAGNOSTIC_OUTPUT_NAME}")\n'
                    '    message(FATAL_ERROR "Deferred output name was not applied")\n'
                    "  endif()\n"
                    "endfunction()\n"
                    "cmake_language(DEFER CALL check_output)\n"
                )
                subprocess.run(
                    [
                        "cmake",
                        "-S",
                        str(root),
                        "-B",
                        str(root / "build"),
                        "-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES="
                        + str(self.common.HERE / "output_name.cmake"),
                        f"-DCCF_DIAGNOSTIC_OUTPUT_NAME={output}",
                    ],
                    check=True,
                    capture_output=True,
                )


if __name__ == "__main__":
    unittest.main()
