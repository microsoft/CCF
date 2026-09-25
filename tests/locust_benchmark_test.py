# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run with the e2e Python dependencies, without a CCF build or network."""

import argparse
import concurrent.futures
import csv
import dataclasses
import errno
import os
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import infra.locust_benchmark as benchmark

LOCUSTFILE = """
import os
from locust import User, constant, events, task
from infra.locust_benchmark_support import (
    add_common_arguments,
    register_steady_state_listeners,
)

@events.init_command_line_parser.add_listener
def arguments(parser):
    add_common_arguments(parser)
    commands = parser.add_subparsers(required=True)
    command = commands.add_parser("run")
    command.add_argument("--fail", action="store_true")

class TestUser(User):
    wait_time = constant(0.01)

    def on_start(self):
        self.environment.events.request.fire(
            request_type="test",
            name="ramp-only",
            response_time=1,
            response_length=1,
            exception=None,
        )

    @task
    def request(self):
        self.environment.events.request.fire(
            request_type="test",
            name="request",
            response_time=1,
            response_length=1,
            exception=RuntimeError("intentional workload failure")
                if self.environment.parsed_options.fail else None,
        )

if not os.environ.get("CCF_LOCUST_TEST_NO_READY"):
    register_steady_state_listeners(events)
"""


class LocustBenchmarkTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ccf-locust-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.locustfile = self.root / "locustfile.py"
        self.locustfile.write_text(LOCUSTFILE, encoding="ascii")
        self.args = argparse.Namespace(
            users=2, spawn_rate=2, measure_time_s=1, locust_processes=2
        )
        self.target = SimpleNamespace(
            get_public_rpc_host=lambda: "127.0.0.1",
            get_public_rpc_port=lambda: 443,
            session_ca=lambda: {"ca": "unused-by-test-user"},
        )
        self.workload = benchmark.Workload(
            str(self.locustfile),
            arguments=("run",),
            environment={"PYTHONPATH": str(Path(__file__).resolve().parent)},
        )
        self.real_popen = subprocess.Popen
        self.processes = []
        self.master_ports = set()
        self.ready_paths = []

    def network(self, name="network"):
        common_dir = self.root / name
        common_dir.mkdir()
        return SimpleNamespace(common_dir=str(common_dir))

    def popen(self, cmd, *, env):
        self.assertNotIn("--processes", cmd)
        if "--worker" in cmd:
            self.assertIn("--reset-stats", cmd)
            self.assertNotIn(benchmark.MASTER_READY_ENVIRONMENT_VARIABLE, env)
            self.assertEqual(cmd[cmd.index("--master-host") + 1], "127.0.0.1")
            port = int(cmd[cmd.index("--master-port") + 1])
            self.assertGreater(port, 0)
            # Workers must only be launched after the master owns this socket.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                with self.assertRaises(OSError) as error:
                    probe.bind(("127.0.0.1", port))
                self.assertEqual(error.exception.errno, errno.EADDRINUSE)
            self.master_ports.add(port)
        elif "--master" in cmd:
            ready_path = Path(env[benchmark.MASTER_READY_ENVIRONMENT_VARIABLE])
            self.assertFalse(ready_path.exists())
            self.assertEqual(ready_path.parent.stat().st_mode & 0o777, 0o700)
            self.ready_paths.append(ready_path)
            self.assertEqual(cmd[cmd.index("--master-bind-host") + 1], "127.0.0.1")
            self.assertEqual(cmd[cmd.index("--master-bind-port") + 1], "0")
            self.assertEqual(cmd[cmd.index("--expect-workers") + 1], "2")
            self.assertIn("--expect-workers-max-wait", cmd)
        with (self.root / "output").open("ab") as output:
            process = self.real_popen(cmd, env=env, stdout=output, stderr=output)
        self.processes.append(process)
        return process

    def assert_reaped(self):
        self.assertTrue(self.processes)
        for process in self.processes:
            self.assertIsNotNone(process.returncode)
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        for path in self.ready_paths:
            self.assertFalse(path.parent.exists())

    def run_locust(self, network, workload=None):
        return benchmark.run_locust(
            self.args, network, self.target, workload or self.workload
        )

    def test_occupied_default_port(self):
        network = self.network()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            try:
                occupied.bind(("127.0.0.1", 5557))
                occupied.listen()
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
            with patch.object(benchmark.subprocess, "Popen", side_effect=self.popen):
                stats = self.run_locust(network)
        self.assertGreater(int(stats["Request Count"]), 0)
        self.assertEqual(int(stats["Failure Count"]), 0)
        result = benchmark.parse_result(stats, self.args.measure_time_s, None)
        self.assertGreater(result.throughput, 0)
        self.assertNotIn(5557, self.master_ports)
        with (Path(network.common_dir) / "locust_stats.csv").open() as stats_file:
            for row in csv.DictReader(stats_file):
                if row["Name"] == "ramp-only":
                    self.assertEqual(int(row["Request Count"]), 0)
        self.assertEqual(len(self.processes), 3)
        self.assert_reaped()

    def test_concurrent_startups(self):
        networks = [self.network(f"network-{i}") for i in range(2)]
        with (
            patch.object(benchmark.subprocess, "Popen", side_effect=self.popen),
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            results = list(executor.map(self.run_locust, networks))
        self.assertTrue(all(int(stats["Request Count"]) > 0 for stats in results))
        self.assertEqual(len(self.master_ports), 2)
        self.assertEqual(len(self.processes), 6)
        self.assert_reaped()

    def test_workload_failure_is_not_swallowed(self):
        workload = dataclasses.replace(self.workload, arguments=("run", "--fail"))
        with (
            patch.object(benchmark.subprocess, "Popen", side_effect=self.popen),
            self.assertRaises(subprocess.CalledProcessError) as error,
        ):
            self.run_locust(self.network(), workload)
        self.assertEqual(error.exception.returncode, 1)
        self.assertIn(
            "intentional workload failure", (self.root / "output").read_text()
        )
        self.assert_reaped()

    def test_master_exits_before_readiness(self):
        workload = dataclasses.replace(
            self.workload, locust_file_name=str(self.root / "missing.py")
        )
        with (
            patch.object(benchmark.subprocess, "Popen", side_effect=self.popen),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            self.run_locust(self.network(), workload)
        self.assertEqual(len(self.processes), 1)
        self.assert_reaped()

    def test_missing_readiness_times_out_without_starting_workers(self):
        workload = dataclasses.replace(
            self.workload,
            environment={**self.workload.environment, "CCF_LOCUST_TEST_NO_READY": "1"},
        )
        with (
            patch.object(benchmark.subprocess, "Popen", side_effect=self.popen),
            patch.object(benchmark, "STARTUP_TIMEOUT_S", 2),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            self.run_locust(self.network(), workload)
        self.assertEqual(len(self.processes), 1)
        self.assert_reaped()

    def test_missing_worker_is_bounded(self):
        def popen(cmd, *, env):
            if "--worker" in cmd:
                cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
            return self.popen(cmd, env=env)

        with (
            patch.object(benchmark.subprocess, "Popen", side_effect=popen),
            patch.object(benchmark, "STARTUP_TIMEOUT_S", 2),
            self.assertRaises(subprocess.CalledProcessError) as error,
        ):
            self.run_locust(self.network())
        self.assertEqual(error.exception.returncode, 1)
        self.assertIn("Gave up waiting for workers", (self.root / "output").read_text())
        self.assert_reaped()

    def test_partial_worker_launch_cleans_up(self):
        def popen(cmd, *, env):
            if len(self.processes) == 2:
                raise OSError("worker launch failed")
            return self.popen(cmd, env=env)

        with (
            patch.object(benchmark.subprocess, "Popen", side_effect=popen),
            self.assertRaisesRegex(OSError, "worker launch failed"),
        ):
            self.run_locust(self.network())
        self.assertEqual(len(self.processes), 2)
        self.assert_reaped()

    def test_cleanup_kills_and_reaps_unresponsive_children(self):
        with self.real_popen(
            [
                sys.executable,
                "-c",
                (
                    "import signal, time; "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                    "print('ready', flush=True); time.sleep(60)"
                ),
            ],
            stdout=subprocess.PIPE,
            text=True,
        ) as process:
            self.assertEqual(process.stdout.readline(), "ready\n")
            with patch.object(benchmark, "SHUTDOWN_TIMEOUT_S", 0.1):
                benchmark.stop_processes([process])
            self.assertEqual(process.returncode, -signal.SIGKILL)
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)

    def test_timeout_and_interrupt_clean_up_all_children(self):
        for failure in (
            subprocess.TimeoutExpired(["locust"], 1),
            KeyboardInterrupt(),
        ):
            with self.subTest(failure=type(failure).__name__):
                master, *workers = [Mock(args=["locust"]) for _ in range(3)]
                children = [master, *workers]
                for process in children:
                    process.poll.return_value = None
                    process.wait.return_value = 0
                master.wait.side_effect = [failure, 0, 0]
                with (
                    patch.object(benchmark, "wait_for_master", return_value=12345),
                    patch.object(benchmark.subprocess, "Popen", side_effect=children),
                    self.assertRaises(type(failure)),
                ):
                    self.run_locust(self.network(type(failure).__name__))
                for process in children:
                    process.terminate.assert_called_once()
                    self.assertGreaterEqual(process.wait.call_count, 2)
                self.assertEqual(
                    master.wait.call_args_list[0].kwargs["timeout"],
                    benchmark.STARTUP_TIMEOUT_S
                    + 1
                    + self.args.measure_time_s
                    + benchmark.RUN_TIME_MARGIN_S
                    + benchmark.SHUTDOWN_TIMEOUT_S,
                )

    def test_invalid_readiness_and_clean_early_exit(self):
        ready_path = self.root / "master.port"
        master = Mock(args=["locust"])
        master.poll.return_value = None
        for content in ("0", "65536", "not a port"):
            with self.subTest(content=content):
                ready_path.write_text(content, encoding="ascii")
                with self.assertRaises((RuntimeError, ValueError)):
                    benchmark.wait_for_master(master, ready_path)
        ready_path.unlink()
        master.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, "exited before publishing"):
            benchmark.wait_for_master(master, ready_path)

    def test_worker_exit_failure_and_shutdown_timeout(self):
        for exit_code in (7, subprocess.TimeoutExpired(["locust"], 1)):
            with self.subTest(exit_code=exit_code):
                master, *workers = [Mock(args=["locust"]) for _ in range(3)]
                children = [master, *workers]
                for process in children:
                    process.poll.return_value = None
                    process.wait.return_value = 0
                workers[0].wait.side_effect = [exit_code, 0, 0]
                error_type = (
                    subprocess.CalledProcessError
                    if isinstance(exit_code, int)
                    else subprocess.TimeoutExpired
                )
                with (
                    patch.object(benchmark, "wait_for_master", return_value=12345),
                    patch.object(benchmark.subprocess, "Popen", side_effect=children),
                    self.assertRaises(error_type) as error,
                ):
                    self.run_locust(self.network(error_type.__name__))
                if isinstance(exit_code, int):
                    self.assertEqual(error.exception.returncode, exit_code)
                for process in children:
                    process.terminate.assert_called_once()
                    self.assertGreaterEqual(process.wait.call_count, 2)

    def test_local_mode(self):
        self.args.locust_processes = 0
        with patch.object(benchmark.subprocess, "Popen", side_effect=self.popen):
            stats = self.run_locust(self.network())
        self.assertGreater(int(stats["Request Count"]), 0)
        self.assertEqual(len(self.processes), 1)
        self.assert_reaped()


if __name__ == "__main__":
    unittest.main()
