# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import infra.locust_benchmark


class LocustBenchmarkTest(unittest.TestCase):
    def test_spawn_rate_must_be_positive(self):
        parser = argparse.ArgumentParser()
        infra.locust_benchmark.add_cli_arguments(parser)

        for spawn_rate in ("0", "-1"):
            with self.subTest(spawn_rate=spawn_rate), self.assertRaises(SystemExit):
                parser.parse_args(["--spawn-rate", spawn_rate])

        args = parser.parse_args(["--spawn-rate", "1"])
        self.assertEqual(args.spawn_rate, 1)

    def test_passes_secrets_in_environment_only(self):
        class Primary:
            @staticmethod
            def get_public_rpc_host():
                return "127.0.0.1"

            @staticmethod
            def get_public_rpc_port():
                return 8000

            @staticmethod
            def session_ca():
                return {"ca": "/path/to/ca.pem"}

        token = "secret-token"
        workload = infra.locust_benchmark.Workload(
            locust_file_name="workload.py",
            environment={
                infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE: token,
            },
        )
        args = SimpleNamespace(
            users=10,
            spawn_rate=5,
            measure_time_s=20,
            locust_processes=2,
        )
        network = SimpleNamespace(common_dir="/tmp")

        with mock.patch.object(
            infra.locust_benchmark.infra.net,
            "probably_free_local_port",
            return_value=12345,
        ), mock.patch.object(
            infra.locust_benchmark.subprocess, "run"
        ) as run, mock.patch.object(
            infra.locust_benchmark,
            "read_aggregated_stats",
            return_value={"Name": "Aggregated"},
        ):
            infra.locust_benchmark.run_locust(args, network, Primary(), workload)

        command = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertNotIn(token, " ".join(command))
        self.assertEqual(
            environment[infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE], token
        )
        self.assertTrue(run.call_args.kwargs["check"])

    def test_reads_aggregated_stats(self):
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", delete=False
        ) as stats_file:
            stats_file.write("Type,Name,Request Count,Failure Count\n")
            stats_file.write("POST,/endpoint,5,0\n")
            stats_file.write(",Aggregated,5,0\n")
            stats_path = stats_file.name

        self.addCleanup(os.unlink, stats_path)
        stats = infra.locust_benchmark.read_aggregated_stats(stats_path)
        self.assertEqual(stats["Request Count"], "5")

    def test_rejects_missing_aggregated_stats(self):
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", delete=False
        ) as stats_file:
            stats_file.write("Type,Name,Request Count,Failure Count\n")
            stats_file.write("POST,/endpoint,5,0\n")
            stats_path = stats_file.name

        self.addCleanup(os.unlink, stats_path)
        with self.assertRaisesRegex(RuntimeError, "No Aggregated row"):
            infra.locust_benchmark.read_aggregated_stats(stats_path)

    def test_parses_valid_result(self):
        result = infra.locust_benchmark.parse_result(
            {
                "Request Count": "2000",
                "Failure Count": "0",
                "Requests/s": "100",
                "Median Response Time": "10",
                "99%": "25",
                "Min Response Time": "2",
            },
            measure_time_s=20,
            memory=None,
        )
        self.assertEqual(result.throughput, 100)
        self.assertEqual(result.p99_latency_ms, 25)

    def test_rejects_short_measurement(self):
        with self.assertRaisesRegex(RuntimeError, "run was cut short"):
            infra.locust_benchmark.parse_result(
                {
                    "Request Count": "500",
                    "Failure Count": "0",
                    "Requests/s": "100",
                    "Median Response Time": "10",
                    "99%": "25",
                    "Min Response Time": "2",
                },
                measure_time_s=20,
                memory=None,
            )

    def test_rejects_failed_requests(self):
        with self.assertRaisesRegex(RuntimeError, "3 failures out of 2000"):
            infra.locust_benchmark.parse_result(
                {
                    "Request Count": "2000",
                    "Failure Count": "3",
                    "Requests/s": "100",
                    "Median Response Time": "10",
                    "99%": "25",
                    "Min Response Time": "2",
                },
                measure_time_s=20,
                memory=None,
            )


if __name__ == "__main__":
    unittest.main()
