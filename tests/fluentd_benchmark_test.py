# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import socket
import unittest
from types import SimpleNamespace
from unittest import mock

import infra.locust_benchmark
from infra.fluentd import Collector

import msgpack


class CollectorTest(unittest.TestCase):
    def test_invalid_node_count(self):
        with self.assertRaises(ValueError):
            Collector(0)

    def test_empty(self):
        with Collector() as collector:
            self.assertEqual(collector.endpoint["queue_capacity"], 4096)
        self.assertEqual(collector.records, 0)
        self.assertEqual(collector.bytes, 0)

    def test_two_fragmented_streams(self):
        with Collector() as collector:
            total = 0
            for process_id in ("node0", "node1"):
                with socket.create_connection(
                    ("127.0.0.1", int(collector.endpoint["port"]))
                ) as connection:
                    frame = msgpack.packb(
                        [
                            "ccf.raft_trace",
                            msgpack.ExtType(0, b"\x00" * 8),
                            {"process_id": process_id},
                        ]
                    )
                    connection.sendall(frame[:3])
                    connection.sendall(frame[3:] + frame * 100)
                    total += len(frame) * 101
        self.assertEqual(collector.records, 202)
        self.assertEqual(collector.bytes, total)
        self.assertEqual(collector.processes, {"node0", "node1"})

    def test_invalid_tag(self):
        with self.assertRaisesRegex(
            RuntimeError, "Unexpected trace tag"
        ), Collector() as collector, socket.create_connection(
            ("127.0.0.1", int(collector.endpoint["port"]))
        ) as connection:
            connection.sendall(msgpack.packb(["wrong", 0, {}]))

    def test_shutdown_with_open_peer(self):
        connection = None
        try:
            with Collector() as collector:
                connection = socket.create_connection(
                    ("127.0.0.1", int(collector.endpoint["port"]))
                )
            self.assertFalse(collector.thread.is_alive())
        finally:
            if connection is not None:
                connection.close()


class BenchmarkCollectorTest(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(
            nodes=["node0", "node1", "node2"],
            binary_dir=".",
            debug_nodes=[],
            pdb=False,
            observability=None,
            label="benchmark",
            measure_time_s=20,
        )
        network_factory = self.enterContext(
            mock.patch("infra.locust_benchmark.infra.network.network")
        )
        self.network = network_factory.return_value.__enter__.return_value
        self.network.find_primary.return_value = (mock.Mock(), None)
        self.result = infra.locust_benchmark.Result(1000, 5, 10, 1, None, "tx")
        self.enterContext(
            mock.patch(
                "infra.locust_benchmark.infra.proc.get_proc_memory_stats",
                return_value=None,
            )
        )
        self.enterContext(
            mock.patch("infra.locust_benchmark.parse_result", return_value=self.result)
        )
        self.write_counts = self.enterContext(mock.patch("pathlib.Path.write_text"))
        self.run_locust = self.enterContext(
            mock.patch("infra.locust_benchmark.run_locust")
        )
        self.prepare = mock.Mock(
            return_value=infra.locust_benchmark.Workload("locustfile.py")
        )

    def emit(self, count):
        endpoint = self.network.start_and_open.call_args.args[0].observability[
            "fluentd"
        ]
        for index in range(count):
            with socket.create_connection(
                (endpoint["host"], int(endpoint["port"]))
            ) as connection:
                connection.sendall(
                    msgpack.packb(
                        [
                            "ccf.raft_trace",
                            msgpack.ExtType(0, b"\x00" * 8),
                            {"process_id": f"node{index}"},
                        ]
                    )
                )

    @mock.patch.dict("os.environ", {"CCF_BENCHMARK_FLUENTD": "1"})
    def test_every_node_exports_without_mutating_arguments(self):
        self.run_locust.side_effect = lambda *_: self.emit(len(self.args.nodes))
        result = infra.locust_benchmark.measure(self.args, 2, self.prepare)
        self.assertIs(result, self.result)
        self.assertIsNone(self.args.observability)
        started_args = self.network.start_and_open.call_args.args[0]
        self.assertEqual(started_args.label, self.args.label)
        self.assertEqual(started_args.sig_ms_interval, 2)
        self.assertEqual(started_args.observability["fluentd"]["queue_capacity"], 4096)
        counts = json.loads(self.write_counts.call_args.args[0])
        self.assertEqual(counts["records"], 3)
        self.assertEqual(counts["processes"], 3)
        self.assertEqual(counts["expected_processes"], 3)
        self.assertGreater(counts["bytes"], 0)

    @mock.patch.dict("os.environ", {"CCF_BENCHMARK_FLUENTD": "1"})
    def test_missing_node_trace_fails(self):
        self.run_locust.side_effect = lambda *_: self.emit(1)
        with self.assertRaisesRegex(RuntimeError, "Every benchmark node"):
            infra.locust_benchmark.measure(self.args, 2, self.prepare)
        counts = json.loads(self.write_counts.call_args.args[0])
        self.assertEqual(counts["processes"], 1)
        self.assertEqual(counts["expected_processes"], 3)

    @mock.patch.dict("os.environ", {"CCF_BENCHMARK_FLUENTD": "0"})
    def test_disabled_mode_does_not_start_a_collector(self):
        with mock.patch("infra.fluentd.Collector") as collector:
            result = infra.locust_benchmark.measure(self.args, 2, self.prepare)
        self.assertIs(result, self.result)
        collector.assert_not_called()
        self.write_counts.assert_not_called()
        self.assertIs(self.network.start_and_open.call_args.args[0], self.args)

    @mock.patch.dict("os.environ", {"CCF_BENCHMARK_FLUENTD": "invalid"})
    def test_invalid_mode_fails(self):
        with self.assertRaisesRegex(ValueError, "must be 0 or 1"):
            infra.locust_benchmark.measure(self.args, 2, self.prepare)
        self.network.start_and_open.assert_not_called()

    @mock.patch.dict("os.environ", {"CCF_BENCHMARK_FLUENTD": "1"})
    def test_explicit_observability_is_not_overwritten(self):
        self.args.observability = {"fluentd": {"host": "127.0.0.1", "port": "24224"}}
        with self.assertRaisesRegex(ValueError, "cannot override"):
            infra.locust_benchmark.measure(self.args, 2, self.prepare)
        self.network.start_and_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
