# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import socket
import unittest

from fluentd_benchmark import Collector

import msgpack


class CollectorTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
