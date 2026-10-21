# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import pathlib
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import raft_trace
import raft_trace_capture

import msgpack


class CaptureTests(unittest.TestCase):
    def collect(self, sequences):
        def driver(args, **_):
            with socket.create_connection((args[-2], int(args[-1]))) as peer:
                for sequence in sequences:
                    peer.sendall(
                        msgpack.packb(
                            [
                                "ccf.raft_trace",
                                msgpack.ExtType(0, struct.pack(">II", 1, 0)),
                                {
                                    "process_id": "one",
                                    "h_ts": sequence,
                                    "msg": {"cmd": "state_all"},
                                },
                            ]
                        )
                    )
            return subprocess.CompletedProcess(args, 0, "native stdout\n", "")

        with patch("raft_trace.subprocess.run", side_effect=driver):
            return raft_trace.run_driver("driver", "scenario")

    def test_preserves_order_and_rejects_gaps(self):
        _, records = self.collect([0, 1, 2])
        self.assertEqual([row["h_ts"] for row in records], [0, 1, 2])
        for sequences in ([1, 0], [0, 0], [0, 2], [1]):
            with self.subTest(sequences=sequences), self.assertRaisesRegex(
                AssertionError, "trace sequence"
            ):
                self.collect(sequences)

    def test_duplicate_keys_fail(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            raft_trace.unique_map([("msg", 1), ("msg", 2)])

    def test_writes_records_without_protocol_mapping(self):
        result, records = self.collect([0, 1])
        for phase in ("pre", "post"):
            records.append(
                {
                    "process_id": "one",
                    "h_ts": len(records),
                    "msg": {
                        "function": "operation_boundary",
                        "operation_id": 0,
                        "operation": "periodic",
                        "phase": phase,
                        "state": {"node_id": "0"},
                        "configurations": [],
                        "peers": [],
                    },
                }
            )
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "nested" / "trace.stdout"
            with patch("raft_trace.run_driver", return_value=(result, records)):
                raft_trace_capture.capture("driver", "scenario", output)
            observed = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(
                observed, [{"tag": "ccf.raft_trace", **r} for r in records]
            )
            self.assertEqual(
                pathlib.Path(str(output) + ".driver.stdout").read_text(), result.stdout
            )

    def test_legacy_adapter_omits_only_boundary_observations(self):
        command = {"cmd": "periodic_one,0,10"}
        boundary = {"function": "operation_boundary", "phase": "pre"}
        callback = {"function": "send_append_entries"}
        records = [
            {"process_id": "one", "h_ts": index, "msg": message}
            for index, message in enumerate((command, boundary, callback))
        ]
        self.assertEqual(
            raft_trace.as_log_lines(records),
            [
                {"tag": "raft_trace", **command},
                {"tag": "raft_trace", "h_ts": "2", "msg": callback},
            ],
        )

    def test_failed_capture_cannot_leave_success_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scenarios = root / "scenarios"
            scenarios.mkdir()
            (scenarios / "one").touch()
            output = root / "output"
            output.mkdir()
            trace = output / "one.stdout"
            trace.write_text("stale success")
            result = subprocess.CompletedProcess([], 1, "native failure", "")
            with (
                patch("sys.argv", ["capture", "driver", str(scenarios), str(output)]),
                patch("raft_trace.run_driver", return_value=(result, [])),
                self.assertRaisesRegex(RuntimeError, "1/1 captures failed"),
            ):
                raft_trace_capture.main()
            self.assertFalse(trace.exists())
            self.assertTrue((output / "one.partial").exists())
            self.assertEqual(
                (output / "one.stdout.driver.stdout").read_text(), "native failure"
            )


if __name__ == "__main__":
    unittest.main()
