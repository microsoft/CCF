# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import socket
import subprocess
import unittest
from unittest import mock

from raft_scenarios_runner import (
    noop,
    preprocess_for_trace_validation,
    separate_log_lines,
)
from raft_trace import run_driver

import msgpack


class ReplayTest(unittest.TestCase):
    def test_flat_replay_input(self):
        nodes = {"node": {"address": "127.0.0.1:1234"}}
        configuration = {"idx": 1, "nodes": nodes, "rid": 1}
        messages = [
            {"function": "become_leader"},
            {"function": "replicate"},
            {"function": "add_configuration", **configuration},
            {"function": "replicate", "globally_committable": True},
            {"function": "commit", "idx": 2},
            {"function": "replicate"},
            {"function": "add_configuration", **configuration},
            {"function": "commit", "idx": 4},
        ]
        records = [
            json.dumps(
                {
                    "h_ts": index,
                    "msg": {
                        "state": {"node_id": "node"},
                        "configurations": [configuration],
                        **message,
                    },
                }
            )
            for index, message in enumerate(messages)
        ]
        replay = [
            json.loads(line)["msg"] for line in preprocess_for_trace_validation(records)
        ]
        self.assertEqual(
            [m["function"] for m in replay],
            ["bootstrap", "add_configuration", "commit"],
        )
        self.assertEqual(replay[0]["idx"], 2)
        self.assertEqual(replay[1]["nodes"], nodes)
        self.assertEqual(replay[1]["rid"], replay[1]["idx"])
        self.assertEqual(replay[2]["idx"], 4)
        self.assertTrue(all("args" not in message for message in replay))

    def test_only_collected_events_become_trace_lines(self):
        message = {"function": "commit", "idx": 7}
        record = {"process_id": "driver", "h_ts": 3, "msg": message}
        stdout = '<RaftDriver>step\n{"tag":"raft_trace","msg":"legacy"}\n'
        mermaid, log = separate_log_lines(stdout, [record], noop)
        self.assertEqual(mermaid, "step\n")
        self.assertEqual(
            json.loads(log),
            {"tag": "raft_trace", "h_ts": "3", "msg": message},
        )

    def test_empty_trace_stays_empty(self):
        _, log = separate_log_lines("", [], preprocess_for_trace_validation)
        self.assertEqual(log, "")


class CollectorTest(unittest.TestCase):
    def test_success_without_trace(self):
        for scenario in ("create_node,0\n", "pre_vote_enabled,true\n"):
            with self.subTest(scenario=scenario), mock.patch(
                "raft_trace.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ), mock.patch(
                "pathlib.Path.open", mock.mock_open(read_data=scenario)
            ), self.assertRaisesRegex(
                AssertionError, "No Raft trace records"
            ):
                run_driver("driver", "scenario", timeout=1)

    def test_scenario_without_commands(self):
        for scenario in ("", " \n# comment\n \t# comment\n", "====\ncreate_node,0\n"):
            with self.subTest(scenario=scenario), mock.patch(
                "raft_trace.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ), mock.patch("pathlib.Path.open", mock.mock_open(read_data=scenario)):
                result, records = run_driver("driver", "scenario", timeout=1)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(records, [])

    def test_command_trace(self):
        record = {
            "process_id": "driver",
            "h_ts": 0,
            "msg": {"cmd": "pre_vote_enabled,true"},
        }

        def driver(command, **kwargs):
            with socket.create_connection((command[-2], int(command[-1]))) as peer:
                peer.sendall(
                    msgpack.packb(
                        [
                            "ccf.raft_trace",
                            msgpack.ExtType(0, b"\x00\x00\x00\x01\x00\x00\x00\x00"),
                            record,
                        ]
                    )
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch("raft_trace.subprocess.run", side_effect=driver):
            result, records = run_driver("driver", "scenario", timeout=1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(records, [record])


if __name__ == "__main__":
    unittest.main()
