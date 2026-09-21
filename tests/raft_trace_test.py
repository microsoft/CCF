# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import socket
import subprocess
import unittest
from unittest import mock

from raft_scenarios_runner import flatten_legacy_trace, preprocess_for_trace_validation
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

    def test_legacy_baseline_comparison(self):
        for function, args in (
            ("commit", {"idx": 7}),
            ("add_configuration", {"configuration": {"idx": 7, "nodes": {}, "rid": 7}}),
        ):
            with self.subTest(function=function):
                legacy = {"function": function, "state": {}}
                if function == "add_configuration":
                    legacy["configurations"] = []
                legacy["args"] = args
                if function == "commit":
                    legacy["configurations"] = []
                expected = {
                    "function": function,
                    "state": {},
                    **(
                        {"configurations": []}
                        if function == "add_configuration"
                        else {}
                    ),
                    **(args if function == "commit" else args["configuration"]),
                    **({"configurations": []} if function == "commit" else {}),
                }
                self.assertEqual(
                    msgpack.packb(flatten_legacy_trace(legacy)), msgpack.packb(expected)
                )
                self.assertIs(flatten_legacy_trace(expected), expected)
                self.assertIn("args", legacy)


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
