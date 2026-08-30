# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import pathlib
import tempfile
import unittest
from unittest import mock

import infra.recovery_trace

VERSION = "ccf.recovery_decision_protocol.trace/1"
EXPECTED_LOCATIONS = ["A", "B"]


def event(node, sequence, kind, **extra):
    value = {
        "version": VERSION,
        "instance": "synthetic",
        "expected_locations": EXPECTED_LOCATIONS,
        "node": node,
        "sequence": sequence,
        "kind": kind,
        "pre": "GOSSIPING",
        "post": "GOSSIPING",
    }
    value.update(extra)
    return value


class FakeNode:
    def __init__(self, path, name=None):
        self.path = path
        self.name = name
        self.remote = object() if name is not None else None

    def get_logs(self):
        return str(self.path), None

    def get_sealing_recovery_location(self):
        return {"name": self.name}


class FakeNetwork:
    def __init__(self, nodes, common_dir):
        self.nodes = nodes
        self.common_dir = common_dir


class RecoveryTraceTest(unittest.TestCase):
    def test_extract_linearize_and_validate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            a_log = root / "a.out"
            b_log = root / "b.out"
            fixture = (
                pathlib.Path(__file__).resolve().parents[2]
                / "lean"
                / "disaster-recovery"
                / "fixtures"
                / "accepted-multinode.ndjson"
            )
            with open(fixture, encoding="utf-8") as trace:
                events = [json.loads(line) for line in trace if line.strip()]
            a_events = [item for item in events if item["node"] == "A"]
            b_events = [item for item in events if item["node"] == "B"]
            a_log.write_text(
                "".join(
                    f"[info] RDP_TRACE {json.dumps(trace_event)}\n"
                    for trace_event in a_events
                ),
                encoding="utf-8",
            )
            b_log.write_text(
                "".join(
                    json.dumps({"msg": f"RDP_TRACE {json.dumps(trace_event)}"}) + "\n"
                    for trace_event in b_events
                ),
                encoding="utf-8",
            )
            network = FakeNetwork(
                [FakeNode(b_log), FakeNode(a_log)],
                directory,
            )

            extracted = infra.recovery_trace.extract_events(network.nodes)
            ordered = infra.recovery_trace.linearize(extracted)
            positions = {
                item["message_id"]: index
                for index, item in enumerate(ordered)
                if "message_id" in item
            }
            for index, item in enumerate(ordered):
                if "caused_by" in item:
                    self.assertLess(positions[item["caused_by"]], index)

            trace_path = infra.recovery_trace.validate_recovery_trace(
                network, "synthetic"
            )
            self.assertTrue(trace_path.is_file())

    def test_rejects_non_contiguous_sequence(self):
        broken = [
            event("A", 0, "start"),
            event("A", 2, "timeout"),
        ]
        with self.assertRaisesRegex(ValueError, "not contiguous"):
            infra.recovery_trace.linearize(broken)

    def test_rejects_unresolved_cause(self):
        broken = [
            event("A", 0, "start"),
            event(
                "A",
                1,
                "gossip_accepted",
                message_id="receive",
                caused_by="missing-send",
                source="B",
                view=1,
                seqno=1,
            ),
        ]
        with self.assertRaisesRegex(ValueError, "no matching send"):
            infra.recovery_trace.linearize(broken)

    def test_disabled_validation_preserves_default_tests(self):
        with mock.patch.dict(
            "os.environ",
            {infra.recovery_trace.TRACE_VALIDATOR_ENV: ""},
            clear=False,
        ):
            self.assertIsNone(
                infra.recovery_trace.validate_recovery_trace_if_enabled(
                    FakeNetwork([], "."), "disabled", "QUORUM"
                )
            )

    def test_waits_for_terminal_scenario_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = pathlib.Path(directory) / "a.out"
            events = [
                event("A", 0, "start"),
                event("A", 1, "open", open_kind="QUORUM"),
                event("A", 2, "complete"),
            ]
            log_path.write_text(
                "".join(
                    f"RDP_TRACE {json.dumps(trace_event)}\n" for trace_event in events
                ),
                encoding="utf-8",
            )
            network = FakeNetwork(
                [FakeNode(log_path, "A")],
                directory,
            )
            self.assertEqual(
                infra.recovery_trace.wait_for_terminal_events(network, "QUORUM", 0.1),
                events,
            )


if __name__ == "__main__":
    unittest.main()
