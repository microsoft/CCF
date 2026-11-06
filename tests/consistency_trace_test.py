# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Checks for the opt-in consistency trace recorder used by partitions_test."""

import contextlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

import infra.consistency_trace as ct
from infra.tx_status import TxStatus


def response(view, seqno, status_code=200, body=None):
    return SimpleNamespace(
        status_code=status_code,
        view=view,
        seqno=seqno,
        body=SimpleNamespace(json=lambda: body),
    )


def consensus(state, view):
    return response(
        None, None, body={"details": {"leadership_state": state, "current_view": view}}
    )


class FakeNode:
    def __init__(self, replies):
        self.local_node_id = 0
        self.replies = replies
        self.paths = []

    @contextlib.contextmanager
    def client(self, *args, **kwargs):
        def get(path):
            self.paths.append(path)
            reply = self.replies[path]
            return reply.pop(0) if isinstance(reply, list) else reply

        yield SimpleNamespace(get=get)


class FakeNetwork:
    def __init__(self, node, common_dir=None):
        self.node = node
        self.common_dir = common_dir
        self.find_primary_calls = 0

    def find_primary(self, nodes=None):
        self.find_primary_calls += 1
        return self.node, None


class Untouchable:
    def __getattr__(self, name):
        raise AssertionError(f"disabled recording used network.{name}")


def leader_read(view, seqno, after=None):
    return FakeNode(
        {
            "/node/consensus": [
                consensus("Leader", view),
                after or consensus("Leader", view),
            ],
            ct.READ_PATH: response(view, seqno),
        }
    )


def tvc_write(tx, txid):
    # As printed by tests/tvc.py for a write
    return [
        {"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": tx},
        {"action": "RwTxExecuteAction", "type": "RwTxExecute", "tx_id": txid, "tx": tx},
        {
            "action": "RwTxResponseAction",
            "type": "RwTxResponse",
            "tx": tx,
            "tx_id": txid,
        },
    ]


def tvc_status(txid, status):
    return {
        "action": f"Status{status}ResponseAction",
        "type": "TxStatusReceived",
        "tx_id": txid,
        "status": f"{status}Status",
    }


def tvc_read(tx, txid):
    return [
        {"action": "RoTxRequestAction", "type": "RoTxRequest", "tx": tx},
        {
            "action": "RoTxResponseAction",
            "type": "RoTxResponse",
            "tx": tx,
            "tx_id": txid,
        },
    ]


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / ct.FILE_NAME

    def tearDown(self):
        self.directory.cleanup()

    def records(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def test_format_and_contiguous_ids(self):
        trace = ct.ConsistencyTrace(self.path)
        lost, new = response(2, 10), response(4, 12)
        self.assertTrue(trace.write(lost))
        self.assertFalse(trace.write(response(None, None, status_code=503)))
        self.assertTrue(trace.write(new))
        self.assertTrue(trace.status(new, TxStatus.Committed))
        self.assertTrue(trace.primary_read(FakeNetwork(leader_read(4, 13))))
        self.assertTrue(trace.status(lost, TxStatus.Invalid))
        trace.close()
        self.assertEqual(
            self.records(),
            tvc_write(0, [2, 10])
            + tvc_write(1, [4, 12])
            + [tvc_status([4, 12], "Committed")]
            + tvc_read(2, [4, 13])
            + [tvc_status([2, 10], "Invalid")],
        )

    def test_status_recorded_once_per_write(self):
        trace = ct.ConsistencyTrace(self.path)
        write = response(2, 10)
        self.assertFalse(trace.status(write, TxStatus.Committed))
        trace.write(write)
        self.assertTrue(trace.status(write, TxStatus.Committed))
        self.assertFalse(trace.status(write, TxStatus.Committed))
        with self.assertRaises(AssertionError):
            trace.status(write, TxStatus.Pending)
        # A contradiction is kept so that replay rejects it
        self.assertTrue(trace.status(write, TxStatus.Invalid))
        trace.close()
        self.assertEqual(
            self.records()[3:],
            [tvc_status([2, 10], "Committed"), tvc_status([2, 10], "Invalid")],
        )

    def test_read_requires_leadership_in_read_view(self):
        trace = ct.ConsistencyTrace(self.path)
        cases = [
            leader_read(3, 20, after=consensus("Follower", 3)),
            leader_read(3, 20, after=consensus("Leader", 4)),
            leader_read(3, 20, after=None),
        ]
        cases[2].replies[ct.READ_PATH] = response(2, 20)
        for node in cases:
            self.assertFalse(trace.primary_read(FakeNetwork(node)))
        self.assertTrue(trace.primary_read(FakeNetwork(leader_read(3, 21))))
        trace.close()
        self.assertEqual(self.records(), tvc_read(0, [3, 21]))

    def test_other_threads_are_rejected(self):
        trace = ct.ConsistencyTrace(self.path)
        errors = []

        def use():
            try:
                trace.write(response(2, 10))
            except AssertionError as e:
                errors.append(e)

        thread = threading.Thread(target=use)
        thread.start()
        thread.join()
        self.assertEqual(len(errors), 1)
        trace.close()
        self.assertEqual(self.records(), [])

    def test_close_sweeps_terminal_statuses_only(self):
        node = FakeNode(
            {
                "/node/tx?transaction_id=2.10": response(
                    None, None, body={"status": "Committed"}
                ),
                "/node/tx?transaction_id=2.11": response(
                    None, None, body={"status": "Pending"}
                ),
            }
        )
        trace = ct.ConsistencyTrace(self.path)
        trace.write(response(2, 10))
        trace.write(response(2, 11))
        trace.close(FakeNetwork(node), timeout=1)
        self.assertEqual(self.records()[6:], [tvc_status([2, 10], "Committed")])

    def test_disabled_recording_does_nothing(self):
        with ct.recording(Untouchable(), enabled=False) as trace:
            self.assertIsNone(trace)
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])

    def test_enabled_recording_skips_sweep_on_failure(self):
        network = FakeNetwork(Untouchable(), common_dir=self.directory.name)
        with self.assertRaises(RuntimeError), ct.recording(
            network, enabled=True
        ) as trace:
            trace.write(response(2, 10))
            raise RuntimeError("test failure")
        self.assertEqual(network.find_primary_calls, 0)
        self.assertEqual(self.records(), tvc_write(0, [2, 10]))


if __name__ == "__main__":
    unittest.main()
