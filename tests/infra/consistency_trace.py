# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Record client observations in the tests/tvc.py consistency trace format.

Tests call the methods below explicitly on responses they already hold, and
captures are replayed by lean/consistency (consistency-replay).
"""

import contextlib
import json
import os
import subprocess

from loguru import logger as LOG

# Written by infra.checker.check_can_progress. Its value is irrelevant: the
# format carries no values.
READ_PATH = "/app/log/public?id=3&scope=check_can_progress"


class ConsistencyTrace:
    def __init__(self, path):
        self.path = path
        # Closed in close()
        self._file = open(path, "w", encoding="ascii")  # noqa: SIM115
        self._next_tx = 0

    def _emit(self, action, type_, **fields):
        self._file.write(json.dumps({"action": action, "type": type_, **fields}) + "\n")

    def _request(self, kind):
        tx = self._next_tx
        self._next_tx += 1
        self._emit(f"{kind}TxRequestAction", f"{kind}TxRequest", tx=tx)
        return tx

    def write(self, r):
        tx = self._request("Rw")
        tx_id = [r.view, r.seqno]
        self._emit("RwTxExecuteAction", "RwTxExecute", tx=tx, tx_id=tx_id)
        self._emit("RwTxResponseAction", "RwTxResponse", tx=tx, tx_id=tx_id)

    def status(self, r, status):
        self._emit(
            f"Status{status.value}ResponseAction",
            "TxStatusReceived",
            tx_id=[r.view, r.seqno],
            status=f"{status.value}Status",
        )

    def primary_read(self, network, nodes):
        """Read on the primary, recorded only if that node was leader in the
        same view before and after the read, and the read is at that view."""
        primary, _ = network.find_primary(nodes=nodes)
        with primary.client("user0") as c:
            before = c.get("/node/consensus").body.json()["details"]
            r = c.get(READ_PATH)
            after = c.get("/node/consensus").body.json()["details"]
        view = before["current_view"]
        if (
            r.status_code != 200
            or r.view != view
            or any(
                d["leadership_state"] != "Leader" or d["current_view"] != view
                for d in (before, after)
            )
        ):
            LOG.info(f"Not recording read: {r}, {before}, {after}")
            return
        tx = self._request("Ro")
        self._emit("RoTxResponseAction", "RoTxResponse", tx=tx, tx_id=[r.view, r.seqno])

    def close(self):
        self._file.close()


def replay(path):
    """Replay a trace with the Lean consistency replayer, if one is configured."""
    replayer = os.getenv("CCF_LEAN_CONSISTENCY_REPLAYER")
    if not replayer:
        return
    result = subprocess.run(
        [replayer, path], capture_output=True, text=True, check=False
    )
    assert (
        result.returncode == 0
    ), f"Lean consistency replay failed:\n{result.stdout}{result.stderr}"
    LOG.info(result.stdout.strip())


@contextlib.contextmanager
def recording(network, name, enabled):
    """Yield a trace named after its source, in network.common_dir, if enabled.
    Otherwise yield None.

    The trace is replayed on exit, unless the body raised."""
    if not enabled:
        yield None
        return
    trace = ConsistencyTrace(
        os.path.join(network.common_dir, f"{name}_consistency_trace.ndjson")
    )
    try:
        yield trace
    finally:
        trace.close()
    replay(trace.path)
