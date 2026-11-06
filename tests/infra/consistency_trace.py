# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Record client observations in the consistency trace format of tests/tvc.py.

Captures are replayed by lean/consistency (consistency-replay). Recording is
explicit: tests call the methods below on responses they already hold, so
shared client code is never instrumented. A trace is owned by the thread that
created it and is not synchronised.
"""

import contextlib
import json
import os
import threading
import time

from loguru import logger as LOG

from infra.tx_status import TxStatus

FILE_NAME = "consistency_trace.ndjson"

# Written by infra.checker.check_can_progress, so it exists once a recorded
# write has committed. Its value is irrelevant: the format carries no values.
READ_PATH = "/app/log/public?id=3&scope=check_can_progress"

TERMINAL_STATUSES = (TxStatus.Committed, TxStatus.Invalid)


class ConsistencyTrace:
    def __init__(self, path):
        self.path = path
        self._thread = threading.get_ident()
        # Closed in close()
        self._file = open(path, "w", encoding="ascii")  # noqa: SIM115
        self._next_tx = 0
        # (view, seqno) of each recorded write -> recorded TxStatus, or None
        self._writes = {}

    def _check_thread(self):
        assert (
            threading.get_ident() == self._thread
        ), "ConsistencyTrace must only be used by the thread that created it"

    def _emit(self, **record):
        self._file.write(json.dumps(record) + "\n")

    def _request_id(self):
        tx = self._next_tx
        self._next_tx += 1
        return tx

    @staticmethod
    def _txid(response):
        if response.status_code != 200 or response.view is None:
            return None
        if response.seqno is None:
            return None
        return (response.view, response.seqno)

    def write(self, response):
        """Record a successful write as request, execution and response."""
        self._check_thread()
        txid = self._txid(response)
        if txid is None:
            LOG.info(f"Not recording write without a transaction ID: {response}")
            return False
        assert txid not in self._writes, f"Write {txid} already recorded"
        tx = self._request_id()
        tx_id = list(txid)
        self._emit(action="RwTxRequestAction", type="RwTxRequest", tx=tx)
        self._emit(action="RwTxExecuteAction", type="RwTxExecute", tx=tx, tx_id=tx_id)
        self._emit(action="RwTxResponseAction", type="RwTxResponse", tx=tx, tx_id=tx_id)
        self._writes[txid] = None
        return True

    def status(self, response, status):
        """Record a terminal status for a recorded write, once."""
        self._check_thread()
        assert status in TERMINAL_STATUSES, status
        txid = self._txid(response)
        if txid not in self._writes:
            LOG.info(f"Not recording status of unrecorded write {txid}")
            return False
        recorded = self._writes[txid]
        if recorded == status:
            return False
        if recorded is not None:
            # Contradictory reports are kept so that replay rejects them.
            LOG.error(f"Write {txid} reported {status} after {recorded}")
        self._emit(
            action=f"Status{status.value}ResponseAction",
            type="TxStatusReceived",
            tx_id=list(txid),
            status=f"{status.value}Status",
        )
        self._writes[txid] = status
        return True

    def primary_read(self, network, nodes=None):
        """Read on the primary, recording it only if it was served by a leader.

        The node must report leadership in the same view before and after the
        read, and the read must be at that view. Returns whether it was recorded.
        """
        self._check_thread()
        primary, _ = network.find_primary(nodes=nodes)
        with primary.client("user0") as c:
            before = c.get("/node/consensus").body.json()["details"]
            r = c.get(READ_PATH)
            after = c.get("/node/consensus").body.json()["details"]
        view = before["current_view"]
        led = all(
            details["leadership_state"] == "Leader" and details["current_view"] == view
            for details in (before, after)
        )
        txid = self._txid(r)
        if not led or txid is None or txid[0] != view:
            LOG.info(
                f"Not recording read on {primary.local_node_id}: {r}, {before}, {after}"
            )
            return False
        tx = self._request_id()
        self._emit(action="RoTxRequestAction", type="RoTxRequest", tx=tx)
        self._emit(
            action="RoTxResponseAction", type="RoTxResponse", tx=tx, tx_id=list(txid)
        )
        return True

    def _sweep(self, network, timeout):
        end_time = time.time() + timeout
        while True:
            pending = [txid for txid, status in self._writes.items() if status is None]
            if not pending or time.time() > end_time:
                break
            primary, _ = network.find_primary()
            with primary.client() as c:
                for view, seqno in pending:
                    r = c.get(f"/node/tx?transaction_id={view}.{seqno}")
                    status = TxStatus(r.body.json()["status"])
                    if status in TERMINAL_STATUSES:
                        self.status(_TxIDResponse(view, seqno), status)
            time.sleep(0.5)
        if pending:
            LOG.info(f"Omitting statuses of non-terminal writes: {pending}")

    def close(self, network=None, timeout=10):
        """Record terminal statuses still unknown, within timeout, then flush.

        Without a network, for example after a failure, nothing is queried.
        Sweep errors are logged, not raised: omitted statuses are still valid.
        """
        self._check_thread()
        try:
            if network is not None:
                self._sweep(network, timeout)
        except Exception as e:
            LOG.warning(f"Consistency trace status sweep failed: {e!r}")
        finally:
            self._file.close()
        LOG.info(f"Consistency trace written to {self.path}")


class _TxIDResponse:
    status_code = 200

    def __init__(self, view, seqno):
        self.view = view
        self.seqno = seqno


@contextlib.contextmanager
def recording(network, enabled):
    """Yield a trace in network.common_dir if enabled, otherwise None.

    When disabled, network is not used and no file is created.
    """
    if not enabled:
        yield None
        return
    trace = ConsistencyTrace(os.path.join(network.common_dir, FILE_NAME))
    try:
        yield trace
    except BaseException:
        trace.close()
        raise
    trace.close(network)
