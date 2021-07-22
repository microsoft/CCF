# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from ccf.commit import wait_for_commit
from ccf.tx_id import TxID
import time
import pprint


class Checker:
    def __init__(self, client=None):
        self.client = client
        self.notified_commit = 0

    # TODO: that API's not right!
    def __call__(self, rpc_result, result=None, error=None):
        if error is not None:
            if callable(error):
                assert error(
                    rpc_result.status_code, rpc_result.body
                ), f"{rpc_result.status_code}: {rpc_result.body}"
            else:
                assert rpc_result.body.text() == error, "Expected {}, got {}".format(
                    error, rpc_result.body
                )
            return

        if result is not None:
            if callable(result):
                assert result(rpc_result.body), rpc_result.body
            else:
                assert rpc_result.body.json() == result, "Expected {}, got {}".format(
                    result, rpc_result.body
                )

            assert rpc_result.seqno >= 0 and rpc_result.view >= 0

        if self.client:
            wait_for_commit(self.client, rpc_result.seqno, rpc_result.view)


def check_can_progress(node, timeout=3):
    # Check that a write transaction issued on one node is eventually
    # committed by the service
    with node.client("user0") as uc:
        submitted_seqno = uc.post(
            "/app/log/private", {"id": 42, "msg": "Hello world"}
        ).seqno

    with node.client() as c:
        end_time = time.time() + timeout
        while time.time() < end_time:
            current_commit_txid = TxID.from_str(
                c.get("/node/commit").body.json()["transaction_id"]
            )
            if current_commit_txid.seqno > submitted_seqno:
                return current_commit_txid
            time.sleep(0.1)
        details = c.get("/node/consensus").body.json()
        assert False, f"Stuck at {submitted_seqno}: {pprint.pformat(details)}"


def check_does_not_progress(node, timeout=3):
    # Check that a write transaction issued on one node is _not_
    # committed by the service
    with node.client("user0") as uc:
        submitted_seqno = uc.post(
            "/app/log/private", {"id": 42, "msg": "Hello world"}
        ).seqno

    with node.client() as c:
        end_time = time.time() + timeout
        while time.time() < end_time:
            current_commit_txid = TxID.from_str(
                c.get("/node/commit").body.json()["transaction_id"]
            )
            if current_commit_txid.seqno > submitted_seqno:
                assert False, "Commit advanced when it shouldn't have"
            time.sleep(0.1)
        return True
