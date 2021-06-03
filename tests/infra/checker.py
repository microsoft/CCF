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
    with node.client() as c:
        r = c.get("/node/commit")
        original_tx = TxID.from_str(r.body.json()["transaction_id"])
        with node.client("user0") as uc:
            uc.post("/app/log/private", {"id": 42, "msg": "Hello world"})
        end_time = time.time() + timeout
        while time.time() < end_time:
            current_tx = TxID.from_str(
                c.get("/node/commit").body.json()["transaction_id"]
            )
            if current_tx.seqno > original_tx.seqno:
                return current_tx
            time.sleep(0.1)
        details = c.get("/node/consensus").body.json()
        assert False, f"Stuck at {r}: {pprint.pformat(details)}"
