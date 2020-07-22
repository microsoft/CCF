# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import time


from ccf.tx_status import TxStatus


def wait_for_commit(client, seqno, view, timeout=3):
    """
    Given a client to a CCF network and a seqno/view pair, this function
    waits for this specific commit index to be committed by the
    network in this view.

    A TimeoutError exception is raised if the commit index is not globally
    committed within the given timeout.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        r = client.get("/node/tx", {"view": view, "seqno": seqno})
        assert (
            r.status_code == http.HTTPStatus.OK
        ), f"tx request returned HTTP status {r.status_code}"
        status = TxStatus(r.body["status"])
        if status == TxStatus.Committed:
            return
        elif status == TxStatus.Invalid:
            raise RuntimeError(
                f"Transaction ID {view}.{seqno} is marked invalid and will never be committed"
            )
        else:
            time.sleep(0.1)
    raise TimeoutError("Timed out waiting for commit")
