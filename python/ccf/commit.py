# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import time


from ccf.tx_status import TxStatus


def wait_for_commit(client, seqno: int, view: int, timeout: int = 3) -> None:
    """
    Waits for a specific seqno/view pair to be committed by the network,
    as per the node to which client is connected to.

    :param client: Instance of :py:class:`ccf.clients.CCFClient`
    :param int seqno: Transaction sequence number.
    :param int view: Consensus view.
    :param str timeout: Maximum time to wait for this seqno/view pair to be committed before giving up.

    A TimeoutError exception is raised if the commit index is not committed within the given timeout.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        r = client.get(f"/node/tx?view={view}&seqno={seqno}")
        assert (
            r.status_code == http.HTTPStatus.OK
        ), f"tx request returned HTTP status {r.status_code}"
        assert isinstance(r.body, dict), "/node/tx should return a JSON object"
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
