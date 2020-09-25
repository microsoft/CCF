# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import time

from typing import Optional, List

from ccf.tx_status import TxStatus
from ccf.log_capture import flush_info


def wait_for_commit(
    client, seqno: int, view: int, timeout: int = 3, log_capture: Optional[list] = None
) -> None:
    """
    Waits for a specific seqno/view pair to be committed by the network,
    as per the node to which client is connected to.

    :param client: Instance of :py:class:`ccf.clients.CCFClient`
    :param int seqno: Transaction sequence number.
    :param int view: Consensus view.
    :param str timeout: Maximum time to wait for this seqno/view pair to be committed before giving up.
    :param list log_capture: Rather than emit to default handler, capture log lines to list (optional).

    A TimeoutError exception is raised if the commit index is not committed within the given timeout.
    """
    logs: List[str] = []
    end_time = time.time() + timeout
    while time.time() < end_time:
        logs = []
        r = client.get(f"/node/tx?view={view}&seqno={seqno}", log_capture=logs)
        assert (
            r.status_code == http.HTTPStatus.OK
        ), f"tx request returned HTTP status {r.status_code}"
        status = TxStatus(r.body.json()["status"])
        if status == TxStatus.Committed:
            flush_info(logs, log_capture, 1)
            return
        elif status == TxStatus.Invalid:
            raise RuntimeError(
                f"Transaction ID {view}.{seqno} is marked invalid and will never be committed"
            )
        else:
            time.sleep(0.1)
    flush_info(logs, log_capture, 1)
    raise TimeoutError("Timed out waiting for commit")
