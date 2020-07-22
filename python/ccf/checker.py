# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import http
import time

from ccf.tx_status import TxStatus


def wait_for_global_commit(client, seqno, view, timeout=3):
    """
    Given a client to a CCF network and a seqno/view pair, this function
    waits for this specific commit index to be globally committed by the
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


class Checker:
    """
    Utility to verify that a CCF transaction has been committed.

    :param ccf.clients.CCFClient client: CCF client used to verify response.
    :param notification_queue: Notification queue.
    """
    def __init__(self, client=None, notification_queue=None):
        self.client = client
        self.notification_queue = notification_queue
        self.notified_commit = 0

    # TODO: that API's not right!
    def __call__(self, rpc_result, result=None, error=None, timeout=2):
        """
        Lalala.

        :param ccf.clients.Response rpc_result: Hey there.

        """
        if error is not None:
            if callable(error):
                assert error(
                    rpc_result.status_code, rpc_result.body
                ), f"{rpc_result.status_code}: {rpc_result.body}"
            else:
                assert rpc_result.body == error, "Expected {}, got {}".format(
                    error, rpc_result.body
                )
            return

        if result is not None:
            if callable(result):
                assert result(rpc_result.body), rpc_result.body
            else:
                assert rpc_result.body == result, "Expected {}, got {}".format(
                    result, rpc_result.body
                )

            assert rpc_result.seqno and rpc_result.view, rpc_result

        if self.client:
            wait_for_global_commit(self.client, rpc_result.seqno, rpc_result.view)

        if self.notification_queue:
            end_time = time.time() + timeout
            while time.time() < end_time:
                while self.notification_queue.not_empty:
                    notification = self.notification_queue.get()
                    n = json.loads(notification)["commit"]
                    assert (
                        n > self.notified_commit
                    ), f"Received notification of commit {n} after commit {self.notified_commit}"
                    self.notified_commit = n
                    if n >= rpc_result.seqno:
                        return
                time.sleep(0.5)
            raise TimeoutError("Timed out waiting for notification")
