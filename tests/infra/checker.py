# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import time

from ccf.commit import wait_for_commit


class Checker:
    def __init__(self, client=None, notification_queue=None):
        self.client = client
        self.notification_queue = notification_queue
        self.notified_commit = 0

    # TODO: that API's not right!
    def __call__(self, rpc_result, result=None, error=None, timeout=2):
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

            assert rpc_result.seqno >= 0 and rpc_result.view >= 0, rpc_result

        if self.client:
            wait_for_commit(self.client, rpc_result.seqno, rpc_result.view)

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
