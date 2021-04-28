# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from ccf.commit import wait_for_commit


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
