# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from infra.commit import wait_for_commit
import pprint
import http


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


def get_free_log_id(c):
    log_id = 42
    r = c.get(f"/app/log/private?id={log_id}")
    while (
        r.status_code != http.HTTPStatus.NOT_FOUND
        and r.status_code != http.HTTPStatus.BAD_REQUEST
        and not (
            r.status_code == http.HTTPStatus.OK
            and r.body.json() == {"error": "No such key"}
        )
    ):
        log_id = log_id + 1
        r = c.get(f"/app/log/private?id={log_id}")
    return log_id


def check_can_progress(node, timeout=3):
    # Check that a write transaction issued on one node is eventually
    # committed by the service by a specified timeout
    with node.client("user0") as c:
        log_id = get_free_log_id(c)
        r = c.post("/app/log/private", {"id": log_id, "msg": "Hello world"})
        try:
            c.wait_for_commit(r, timeout=timeout)
            return r
        except TimeoutError:
            details = c.get("/node/consensus").body.json()
            assert False, f"Stuck before {r.view}.{r.seqno}: {pprint.pformat(details)}"


def check_does_not_progress(node, timeout=3):
    # Check that a write transaction issued on one node is _not_
    # committed by the service by a specified timeout
    with node.client("user0") as c:
        log_id = get_free_log_id(c)
        r = c.post("/app/log/private", {"id": log_id, "msg": "Hello world"})
        try:
            c.wait_for_commit(r, timeout=timeout)
        except TimeoutError:
            return r
        else:
            assert False, f"Commit unexpectedly advanced past {r.view}.{r.seqno}"
