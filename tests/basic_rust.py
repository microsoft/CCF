# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import threading
import time

import infra.e2e_args
import infra.network
import suite.test_requirements as reqs

CONCURRENT_WRITES = 50
READY_TIMEOUT_S = 10
SLOW_REQUEST_TIMEOUT_S = 30


@reqs.description("Exercise Rust application endpoints and KV access")
@reqs.supports_methods(
    "/app/compaction/fast/{key}",
    "/app/compaction/marker",
    "/app/compaction/ready",
    "/app/compaction/slow",
    "/app/empty-error-code",
    "/app/header-validation",
    "/app/health",
    "/app/invalid-error-status",
    "/app/panic",
    "/app/records/{key}",
)
def test_basic_rust(network, args):
    primary, _ = network.find_primary()

    with primary.client() as anonymous:
        response = anonymous.get("/app/panic")
        assert response.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, response
        error = response.body.json()["error"]
        assert error["message"] == "Rust endpoint panicked", error

        # Panic messages may contain request or KV data, and node output is
        # visible to the host.
        for log_path in primary.get_logs():
            with open(log_path, "rb") as log:
                assert b"test panic" not in log.read(), log_path

        response = anonymous.get("/app/health")
        assert response.status_code == http.HTTPStatus.OK, response
        assert response.body.data() == b"OK", response.body

        response = anonymous.get("/app/invalid-error-status")
        assert response.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, response
        error = response.body.json()["error"]
        assert error["code"] == "InvalidStatus", error
        assert error["message"] == "Unsupported status", error

        response = anonymous.get("/app/empty-error-code")
        assert response.status_code == http.HTTPStatus.BAD_REQUEST, response
        error = response.body.json()["error"]
        assert error["code"] == "", error
        assert error["message"] == "Empty error code", error

        response = anonymous.get("/app/header-validation")
        assert response.status_code == http.HTTPStatus.NO_CONTENT, response

        response = anonymous.get("/app/records/missing")
        assert response.status_code == http.HTTPStatus.UNAUTHORIZED, response

    with primary.client("user0") as user:
        value = b"\x00rust\xff"
        response = user.put("/app/records/example", body=value)
        assert response.status_code == http.HTTPStatus.NO_CONTENT, response

        response = user.get("/app/records/example")
        assert response.status_code == http.HTTPStatus.OK, response
        assert response.body.data() == value, response.body

        response = user.get("/app/records/missing")
        assert response.status_code == http.HTTPStatus.NOT_FOUND, response

    return network


def test_compaction_conflict_is_retried(network, args):
    primary, _ = network.find_primary()

    # Both maps must exist before the slow transaction fixes its read version.
    with primary.client() as anonymous:
        response = anonymous.post("/app/compaction/marker")
        assert response.status_code == http.HTTPStatus.NO_CONTENT, response
        response = anonymous.post("/app/compaction/fast/init")
        assert response.status_code == http.HTTPStatus.NO_CONTENT, response
    network.wait_for_all_nodes_to_commit(primary=primary)

    slow_response = {}

    def slow_write():
        with primary.client() as anonymous:
            slow_response["response"] = anonymous.post(
                "/app/compaction/slow", timeout=SLOW_REQUEST_TIMEOUT_S
            )

    slow = threading.Thread(target=slow_write)
    slow.start()

    # The endpoint reads the marker map before sleeping. Advance and compact a
    # different map before the endpoint first accesses it.
    ready_deadline = time.monotonic() + READY_TIMEOUT_S
    with primary.client() as anonymous:
        while True:
            response = anonymous.get("/app/compaction/ready")
            if response.status_code == http.HTTPStatus.OK:
                break
            assert response.status_code == http.HTTPStatus.NOT_FOUND, response
            assert time.monotonic() < ready_deadline, "Slow endpoint did not start"
            time.sleep(0.05)

    with primary.client() as anonymous:
        response = anonymous.post("/app/compaction/fast/retry")
        assert response.status_code == http.HTTPStatus.NO_CONTENT, response
        for i in range(CONCURRENT_WRITES):
            response = anonymous.post(f"/app/compaction/fast/{i}")
            assert response.status_code == http.HTTPStatus.NO_CONTENT, response
    network.wait_for_all_nodes_to_commit(primary=primary)

    slow.join()
    response = slow_response["response"]
    assert response.status_code == http.HTTPStatus.OK, response
    assert response.body.data() == b"retried", response.body

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test_basic_rust(network, args)
        test_compaction_conflict_is_retried(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/basic_rust/basic_rust"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    run(args)
