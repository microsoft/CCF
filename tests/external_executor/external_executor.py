# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import suite.test_requirements as reqs
import queue
from infra.snp import IS_SNP

from executors.logging_app.logging_app import LoggingExecutor

from executors.wiki_cacher.wiki_cacher import WikiCacherExecutor
from executors.util import executor_thread
from executors.ccf.executors.registration import register_new_executor

import kv_pb2_grpc as Service

import misc_pb2 as Misc

import misc_pb2_grpc as MiscService

from google.protobuf.empty_pb2 import Empty as Empty

import grpc
import os
import contextlib
import http
import random
import threading
import time

from loguru import logger as LOG


@reqs.description("Register an external executor")
@reqs.not_snp("UNKNOWN RPC failures")
def test_executor_registration(network, args):
    primary, backup = network.find_primary_and_any_backup()

    service_certificate_bytes = open(
        os.path.join(network.common_dir, "service_cert.pem"), "rb"
    ).read()

    executor_credentials = register_new_executor(
        primary.get_public_rpc_address(),
        service_certificate_bytes,
        with_attestation_container=False,
    )

    anonymous_credentials = grpc.ssl_channel_credentials(service_certificate_bytes)

    # Confirm that these credentials (and NOT anonymous credentials) provide
    # access to the KV service on the target node, but no other nodes
    for node in (
        primary,
        backup,
    ):
        for credentials in (
            anonymous_credentials,
            executor_credentials,
        ):
            with grpc.secure_channel(
                target=node.get_public_rpc_address(),
                credentials=credentials,
            ) as channel:
                should_pass = node == primary and credentials == executor_credentials
                try:
                    stub = Service.KVStub(channel)
                    for m in stub.Activate(Empty(), timeout=1):
                        assert m.HasField(
                            "activated"
                        ), f"Expected only an activated message, not: {m}"
                except grpc.RpcError as e:
                    if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                        assert (
                            should_pass
                        ), "Expected Activate to fail with an auth error"
                    else:
                        assert not should_pass
                        assert e.details() == "Invalid authentication credentials."
                        assert e.code() == grpc.StatusCode.UNAUTHENTICATED, e
                else:
                    assert should_pass

    return network


def test_wiki_cacher_executor(network, args):
    primary, _ = network.find_primary()

    service_certificate_bytes = open(
        os.path.join(network.common_dir, "service_cert.pem"), "rb"
    ).read()

    credentials = register_new_executor(
        primary.get_public_rpc_address(),
        service_certificate_bytes,
        supported_endpoints=WikiCacherExecutor.get_supported_endpoints({"Earth"}),
        with_attestation_container=False,
    )
    wiki_cacher_executor = WikiCacherExecutor(
        primary.get_public_rpc_address(), credentials=credentials
    )

    with executor_thread(wiki_cacher_executor):
        with primary.client() as c:
            r = c.post("/not/a/real/endpoint")
            assert r.status_code == http.HTTPStatus.NOT_FOUND

            r = c.get("/article_description/Earth")
            assert r.status_code == http.HTTPStatus.NOT_FOUND
            # Note: This should be a distinct kind of 404 - reached an executor, and it returned a custom 404

            r = c.post("/update_cache/Earth")
            assert r.status_code == http.HTTPStatus.OK
            content = r.body.text().splitlines()[-1]

            r = c.get("/article_description/Earth")
            assert r.status_code == http.HTTPStatus.OK
            assert r.body.text() == content

    return network


def test_parallel_executors(network, args):
    primary, _ = network.find_primary()

    topics = [
        "England",
        "Scotland",
        "France",
        "Red",
        "Green",
        "Blue",
        "Cat",
        "Dog",
        "Alligator",
        "Garfield",
    ]
    executor_count = len(topics)

    def read_entries(topic, idx):
        with primary.client() as c:
            while True:
                r = c.get(f"/log/public/{topic}?id={idx}", log_capture=[])

                if r.status_code == http.HTTPStatus.OK:
                    # Note: External executor bug: Responses can be received out of order
                    # assert r.body.json()["msg"] == f"A record about {topic}"
                    return
                elif r.status_code == http.HTTPStatus.NOT_FOUND:
                    time.sleep(0.1)
                else:
                    raise ValueError(f"Unexpected response: {r}")

    executors = []

    service_certificate_bytes = open(
        os.path.join(network.common_dir, "service_cert.pem"), "rb"
    ).read()

    with contextlib.ExitStack() as stack:
        for i in range(executor_count):
            supported_endpoints = LoggingExecutor.get_supported_endpoints(topics[i])
            credentials = register_new_executor(
                primary.get_public_rpc_address(),
                service_certificate_bytes,
                supported_endpoints=supported_endpoints,
                with_attestation_container=False,
            )
            executor = LoggingExecutor(
                primary.get_public_rpc_address(), credentials=credentials
            )

            executors.append(executor)
            stack.enter_context(executor_thread(executor))

        for executor in executors:
            assert executor.handled_requests_count == 0

        reader_threads = [
            threading.Thread(target=read_entries, args=(topic, i))
            for i, topic in enumerate(topics)
        ]

        for thread in reader_threads:
            thread.start()

        for i, topic in enumerate(topics):
            with primary.client("user0") as c:
                c.post(
                    f"/log/public/{topic}",
                    body={"id": i, "msg": f"A record about {topic}"},
                    log_capture=[],
                )
                # Note: External executor bug: Responses can be received out of order
                # (i.e. we may receive a response to a GET in the POST and vice-versa).
                # The issue may be in the external executor app or in the handling
                # of HTTP/2 streams. To be investigated when the external executor work is
                # resumed.
                # assert r.status_code == http.HTTPStatus.OK
                time.sleep(0.25)

        for thread in reader_threads:
            thread.join()

    for executor in executors:
        assert executor.handled_requests_count > 0

    return network


@reqs.description("Test gRPC streaming APIs")
def test_streaming(network, args):
    primary, _ = network.find_primary()

    # Create new anonymous credentials
    credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )

    def echo_op(s):
        return (Misc.OpIn(echo=Misc.EchoOp(body=s)), ("echoed", s))

    def reverse_op(s):
        return (
            Misc.OpIn(reverse=Misc.ReverseOp(body=s)),
            ("reversed", s[::-1]),
        )

    def truncate_op(s):
        start = random.randint(0, len(s))
        end = random.randint(start, len(s))
        return (
            Misc.OpIn(truncate=Misc.TruncateOp(body=s, start=start, end=end)),
            ("truncated", s[start:end]),
        )

    def empty_op(s):
        # oneof may always be null - generate some like this to make sure they're handled "correctly"
        return (Misc.OpIn(), None)

    def generate_ops(n):
        for _ in range(n):
            s = f"I'm random string {n}: {random.random()}"
            yield random.choice((echo_op, reverse_op, truncate_op, empty_op))(s)

    def compare_op_results(stub, n_ops):
        LOG.info(f"Sending streaming request containing {n_ops} operations")
        ops = []
        expected_results = []
        for op, expected_result in generate_ops(n_ops):
            ops.append(op)
            expected_results.append(expected_result)

        for actual_result in stub.RunOps(op for op in ops):
            assert len(expected_results) > 0, "More responses than requests"
            expected_result = expected_results.pop(0)
            if expected_result is None:
                assert not actual_result.HasField("result"), actual_result
            else:
                field_name, expected = expected_result
                actual = getattr(actual_result, field_name).body
                assert (
                    actual == expected
                ), f"Wrong {field_name} op: {actual} != {expected}"

        assert len(expected_results) == 0, "Fewer responses than requests"

    with grpc.secure_channel(
        target=primary.get_public_rpc_address(),
        credentials=credentials,
    ) as channel:
        stub = MiscService.TestStub(channel)

        compare_op_results(stub, 0)
        compare_op_results(stub, 1)
        compare_op_results(stub, 20)
        compare_op_results(stub, 1000)

    return network


@reqs.description("Test server async gRPC streaming APIs")
def test_async_streaming(network, args):
    primary, _ = network.find_primary()

    service_certificate_bytes = open(
        os.path.join(network.common_dir, "service_cert.pem"), "rb"
    ).read()

    credentials = grpc.ssl_channel_credentials(service_certificate_bytes)
    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        s = MiscService.TestStub(channel)

        event_name = "name_of_my_event"

        events = queue.Queue()
        subscription_started = threading.Event()

        def subscribe(event_name):
            credentials = grpc.ssl_channel_credentials(service_certificate_bytes)
            with grpc.secure_channel(
                target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
                credentials=credentials,
            ) as subscriber_channel:
                sub_stub = MiscService.TestStub(subscriber_channel)
                LOG.debug(f"Waiting for event {event_name}...")
                for e in sub_stub.Sub(Misc.Event(name=event_name)):  # Blocking
                    if e.HasField("started"):
                        # While we're here, confirm that errors can be returned when calling a streaming RPC.
                        # In this case, from trying to subscribe multiple times
                        try:
                            for e in sub_stub.Sub(Misc.Event(name=event_name)):
                                assert False, "Expected this to be unreachable"
                        except grpc.RpcError as e:
                            assert e.code() == grpc.StatusCode.FAILED_PRECONDITION, e
                            assert (
                                f"Already have a subscriber for {event_name}"
                                in e.details()
                            ), e

                        subscription_started.set()
                    elif e.HasField("terminated"):
                        break
                    else:
                        LOG.info(f"Received update for event {event_name}")
                        events.put(("sub", e.event_info))
                        sub_stub.Ack(e.event_info)

        t = threading.Thread(target=subscribe, args=(event_name,))
        t.start()

        # Wait for subscription thread to actually start, and the server has confirmed it is ready
        assert subscription_started.wait(timeout=3), "Subscription wait timed out"

        event_count = 5
        event_contents = [f"contents {i}" for i in range(event_count)]
        LOG.info(f"Publishing events for {event_name}")

        for contents in event_contents:
            e = Misc.EventInfo(name=event_name, message=contents)
            LOG.info("Adding pub event")
            events.put(("pub", e))
            s.Pub(e)
            # Sleep to try and ensure that the sub happens next, rather than the next pub in this loop
            time.sleep(0.2)
        s.Terminate(Misc.Event(name=event_name))

        t.join()

        # Note: Subscriber stream is now closed but session is still open

        # Assert that all the published events were received by the subscriber,
        # and the pubs and subs were correctly interleaved
        sub_events_left = len(event_contents)
        expect_pub = True
        while events.qsize() > 0:
            kind, next_event = events.get()
            assert next_event.name == event_name
            assert next_event.message == event_contents[0]

            if expect_pub:
                assert kind == "pub"
            else:
                assert kind == "sub"
                event_contents.pop(0)
                sub_events_left -= 1
            expect_pub = not expect_pub
        assert sub_events_left == 0

        # Check that subscriber was automatically unregistered on server when subscriber
        # client stream was closed
        try:
            s.Pub(Misc.EventInfo(name=event_name, message="Hello"))
            assert False, "Publishing event without subscriber should return an error"
        except grpc.RpcError as e:
            assert e.code() == grpc.StatusCode.NOT_FOUND, e
            assert e.details() == f"Updates for event {event_name} has no subscriber"

    return network


@reqs.description("Test multiple executors that support the same endpoint")
def test_multiple_executors(network, args):
    primary, _ = network.find_primary()

    service_certificate_bytes = open(
        os.path.join(network.common_dir, "service_cert.pem"), "rb"
    ).read()

    supported_endpoints = LoggingExecutor.get_supported_endpoints("Monday")

    # register executor_a
    credentials = register_new_executor(
        primary.get_public_rpc_address(),
        service_certificate_bytes,
        supported_endpoints=supported_endpoints,
        with_attestation_container=False,
    )
    executor_a = LoggingExecutor(primary.get_public_rpc_address(), credentials)

    # register executor_b
    supported_endpoints_b = [("GET", "/log/public/Monday")]
    executor_b_credentials = register_new_executor(
        primary.get_public_rpc_address(),
        service_certificate_bytes,
        supported_endpoints=supported_endpoints_b,
        with_attestation_container=False,
    )
    executor_b = LoggingExecutor(
        primary.get_public_rpc_address(), executor_b_credentials
    )

    msg = "recorded on executor a"
    with executor_thread(executor_a):
        with primary.client() as c:
            r = c.post("/log/public/Monday", body={"id": 0, "msg": msg})
            assert r.status_code == http.HTTPStatus.OK, r

            r = c.get("/log/public/Monday?id=0")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.json()["msg"] == msg, r

    # /article_description/Monday this time will be passed to executor_b
    with executor_thread(executor_b):
        with primary.client() as c:
            r = c.get("/log/public/Monday?id=0")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.json()["msg"] == msg, r

    return network


def test_logging_executor(network, args):
    primary, _ = network.find_primary()

    service_certificate_bytes = open(
        os.path.join(network.common_dir, "service_cert.pem"), "rb"
    ).read()

    supported_endpoints = LoggingExecutor.get_supported_endpoints()

    credentials = register_new_executor(
        primary.get_public_rpc_address(),
        service_certificate_bytes,
        supported_endpoints=supported_endpoints,
        with_attestation_container=False,
    )
    executor = LoggingExecutor(primary.get_public_rpc_address(), credentials)

    with executor_thread(executor):
        with primary.client() as c:
            log_id = 42
            log_msg = "Hello world"

            r = c.post("/log/public", {"id": log_id, "msg": log_msg})
            assert r.status_code == 200

            r = c.get(f"/log/public?id={log_id}")

            assert r.status_code == 200
            assert r.body.json()["msg"] == log_msg

            # post to private table
            r = c.post("/log/private", {"id": log_id, "msg": log_msg})
            assert r.status_code == 200
            tx_id = r.headers.get("x-ms-ccf-transaction-id")

            # make a historical query
            timeout = 3
            start_time = time.time()
            end_time = start_time + timeout
            success_msg = ""
            while time.time() < end_time:
                headers = {"x-ms-ccf-transaction-id": tx_id}
                r = c.get(f"/log/private/historical?id={log_id}", headers=headers)
                if r.status_code == http.HTTPStatus.OK:
                    assert r.body.json()["msg"] == log_msg
                    success_msg = log_msg
                    break
                elif r.status_code == http.HTTPStatus.NOT_FOUND:
                    error_msg = (
                        "Only committed transactions can be queried. Transaction "
                        + tx_id
                        + " is Pending"
                    )
                    assert r.body.text() == error_msg
                    time.sleep(0.1)
                    continue
                elif r.status_code == http.HTTPStatus.ACCEPTED:
                    msg = "Historical transaction is not currently available. Please retry."
                    assert r.body.text() == msg
                    time.sleep(0.1)
                    continue
            # check that the historical query succeeded
            assert success_msg == log_msg

    return network


def run(args):
    # Run tests with non-containerised initial network
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
    ) as network:
        network.start_and_open(args)

        if not IS_SNP:  # UNKNOWN RPC failures
            network = test_executor_registration(network, args)

        network = test_parallel_executors(network, args)
        network = test_streaming(network, args)
        network = test_async_streaming(network, args)
        # Wiki cacher executor makes requests to Wikipedia which can be flaky
        # network = test_wiki_cacher_executor(network, args)
        network = test_multiple_executors(network, args)
        network = test_logging_executor(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    # Note: set following envvar for debug logs:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http

    run(args)
