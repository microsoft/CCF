# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import suite.test_requirements as reqs
import queue

from executors.logging_app import LoggingExecutor
from executors.wiki_cacher import WikiCacherExecutor
from executors.util import executor_thread
from executors.utils.executor_container import executor_container
from infra.env import modify_env
from run_executor import register_new_executor

# pylint: disable=import-error
import kv_pb2_grpc as Service

# pylint: disable=import-error
import misc_pb2 as Misc

# pylint: disable=import-error
import misc_pb2_grpc as MiscService

# pylint: disable=import-error
import executor_registration_pb2 as ExecutorRegistration

# pylint: disable=import-error
import executor_registration_pb2_grpc as RegistrationService

# pylint: disable=import-error
import index_pb2 as Index

# pylint: disable=import-error
import index_pb2_grpc as IndexService

# pylint: disable=no-name-in-module
from google.protobuf.empty_pb2 import Empty as Empty

import grpc
import os
import contextlib
import http
import random
import threading
import time

from loguru import logger as LOG


@reqs.description(
    "Register an external executor (Disabled on SNP due to UNKNOWN RPC failures)"
)
@reqs.not_snp()
def test_executor_registration(network, args):
    primary, backup = network.find_primary_and_any_backup()

    executor_credentials = register_new_executor(
        primary.get_public_rpc_address(),
        network.common_dir,
    )

    anonymous_credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )

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
                    # pylint: disable=no-member
                    if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                        assert (
                            should_pass
                        ), "Expected Activate to fail with an auth error"
                    else:
                        assert not should_pass
                        # pylint: disable=no-member
                        assert e.details() == "Invalid authentication credentials."
                        # pylint: disable=no-member
                        assert e.code() == grpc.StatusCode.UNAUTHENTICATED, e
                else:
                    assert should_pass

    return network


def test_wiki_cacher_executor(network, args):
    primary, _ = network.find_primary()

    with executor_container(
        "wiki_cacher",
        primary,
        network,
        WikiCacherExecutor.get_supported_endpoints({"Earth"}),
        args.workspace,
    ):
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

    executor_count = 10

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

    def read_topic(topic):
        with primary.client() as c:
            while True:
                r = c.get(f"/article_description/{topic}", log_capture=[])
                if r.status_code == http.HTTPStatus.NOT_FOUND:
                    time.sleep(0.1)
                elif r.status_code == http.HTTPStatus.OK:
                    LOG.success(f"Found out about {topic}: {r.body.text()}")
                    return
                else:
                    raise ValueError(f"Unexpected response: {r}")

    executors = []

    with contextlib.ExitStack() as stack:
        for i in range(executor_count):
            wikicacher_executor = WikiCacherExecutor(
                primary.get_public_rpc_address(),
                label=f"Executor {i}",
            )
            supported_endpoints = wikicacher_executor.get_supported_endpoints(
                {topics[i]}
            )

            credentials = register_new_executor(
                primary.get_public_rpc_address(),
                network.common_dir,
                supported_endpoints=supported_endpoints,
            )

            wikicacher_executor.credentials = credentials
            executors.append(wikicacher_executor)
            stack.enter_context(executor_thread(wikicacher_executor))

        for executor in executors:
            assert executor.handled_requests_count == 0

        reader_threads = [
            threading.Thread(target=read_topic, args=(topic,)) for topic in topics * 3
        ]

        for thread in reader_threads:
            thread.start()

        with primary.client() as c:
            random.shuffle(topics)
            for topic in topics:
                r = c.post(f"/update_cache/{topic}", log_capture=[])
                assert r.status_code == http.HTTPStatus.OK
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

    credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )
    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        s = MiscService.TestStub(channel)

        event_name = "name_of_my_event"

        events = queue.Queue()
        subscription_started = threading.Event()

        def subscribe(event_name):
            credentials = grpc.ssl_channel_credentials(
                open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
            )
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
                            # pylint: disable=no-member
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
            # pylint: disable=no-member
            assert e.code() == grpc.StatusCode.NOT_FOUND, e
            # pylint: disable=no-member
            assert e.details() == f"Updates for event {event_name} has no subscriber"

    return network


@reqs.description("Test index API")
def test_index_api(network, args):
    primary, _ = network.find_primary()

    def add_kv_entries(network):
        logging_executor = LoggingExecutor(primary.get_public_rpc_address())
        supported_endpoints = logging_executor.supported_endpoints
        credentials = register_new_executor(
            primary.get_public_rpc_address(),
            network.common_dir,
            supported_endpoints=supported_endpoints,
        )
        logging_executor.credentials = credentials
        log_id = 14
        with executor_thread(logging_executor):
            with primary.client() as c:
                for _ in range(3):
                    r = c.post(
                        "/app/log/public",
                        {"id": log_id, "msg": "hello_world_" + str(log_id)},
                    )
                    assert r.status_code == 200
                    log_id = log_id + 1

    add_kv_entries(network)

    credentials = register_new_executor(
        primary.get_public_rpc_address(),
        network.common_dir,
    )

    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        data = queue.Queue()
        subscription_started = threading.Event()

        def InstallandSub():
            sub_credentials = register_new_executor(
                primary.get_public_rpc_address(),
                network.common_dir,
            )

            with grpc.secure_channel(
                target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
                credentials=sub_credentials,
            ) as subscriber_channel:
                in_stub = IndexService.IndexStub(subscriber_channel)
                for work in in_stub.InstallAndSubscribe(
                    Index.IndexInstall(
                        strategy_name="TestStrategy",
                        map_name="public:records",
                        data_structure=Index.IndexInstall.MAP,
                    )
                ):
                    if work.HasField("subscribed"):
                        subscription_started.set()
                        LOG.info("subscribed to a Index stream")
                        continue

                    elif work.HasField("work_done"):
                        LOG.info("work done")
                        break

                    assert work.HasField("key_value")
                    LOG.info("Has key value")
                    result = work.key_value
                    data.put(result)

        th = threading.Thread(target=InstallandSub)
        th.start()

        # Wait for subscription thread to actually start, and the server has confirmed it is ready
        assert subscription_started.wait(timeout=3), "Subscription wait timed out"
        time.sleep(1)

        index_stub = IndexService.IndexStub(channel)
        while data.qsize() > 0:
            LOG.info("storing indexed data")
            res = data.get()
            index_stub.StoreIndexedData(
                Index.IndexPayload(
                    strategy_name="TestStrategy",
                    key=res.key,
                    value=res.value,
                )
            )

        LOG.info("Fetching indexed data")
        log_id = 14
        for _ in range(3):
            result = index_stub.GetIndexedData(
                Index.IndexKey(
                    strategy_name="TestStrategy", key=log_id.to_bytes(8, "big")
                )
            )
            assert result.value.decode("utf-8") == "hello_world_" + str(log_id)
            log_id = log_id + 1

        index_stub.Unsubscribe(Index.IndexStrategy(strategy_name="TestStrategy"))

        th.join()

    return network


@reqs.description("Test multiple executors that support the same endpoint")
def test_multiple_executors(network, args):
    primary, _ = network.find_primary()

    # register executor_a
    wikicacher_executor_a = WikiCacherExecutor(primary.get_public_rpc_address())
    supported_endpoints_a = wikicacher_executor_a.get_supported_endpoints({"Monday"})

    executor_a_credentials = register_new_executor(
        primary.get_public_rpc_address(),
        network.common_dir,
        supported_endpoints=supported_endpoints_a,
    )
    wikicacher_executor_a.credentials = executor_a_credentials

    # register executor_b
    supported_endpoints_b = [("GET", "/article_description/Monday")]
    executor_b_credentials = register_new_executor(
        primary.get_public_rpc_address(),
        network.common_dir,
        supported_endpoints=supported_endpoints_b,
    )
    wikicacher_executor_b = WikiCacherExecutor(primary.get_public_rpc_address())
    wikicacher_executor_b.credentials = executor_b_credentials

    with executor_thread(wikicacher_executor_a):
        with primary.client() as c:
            r = c.post("/update_cache/Monday")
            assert r.status_code == http.HTTPStatus.OK, r
            content = r.body.text().splitlines()[-1]

            r = c.get("/article_description/Monday")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.text() == content, r

    # /article_description/Monday this time will be passed to executor_b
    with executor_thread(wikicacher_executor_b):
        with primary.client() as c:
            r = c.get("/article_description/Monday")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.text() == content, r

    return network


def test_logging_executor(network, args):
    primary, _ = network.find_primary()

    logging_executor = LoggingExecutor(primary.get_public_rpc_address())
    logging_executor.add_supported_endpoints(("PUT", "/test/endpoint"))
    supported_endpoints = logging_executor.supported_endpoints

    credentials = register_new_executor(
        primary.get_public_rpc_address(),
        network.common_dir,
        supported_endpoints=supported_endpoints,
    )

    logging_executor.credentials = credentials

    with executor_thread(logging_executor):
        with primary.client() as c:
            log_id = 42
            log_msg = "Hello world"

            r = c.post("/app/log/public", {"id": log_id, "msg": log_msg})
            assert r.status_code == 200

            r = c.get(f"/app/log/public?id={log_id}")

            assert r.status_code == 200
            assert r.body.json()["msg"] == log_msg

            # post to private table
            r = c.post("/app/log/private", {"id": log_id, "msg": log_msg})
            assert r.status_code == 200
            tx_id = r.headers.get("x-ms-ccf-transaction-id")

            # make a historical query
            timeout = 3
            start_time = time.time()
            end_time = start_time + timeout
            success_msg = ""
            while time.time() < end_time:
                headers = {"x-ms-ccf-transaction-id": tx_id}
                r = c.get(f"/app/log/private/historical?id={log_id}", headers=headers)
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

    # Run tests with containerised initial network
    with modify_env(CONTAINER_NODES="1"):
        with infra.network.network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
        ) as network:
            network.start_and_open(args)

            primary, _ = network.find_primary()
            LOG.info("Check that endpoint supports HTTP/2")
            with primary.client() as c:
                r = c.get("/node/network/nodes").body.json()
                assert (
                    r["nodes"][0]["rpc_interfaces"][
                        infra.interfaces.PRIMARY_RPC_INTERFACE
                    ]["app_protocol"]
                    == "HTTP2"
                ), "Target node does not support HTTP/2"

            network = test_wiki_cacher_executor(network, args)

    # Run tests with non-containerised initial network
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
    ) as network:
        network.start_and_open(args)

        network = test_executor_registration(network, args)
        network = test_parallel_executors(network, args)
        network = test_streaming(network, args)
        network = test_async_streaming(network, args)
        network = test_logging_executor(network, args)
        network = test_index_api(network, args)
        network = test_multiple_executors(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    # Note: set following envvar for debug logs:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http

    run(args)
