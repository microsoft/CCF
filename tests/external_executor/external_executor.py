# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import suite.test_requirements as reqs
import queue

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from executors.logging_app import LoggingExecutor
from executors.wiki_cacher import WikiCacherExecutor
from executors.util import executor_thread

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

# pylint: disable=no-name-in-module
from google.protobuf.empty_pb2 import Empty as Empty

import grpc
import os
import contextlib
import http
import random
import threading
import time
import hashlib

from loguru import logger as LOG


def make_fake_code_id():
    return random.getrandbits(256).to_bytes(32, "big").hex()


def new_executor_message(
    attestation_format=ExecutorRegistration.Attestation.INSECURE_VIRTUAL,
    quote=None,
    endorsements=b"testendorsement",
):
    if quote is None:
        quote = make_fake_code_id().encode("ascii")

    message = ExecutorRegistration.NewExecutor()
    message.attestation.format = attestation_format
    message.attestation.quote = quote
    message.attestation.endorsements = endorsements

    return message


def calculate_executor_id(cert):
    pubk_der_bytes = (
        load_pem_x509_certificate(cert.encode("ascii"))
        .public_key()
        .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    return hashlib.sha256(pubk_der_bytes).hexdigest()


def register_new_executor(node, network, message):
    # Generate a new executor identity
    key_priv_pem, _ = infra.crypto.generate_ec_keypair()
    cert = infra.crypto.generate_cert(key_priv_pem)

    message.cert = cert.encode()

    # Connect anonymously to register this executor
    anonymous_credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )

    with grpc.secure_channel(
        target=node.get_public_rpc_address(),
        credentials=anonymous_credentials,
    ) as channel:
        stub = RegistrationService.ExecutorRegistrationStub(channel)
        r = stub.RegisterExecutor(message)
        assert r.details == "Executor registration is accepted."
        LOG.success(f"Registered new executor {r.executor_id}")

    # Create (and return) credentials that allow authentication as this new executor
    executor_credentials = grpc.ssl_channel_credentials(
        root_certificates=open(
            os.path.join(network.common_dir, "service_cert.pem"), "rb"
        ).read(),
        private_key=key_priv_pem.encode(),
        certificate_chain=cert.encode(),
    )

    return executor_credentials, r.executor_id


@reqs.description(
    "Register an external executor (Disabled on SNP due to UNKNOWN RPC failures)"
)
@reqs.not_snp()
def test_executor_registration(network, args):
    primary, backup = network.find_primary_and_any_backup()

    code_id = make_fake_code_id()
    message = new_executor_message(quote=code_id.encode("ascii"))

    supported_endpoints = [
        {"method": method, "uri": "/test/temp"} for method in ("POST", "GET", "PUT")
    ]

    # Confirm that registering an unknown code ID is an error
    try:
        register_new_executor(primary, network, message)
        assert False, "Expected unreachable"
    except grpc.RpcError as e:
        # pylint: disable=no-member
        assert e.code() == grpc.StatusCode.UNAUTHENTICATED

    # Install code ID via governance
    network.consortium.add_executor_code(primary, code_id, supported_endpoints)
    executor_credentials, _ = register_new_executor(primary, network, message)

    # Attempting to install another executor code ID with overlapping paths, producing ambiguous dispatch, produces an error
    conflicting_endpoint = supported_endpoints[0]
    try:
        network.consortium.add_executor_code(
            primary, make_fake_code_id(), [conflicting_endpoint]
        )
        assert False, "Expected unreachable"
    except infra.proposal.ProposalNotCreated as e:
        conflicting_dispatch = (
            f'{conflicting_endpoint["method"]} {conflicting_endpoint["uri"]}'
        )
        error_msg = e.response.body.json()["error"]["message"]
        assert (
            conflicting_dispatch in error_msg
        ), f"Expected proposal creation to fail and report {conflicting_dispatch} in error message: {error_msg}"

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

    # Confirm that after governance removes this executor code ID, additional executors cannot be registered
    network.consortium.remove_executor_code(primary, code_id)

    try:
        register_new_executor(primary, network, message)
        assert False, "Expected unreachable"
    except grpc.RpcError as e:
        # pylint: disable=no-member
        assert e.code() == grpc.StatusCode.UNAUTHENTICATED

    return network


def test_simple_executor(network, args):
    primary, _ = network.find_primary()

    supported_endpoints = WikiCacherExecutor.get_supported_endpoints({"Earth"})

    code_id = make_fake_code_id()
    network.consortium.add_executor_code(
        primary,
        code_id,
        supported_endpoints=supported_endpoints,
    )
    message = new_executor_message(
        quote=code_id.encode("ascii"),
    )
    credentials, _ = register_new_executor(
        primary,
        network,
        message,
    )

    # Note: There is a distinct kind of 404 here - this supported endpoint is _registered_, but no executor is _active_
    with primary.client() as c:
        r = c.get("/article_description/Earth")
        assert r.status_code == http.HTTPStatus.NOT_FOUND
        assert "No active executors" in r.body.json()["error"]["message"], r

    wikicacher_executor = WikiCacherExecutor(primary)
    wikicacher_executor.credentials = credentials
    with executor_thread(wikicacher_executor):
        with primary.client() as c:
            r = c.post("/not/a/real/endpoint")
            # This is a 404 from the framework
            assert r.status_code == http.HTTPStatus.NOT_FOUND
            assert "Unknown path" in r.body.json()["error"]["message"], r

            r = c.get("/article_description/Earth")
            assert r.status_code == http.HTTPStatus.NOT_FOUND
            # Note: This is a 404 returned by this specific executor rather than the framework
            assert "No description for" in r.body.text(), r

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

            supported_endpoints = WikiCacherExecutor.get_supported_endpoints(
                {topics[i]}
            )

            code_id = make_fake_code_id()
            network.consortium.add_executor_code(
                primary,
                code_id,
                supported_endpoints=supported_endpoints,
            )
            credentials, executor_id = register_new_executor(
                primary,
                network,
                new_executor_message(
                    quote=code_id.encode("ascii"),
                ),
            )

            short_executor_id = executor_id[:4] + "..." + executor_id[-4:]
            wikicacher_executor = WikiCacherExecutor(
                primary, label=f"Executor {short_executor_id}"
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


@reqs.description("Test multiple executors that support the same endpoint")
def test_multiple_executors(network, args):
    primary, _ = network.find_primary()

    code_id = make_fake_code_id()

    # register executor_a
    supported_endpoints = WikiCacherExecutor.get_supported_endpoints({"Monday"})

    network.consortium.add_executor_code(
        primary,
        code_id,
        supported_endpoints=supported_endpoints,
    )
    executor_a_credentials, _ = register_new_executor(
        primary,
        network,
        new_executor_message(quote=code_id.encode("ascii")),
    )
    wikicacher_executor_a = WikiCacherExecutor(primary)
    wikicacher_executor_a.credentials = executor_a_credentials

    # register executor_b
    # This uses the same code_id, and supports the same endpoints
    executor_b_credentials, _ = register_new_executor(
        primary,
        network,
        new_executor_message(quote=code_id.encode("ascii")),
    )
    wikicacher_executor_b = WikiCacherExecutor(primary)
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

    logging_executor = LoggingExecutor(primary)
    supported_endpoints = logging_executor.supported_endpoints

    code_id = make_fake_code_id()
    network.consortium.add_executor_code(
        primary,
        code_id,
        supported_endpoints=supported_endpoints,
    )
    credentials, _ = register_new_executor(
        primary,
        network,
        new_executor_message(quote=code_id.encode("ascii")),
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

    return network


def run(args):
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
                r["nodes"][0]["rpc_interfaces"][infra.interfaces.PRIMARY_RPC_INTERFACE][
                    "app_protocol"
                ]
                == "HTTP2"
            ), "Target node does not support HTTP/2"

        network = test_executor_registration(network, args)
        network = test_simple_executor(network, args)
        network = test_parallel_executors(network, args)
        network = test_streaming(network, args)
        network = test_async_streaming(network, args)
        network = test_logging_executor(network, args)
        network = test_multiple_executors(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.snapshot_tx_interval = 10000  # Don't spend too much time producing snapshots
    # Note: set following envvar for debug logs:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http

    run(args)
