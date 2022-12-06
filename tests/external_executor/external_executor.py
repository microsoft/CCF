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

# pylint: disable=import-error
import kv_pb2 as KV

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
from collections import defaultdict

from loguru import logger as LOG


@contextlib.contextmanager
def wrap_tx(stub, primary, uri="/placeholder"):
    with primary.client(connection_timeout=0.1) as c:
        try:
            # This wrapper is used to test the gRPC KV API directly. That is
            # only possible when this executor is processing an active request
            # (StartTx() returns a non-empty response). To trigger that, we do
            # this placeholder GET request. It immediately times out and fails,
            # but then the node we're speaking to will return a
            # RequestDescription for us to operate over.
            # This is a temporary hack to allow direct access to the KV API.
            c.get(uri, timeout=0.1, log_capture=[])
        except Exception as e:
            LOG.trace(e)
        rd = stub.StartTx(Empty())
        assert rd.HasField("optional"), rd
        yield stub
        stub.EndTx(KV.ResponseDescription())


def register_new_executor(node, network, message=None, supported_endpoints=None):
    # Generate a new executor identity
    key_priv_pem, _ = infra.crypto.generate_ec_keypair()
    cert = infra.crypto.generate_cert(key_priv_pem)

    if message is None:
        # Create a default NewExecutor message
        message = ExecutorRegistration.NewExecutor()
        message.attestation.format = ExecutorRegistration.Attestation.AMD_SEV_SNP_V1
        message.attestation.quote = b"testquote"
        message.attestation.endorsements = b"testendorsement"
        message.supported_endpoints.add(method="GET", uri="/app/foo/bar")

        if supported_endpoints:
            for method, uri in supported_endpoints:
                message.supported_endpoints.add(method=method, uri=uri)

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

    return executor_credentials


@reqs.description(
    "Register an external executor (Disabled on SNP due to UNKNOWN RPC failures)"
)
@reqs.not_snp()
def test_executor_registration(network, args):
    primary, backup = network.find_primary_and_any_backup()

    executor_credentials = register_new_executor(primary, network)

    anonymous_credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )

    # Confirm that these credentials (and NOT anoymous credentials) provide
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
                    rd = Service.KVStub(channel).StartTx(Empty())
                    assert should_pass, "Expected StartTx to fail"
                    assert not rd.HasField("optional")
                except grpc.RpcError as e:
                    # NB: This failure will have printed errors like:
                    # These are harmless and expected, and I haven't found a way to swallow them
                    assert not should_pass
                    # pylint: disable=no-member
                    assert e.code() == grpc.StatusCode.UNAUTHENTICATED, e

    return network


@reqs.description("Test basic KV operations via external executor app")
def test_kv(network, args):
    primary, _ = network.find_primary()

    supported_endpoints_a = [("GET", "/placeholder")]
    supported_endpoints_b = [("GET", "/placeholderB")]
    executor_a = register_new_executor(
        primary, network, supported_endpoints=supported_endpoints_a
    )
    executor_b = register_new_executor(
        primary, network, supported_endpoints=supported_endpoints_b
    )

    my_table = "public:my_table"
    my_key = b"my_key"
    my_value = b"my_value"

    with grpc.secure_channel(
        target=primary.get_public_rpc_address(),
        credentials=executor_a,
    ) as channel:
        stub = Service.KVStub(channel)

        with wrap_tx(stub, primary) as tx:
            LOG.info(f"Put key {my_key} in table '{my_table}'")
            tx.Put(KV.KVKeyValue(table=my_table, key=my_key, value=my_value))

        with wrap_tx(stub, primary) as tx:
            LOG.info(f"Get key {my_key} in table '{my_table}'")
            r = tx.Get(KV.KVKey(table=my_table, key=my_key))
            assert r.HasField("optional")
            assert r.optional.value == my_value
            LOG.success(f"Successfully read key {my_key} in table '{my_table}'")

        unknown_key = b"unknown_key"
        with wrap_tx(stub, primary) as tx:
            LOG.info(f"Get unknown key {unknown_key} in table '{my_table}'")
            r = tx.Get(KV.KVKey(table=my_table, key=unknown_key))
            assert not r.HasField("optional")
            LOG.success(f"Unable to read key {unknown_key} as expected")

        tables = ("public:table_a", "public:table_b", "public:table_c")
        writes = [
            (
                random.choice(tables),
                f"Key{i}".encode(),
                random.getrandbits(((i % 16) + 1) * 8).to_bytes(((i % 16) + 1), "big"),
            )
            for i in range(10)
        ]

        with wrap_tx(stub, primary) as tx:
            LOG.info("Write multiple entries in single transaction")
            for t, k, v in writes:
                tx.Put(KV.KVKeyValue(table=t, key=k, value=v))

            LOG.info("Read own writes")
            for t, k, v in writes:
                r = tx.Get(KV.KVKeyValue(table=t, key=k))
                assert r.HasField("optional")
                assert r.optional.value == v

            LOG.info("Snapshot isolation")
            with grpc.secure_channel(
                target=primary.get_public_rpc_address(),
                credentials=executor_b,
            ) as channel_alt:
                stub_alt = Service.KVStub(channel_alt)
                with wrap_tx(stub_alt, primary, uri="/placeholderB") as tx2:
                    for t, k, v in writes:
                        r = tx2.Get(KV.KVKey(table=t, key=k))
                        assert not r.HasField("optional")
                        LOG.success(
                            f"Unable to read key {k} from table {t} (in concurrent transaction) as expected"
                        )

        with wrap_tx(stub, primary) as tx3:
            LOG.info("Read applied writes")
            for t, k, v in writes:
                r = tx3.Get(KV.KVKeyValue(table=t, key=k))
                assert r.HasField("optional")
                assert r.optional.value == v

            writes_by_table = defaultdict(dict)
            for t, k, v in writes:
                writes_by_table[t][k] = v

            for t, table_writes in writes_by_table.items():
                LOG.info(f"Read all in {t}")
                r = tx3.GetAll(KV.KVTable(table=t))
                count = 0
                for result in r:
                    count += 1
                    assert result.key in table_writes
                    assert table_writes[result.key] == result.value
                assert count == len(table_writes)

            LOG.info("Clear one table")
            t, cleared_writes = writes_by_table.popitem()
            tx3.Clear(KV.KVTable(table=t))
            for k, _ in cleared_writes.items():
                r = tx3.Has(KV.KVKey(table=t, key=k))
                assert not r.present

                r = tx3.Get(KV.KVKey(table=t, key=k))
                assert not r.HasField("optional")

                r = tx3.GetAll(KV.KVTable(table=t))
                try:
                    next(r)
                    raise AssertionError("Expected unreachable")
                except StopIteration:
                    pass

    return network


def test_simple_executor(network, args):
    primary, _ = network.find_primary()

    wikicacher_executor = WikiCacherExecutor(primary)
    supported_endpoints = wikicacher_executor.get_supported_endpoints({"Earth"})

    credentials = register_new_executor(
        primary, network, supported_endpoints=supported_endpoints
    )

    wikicacher_executor.credentials = credentials
    with executor_thread(wikicacher_executor):
        with primary.client() as c:
            r = c.post("/not/a/real/endpoint")
            body = r.body.json()
            assert r.status_code == http.HTTPStatus.NOT_FOUND
            assert (
                body["error"]["message"]
                == "Only registered endpoints are supported. No executor was found for POST and /not/a/real/endpoint"
            )

            r = c.get("/article_description/Earth")
            assert r.status_code == http.HTTPStatus.NOT_FOUND

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

            wikicacher_executor = WikiCacherExecutor(primary, label=f"Executor {i}")
            supported_endpoints = wikicacher_executor.get_supported_endpoints(
                {topics[i]}
            )

            credentials = register_new_executor(
                primary, network, supported_endpoints=supported_endpoints
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

        event_name = "event_name"
        event_message = "event_message"
        event = Misc.Event(name=event_name)

        q = queue.Queue()

        def subscribe(event_name):
            credentials = grpc.ssl_channel_credentials(
                open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
            )
            with grpc.secure_channel(
                target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
                credentials=credentials,
            ) as channel:
                s = MiscService.TestStub(channel)
                LOG.debug(f"Waiting for event {event_name}...")
                for e in s.Sub(event_name):  # Blocking
                    q.put(e)
                    return

        t = threading.Thread(target=subscribe, args=(event,))
        t.start()

        LOG.info(f"Publishing event {event_name}")
        # Note: There may not be any subscriber yet, so retry until there is one
        while True:
            try:
                s.Pub(Misc.EventInfo(name=event_name, message=event_message))
                break
            except grpc.RpcError:
                LOG.debug(f"Waiting for subscriber for event {event_name}")
            time.sleep(0.1)

        t.join()

        # Assert that expected message was received by subscriber
        assert q.qsize() == 1
        res_event = q.get()
        assert res_event.name == event_name
        assert res_event.message == event_message

        # Subscriber session is now closed but server-side detached stream
        # still exists in the app. Make sure that streaming on closed
        # session does not cause a node crash.
        s.Pub(Misc.EventInfo(name=event_name, message=event_message))

    return network


@reqs.description("Test multiple executors that support the same endpoint")
def test_multiple_executors(network, args):
    primary, _ = network.find_primary()

    # register executor_a
    wikicacher_executor_a = WikiCacherExecutor(primary)
    supported_endpoints_a = wikicacher_executor_a.get_supported_endpoints({"Monday"})

    executor_a_credentials = register_new_executor(
        primary, network, supported_endpoints=supported_endpoints_a
    )
    wikicacher_executor_a.credentials = executor_a_credentials

    # register executor_b
    supported_endpoints_b = [("GET", "/article_description/Monday")]
    executor_b_credentials = register_new_executor(
        primary, network, supported_endpoints=supported_endpoints_b
    )
    wikicacher_executor_b = WikiCacherExecutor(primary)
    wikicacher_executor_b.credentials = executor_b_credentials

    with executor_thread(wikicacher_executor_a):
        with primary.client() as c:
            r = c.post("/update_cache/Monday")
            assert r.status_code == http.HTTPStatus.OK
            content = r.body.text().splitlines()[-1]

            r = c.get("/article_description/Monday")
            assert r.status_code == http.HTTPStatus.OK
            assert r.body.text() == content

    # /article_description/Monday this time will be passed to executor_b
    with executor_thread(wikicacher_executor_b):
        with primary.client() as c:
            r = c.get("/article_description/Monday")
            assert r.status_code == http.HTTPStatus.OK
            assert r.body.text() == content

    return network


def test_logging_executor(network, args):
    primary, _ = network.find_primary()

    logging_executor = LoggingExecutor(primary)
    logging_executor.add_supported_endpoints(("PUT", "/test/endpoint"))
    supported_endpoints = logging_executor.supported_endpoints

    credentials = register_new_executor(
        primary, network, supported_endpoints=supported_endpoints
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
        network = test_kv(network, args)
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

    # Note: set following envvar for debug logs:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http

    run(args)
