# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import suite.test_requirements as reqs

from executors.wiki_cacher import executor_thread, WikiCacherExecutor

# pylint: disable=import-error
import kv_pb2 as KV

# pylint: disable=import-error
import kv_pb2_grpc as Service

# pylint: disable=import-error
import stringops_pb2 as StringOps

# pylint: disable=import-error
import stringops_pb2_grpc as StringOpsService

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

from loguru import logger as LOG


@contextlib.contextmanager
def wrap_tx(stub, primary):
    with primary.client(connection_timeout=0.1) as c:
        try:
            # This wrapper is used to test the gRPC KV API directly. That is
            # only possible when this executor is processing an active request
            # (StartTx() returns a non-empty response). To trigger that, we do
            # this placeholder GET request. It immediately times out and fails,
            # but then the node we're speaking to will return a
            # RequestDescription for us to operate over.
            # This is a temporary hack to allow direct access to the KV API.
            c.get("/placeholder", timeout=0.1, log_capture=[])
        except Exception as e:
            LOG.trace(e)
        rd = stub.StartTx(Empty())
        assert rd.HasField("optional"), rd
        yield stub
        stub.EndTx(KV.ResponseDescription())


def register_new_executor(node, network, message=None):
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


@reqs.description("Register an external executor")
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
                    #   Error parsing metadata: error=invalid value key=content-type value=application/json
                    # These are harmless and expected, and I haven't found a way to swallow them
                    assert not should_pass
                    assert e.code() == grpc.StatusCode.UNAUTHENTICATED, e

    return network


@reqs.description("Store and retrieve key via external executor app")
def test_put_get(network, args):
    primary, _ = network.find_primary()

    executor_a = register_new_executor(primary, network)
    executor_b = register_new_executor(primary, network)

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
                with wrap_tx(stub_alt, primary) as tx2:
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

    return network


def test_simple_executor(network, args):
    primary, _ = network.find_primary()

    credentials = register_new_executor(primary, network)

    with executor_thread(WikiCacherExecutor(primary, credentials)):
        with primary.client() as c:
            r = c.post("/not/a/real/endpoint")
            assert r.status_code == http.HTTPStatus.NOT_FOUND

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
        "Monday",
        "Tuesday",
        "Wednesday",
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
            credentials = register_new_executor(primary, network)
            executor = WikiCacherExecutor(primary, credentials, label=f"Executor {i}")
            executors.append(executor)
            stack.enter_context(executor_thread(executor))

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
        return (StringOps.OpIn(echo=StringOps.EchoOp(body=s)), ("echoed", s))

    def reverse_op(s):
        return (
            StringOps.OpIn(reverse=StringOps.ReverseOp(body=s)),
            ("reversed", s[::-1]),
        )

    def truncate_op(s):
        start = random.randint(0, len(s))
        end = random.randint(start, len(s))
        return (
            StringOps.OpIn(truncate=StringOps.TruncateOp(body=s, start=start, end=end)),
            ("truncated", s[start:end]),
        )

    def empty_op(s):
        # oneof may always be null - generate some like this to make sure they're handled "correctly"
        return (StringOps.OpIn(), None)

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
        stub = StringOpsService.TestStub(channel)

        compare_op_results(stub, 0)
        compare_op_results(stub, 1)
        compare_op_results(stub, 30)
        compare_op_results(stub, 1000)

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
        network = test_put_get(network, args)
        network = test_simple_executor(network, args)
        network = test_parallel_executors(network, args)
        network = test_streaming(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=1)

    # Note: set following envvar for debug logs:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http

    run(args)
