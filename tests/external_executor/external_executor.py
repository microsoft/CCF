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
import random
import time
from collections import defaultdict

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
            c.get("/placeholder", timeout=0.1)
        except Exception as e:
            LOG.trace(e)
        rd = stub.StartTx(Empty())
        assert rd.HasField("optional"), rd
        yield stub
        stub.EndTx(KV.ResponseDescription())


@reqs.description("Register an external executor")
def test_executor_registration(network, cert, args):
    primary, _ = network.find_primary()

    credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )

    attestation_format = ExecutorRegistration.Attestation.AMD_SEV_SNP_V1
    quote = "testquote"
    endorsements = "testendorsement"
    uris = "/foo/hello/bar"
    methods = "GET"

    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        register = ExecutorRegistration.NewExecutor()
        register.attestation.format = attestation_format
        register.attestation.quote = quote.encode()
        register.attestation.endorsements = endorsements.encode()
        register.cert = cert.encode()

        supported_endpoint = register.supported_endpoints.add()
        supported_endpoint.method = methods
        supported_endpoint.uri = uris

        stub = RegistrationService.ExecutorRegistrationStub(channel)
        r = stub.RegisterExecutor(register)
        assert r.details == "Executor registration is accepted."
        return network


@reqs.description("Test basic KV operations via external executor app")
def test_kv(network, credentials, args):
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

    # Note: set following envvar for debug logs:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http

    my_table = "public:my_table"
    my_key = b"my_key"
    my_value = b"my_value"

    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
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

            # Note: It should be possible to test this here, but currently
            # unsupported as we only allow one remote transaction at a time
            # LOG.info("Snapshot isolation")
            # with wrap_tx(stub) as tx2:
            #     for t, k, v in writes:
            #         require_missing(tx2, t, k)

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


def test_simple_executor(network, credentials, args):
    primary, _ = network.find_primary()

    with executor_thread(WikiCacherExecutor(primary, credentials)):
        with primary.client() as c:
            c.post("/not/a/real/endpoint")
            c.post("/update_cache/Earth")
            c.get("/article_description/Earth")

        time.sleep(2)

    return network


@reqs.description("Test gRPC streaming APIs")
def test_streaming(network, args):
    primary, _ = network.find_primary()

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
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        stub = StringOpsService.TestStub(channel)

        compare_op_results(stub, 0)
        compare_op_results(stub, 1)
        compare_op_results(stub, 30)
        compare_op_results(stub, 1000)


def run(args):
    key_priv_pem, _ = infra.crypto.generate_ec_keypair()
    cert = infra.crypto.generate_cert(key_priv_pem)

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
    ) as network:
        network.start_and_open(args)
        credentials = grpc.ssl_channel_credentials(
            root_certificates=open(
                os.path.join(network.common_dir, "service_cert.pem"), "rb"
            ).read(),
            private_key=key_priv_pem.encode(),
            certificate_chain=cert.encode(),
        )
        network = test_executor_registration(network, cert, args)
        network = test_kv(network, credentials, args)
        network = test_simple_executor(network, credentials, args)
        network = test_streaming(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    run(args)
