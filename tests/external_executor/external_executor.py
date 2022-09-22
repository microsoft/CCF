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
import http_pb2 as HTTP

# pylint: disable=import-error
import kv_pb2_grpc as Service

# pylint: disable=no-name-in-module
from google.protobuf.empty_pb2 import Empty as Empty

import grpc
import os
import contextlib
import random
import time

from loguru import logger as LOG


@contextlib.contextmanager
def wrap_tx(stub):
    stub.StartTx(Empty())
    yield stub
    stub.EndTx(KV.ResponseDescription())


@reqs.description("Store and retrieve key via external executor app")
def test_put_get(network, args):
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

    credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )

    my_table = "public:my_table"
    my_key = b"my_key"
    my_value = b"my_value"

    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        stub = Service.KVStub(channel)

        with wrap_tx(stub) as tx:
            LOG.info(f"Put key '{my_key}' in table '{my_table}'")
            tx.Put(KV.KVKeyValue(table=my_table, key=my_key, value=my_value))

        with wrap_tx(stub) as tx:
            LOG.info(f"Get key '{my_key}' in table '{my_table}'")
            r = tx.Get(KV.KVKey(table=my_table, key=my_key))
            assert r.HasField("optional")
            assert r.optional.value == my_value
            LOG.success(f"Successfully read key '{my_key}' in table '{my_table}'")

        unknown_key = b"unknown_key"
        with wrap_tx(stub) as tx:
            LOG.info(f"Get unknown key '{unknown_key}' in table '{my_table}'")
            r = tx.Get(KV.KVKey(table=my_table, key=unknown_key))
            assert not r.HasField("optional")
            LOG.success(f"Unable to read key '{unknown_key}' as expected")

        tables = ("public:table_a", "public:table_b", "public:table_c")
        writes = [
            (
                random.choice(tables),
                f"Key{i}".encode(),
                random.getrandbits(((i % 16) + 1) * 8).to_bytes(((i % 16) + 1), "big"),
            )
            for i in range(10)
        ]

        with wrap_tx(stub) as tx:
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

        with wrap_tx(stub) as tx3:
            LOG.info("Read applied writes")
            for t, k, v in writes:
                r = tx3.Get(KV.KVKeyValue(table=t, key=k))
                assert r.HasField("optional")
                assert r.optional.value == v

    return network


def test_simple_executor(network, args):
    primary, _ = network.find_primary()
    credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )

    with executor_thread(WikiCacherExecutor(primary, credentials)) as ex:
        with primary.client() as c:
            r = c.post("/not/a/real/endpoint")
            r = c.post("/update_cache/Earth")
            r = c.get("/article_description/Earth")

        time.sleep(2)

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
    ) as network:
        network.start_and_open(args)

        network = test_put_get(network, args)
        network = test_simple_executor(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    run(args)
