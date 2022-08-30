# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.


import infra.network
import infra.e2e_args
import infra.interfaces

import kv_pb2 as KV
import kv_pb2_grpc as Service
import grpc
import os

from loguru import logger as LOG


def test(network, args):
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

    LOG.info("gRPC request")
    # Note: set following envvar for more debug info:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http
    credentials = grpc.ssl_channel_credentials(
        open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    )
    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        # stub = KV.KvLedgerStub(channel)
        # assert stub.PostLog(put) == None
        kv = KV.KVKeyValue()
        kv.key = b"my_key"
        kv.value = b"my_value"

        stub = Service.KVStub(channel)
        r = stub.Put(kv)
        r = stub.Get()

    LOG.success("PostLog successful")

    # with grpc.secure_channel(
    #     target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
    #     credentials=credentials,
    # ) as channel:
    #     stub = Service.KvLedgerStub(channel)
    #     rep = stub.GetLog(get)
    #     LOG.info(f"Value for '{get.key.decode()}': '{rep.value.decode()}'")
    #     assert rep.value == put.value

    # LOG.success("GetLog successful")

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
    ) as network:
        network.start_and_open(args)
        test(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.host_log_level = "trace"
    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    # Also run $ pip install -r /opt/ccf/bin/requirements.txt
    run(args)
