# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import suite.test_requirements as reqs

# pylint: disable=import-error
import kv_pb2 as KV

# pylint: disable=import-error
import kv_pb2_grpc as Service
import grpc
import os
import infra.proc

from loguru import logger as LOG

PROTO_SOURCES_OUTPUT_FILE = "."


def generate_from_proto_files(proto_dir):
    # Generate Python source files from proto definitions here rather than cmake
    # as some CI executors do not cope well with launching the Python interpreter
    for f in os.listdir(proto_dir):
        if f.endswith(".proto"):
            cmd = ["python", "-m", "grpc_tools.protoc"]
            cmd += ["-I", proto_dir]
            cmd += ["--python_out", PROTO_SOURCES_OUTPUT_FILE]
            cmd += ["--grpc_python_out", PROTO_SOURCES_OUTPUT_FILE]
            cmd += [f]
            infra.proc.ccall(*cmd)


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

    my_key = "my_key"
    my_value = "my_value"
    my_table = "my_table"

    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        put = KV.KVKeyValue()
        put.key = my_key.encode()
        put.value = my_value.encode()
        put.table = my_table.encode()

        LOG.info(f"Put key '{my_key}' in table '{my_table}'")
        stub = Service.KVStub(channel)
        stub.Put(put)

        LOG.info(f"Get key '{my_key}' in table '{my_table}'")
        get = KV.KVKey()
        get.key = my_key.encode()
        get.table = my_table.encode()
        r = stub.Get(get)
        assert r.value == my_value.encode()
        LOG.success(f"Successfully read key '{my_key}' in table '{my_table}'")

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
    ) as network:
        network.start_and_open(args)
        test_put_get(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--proto-dir",
            help="Absolute file to directory containing protobuf files",
            type=str,
        )

    args = infra.e2e_args.cli_args(add)

    args.host_log_level = "trace"
    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    generate_from_proto_files(args.proto_dir)
    run(args)
