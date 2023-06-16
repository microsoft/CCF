# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import suite.test_requirements as reqs
import grpc
import time
import threading
import os

from executors.logging_app.logging_app import LoggingExecutor
from executors.util import executor_thread
from executors.ccf.executors.registration import register_new_executor

import index_pb2 as Index

import index_pb2_grpc as IndexService

from loguru import logger as LOG


@reqs.description("Test index API")
def test_index_api(network, args):
    primary, _ = network.find_primary()
    kv_entries = [
        (14, "hello_world_14"),
        (15, "hello_world_15"),
        (16, "hello_world_16"),
        (14, "hello_world_14_overwrite"),
    ]

    service_certificate_bytes = open(
        os.path.join(network.common_dir, "service_cert.pem"), "rb"
    ).read()

    def add_kv_entries(network):
        credentials = register_new_executor(
            primary.get_public_rpc_address(),
            service_certificate_bytes,
            supported_endpoints=LoggingExecutor.get_supported_endpoints(),
            with_attestation_container=False,
        )
        logging_executor = LoggingExecutor(
            primary.get_public_rpc_address(), credentials
        )
        logging_executor.credentials = credentials
        with executor_thread(logging_executor):
            with primary.client() as c:
                for each in kv_entries:
                    r = c.post(
                        "/log/public",
                        {"id": each[0], "msg": each[1]},
                    )
                    assert r.status_code == 200, r.status_code

    add_kv_entries(network)

    credentials = register_new_executor(
        primary.get_public_rpc_address(),
        service_certificate_bytes,
        with_attestation_container=False,
    )

    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        indexed_entries = []
        subscription_started = threading.Event()

        def InstallandSub():
            in_stub = IndexService.IndexStub(channel)
            for work in in_stub.InstallAndSubscribe(
                Index.IndexSubscribe(
                    map_name="public:records",
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
                result = work.key_value
                key = int.from_bytes(result.key, byteorder="big")
                value = result.value.decode("utf-8")
                LOG.info(f"Got key {key} and value {value} to index")

                indexed_entries.append((key, value))

        th = threading.Thread(target=InstallandSub)
        th.start()

        # Wait for subscription thread to actually start, and the server has confirmed it is ready
        assert subscription_started.wait(timeout=3), "Subscription wait timed out"

        # Wait for the index to be populated
        timeout = 1
        end_time = time.time() + timeout
        while time.time() < end_time:
            if len(indexed_entries) == len(kv_entries):
                break
            time.sleep(0.1)
        else:
            assert False, "Stream timed out"

        assert indexed_entries == kv_entries

        index_stub = IndexService.IndexStub(channel)
        for k, v in indexed_entries:
            index_stub.StoreIndexedData(
                Index.IndexPayload(
                    strategy_name="TestStrategy",
                    data_structure=Index.DataStructure.MAP,
                    key=k.to_bytes(8, "big"),
                    value=v.encode("utf-8"),
                )
            )

        expected_index_state = {}
        for k, v in indexed_entries:
            expected_index_state[k] = v

        for k, v in expected_index_state.items():
            LOG.info(f"Fetching indexed data at key {k}")
            result = index_stub.GetIndexedData(
                Index.IndexKey(
                    strategy_name="TestStrategy",
                    data_structure=Index.DataStructure.MAP,
                    key=k.to_bytes(8, "big"),
                )
            )
            decoded = result.value.decode("utf-8")
            assert decoded == v, f"Indexed data does not match, {decoded} != {v}"

        index_stub.Unsubscribe(Index.IndexStrategy(strategy_name="TestStrategy:MAP"))

        th.join()

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

        network = test_index_api(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "src/apps/external_executor/libexternal_executor"
    args.http2 = True  # gRPC interface
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    # Note: set following envvar for debug logs:
    # GRPC_VERBOSITY=DEBUG GRPC_TRACE=client_channel,http2_stream_state,http

    run(args)
