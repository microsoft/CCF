# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import suite.test_requirements as reqs
import queue
import grpc
import time
import threading
import external_executor

from executors.logging_app import LoggingExecutor
from executors.util import executor_thread

# pylint: disable=import-error
import index_pb2 as Index

# pylint: disable=import-error
import index_pb2_grpc as IndexService

from loguru import logger as LOG

@reqs.description("Test index API")
def test_index_api(network, args):
    primary, _ = network.find_primary()

    def add_kv_entries(network):
        logging_executor = LoggingExecutor(primary)
        supported_endpoints = logging_executor.supported_endpoints
        credentials = external_executor.register_new_executor(
            primary, network, supported_endpoints=supported_endpoints
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

    credentials = external_executor.register_new_executor(primary, network)

    with grpc.secure_channel(
        target=f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}",
        credentials=credentials,
    ) as channel:
        data = queue.Queue()
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
                    data_structure=Index.DataStructure.MAP,
                    key=res.key,
                    value=res.value,
                )
            )

        log_id = 14
        for _ in range(3):
            LOG.info("Fetching indexed data")
            result = index_stub.GetIndexedData(
                Index.IndexKey(
                    strategy_name="TestStrategy",
                    data_structure=Index.DataStructure.MAP,
                    key=log_id.to_bytes(8, "big"),
                )
            )
            assert result.value.decode("utf-8") == "hello_world_" + str(log_id)
            log_id = log_id + 1

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