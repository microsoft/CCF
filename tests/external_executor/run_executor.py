# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from argparse import ArgumentParser
import sys

sys.path.append("/workspaces/CCF/tests")

from executors.wiki_cacher import WikiCacherExecutor
from executors.logging_app import LoggingExecutor
from external_executor import register_new_executor


EXECUTORS = {
    "wiki_cacher": WikiCacherExecutor,
    "logging": LoggingExecutor,
}


if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument(
        "--executor",
        help="Executor to run",
    )
    parser.add_argument(
        "--node-public-rpc-address",
        help="Public RPC address of CCF node the executor is registered to",
    )
    parser.add_argument(
        "--network-common-dir",
        help="Path to common network directory",
    )
    parser.add_argument(
        "--supported-endpoints",
        help="Comma separated list of supported endpoints",
        type=lambda s: {tuple(e.split(":")) for e in s.split(",")},
    )
    args = parser.parse_args()

    print(f"Starting {args.executor} executor...")

    executor = EXECUTORS[args.executor](args.node_public_rpc_address)

    credentials = register_new_executor(
        args.node_public_rpc_address,
        args.network_common_dir,
        supported_endpoints=args.supported_endpoints,
    )

    executor.credentials = credentials

    executor.run_loop()
