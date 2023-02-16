from argparse import ArgumentParser
import sys

sys.path.append("/workspaces/CCF/tests")

from executors.wiki_cacher import WikiCacherExecutor
from external_executor import register_new_executor


if __name__ == "__main__":

    print("Starting wiki cacher executor...")

    parser = ArgumentParser()
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
        help="List of supported endpoints",
    )
    args = parser.parse_args()

    executor = WikiCacherExecutor(args.node_public_rpc_address)
    supported_endpoints = executor.get_supported_endpoints({args.supported_endpoints})

    credentials = register_new_executor(
        args.node_public_rpc_address,
        args.network_common_dir,
        supported_endpoints=supported_endpoints,
    )

    executor.credentials = credentials

    executor.run_loop()
