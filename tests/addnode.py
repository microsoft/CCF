# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import json

import logging
import time

from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        # add a valid node
        res = network.create_and_add_node("libloggingenc", args, 2)
        assert res[0] == True
        new_node = res[1]

        with open("networkcert.pem", mode="rb") as file:
            net_cert = list(file.read())

        # add an invalid node
        assert network.create_and_add_node("libluagenericenc", args, 3, False) == (
            False,
            infra.jsonrpc.ErrorCode.CODE_ID_NOT_FOUND,
        )

        with new_node.management_client(format="json") as c:
            c.rpc(
                "joinNetwork",
                {
                    "hostname": primary.host,
                    "service": str(primary.tls_port),
                    "network_cert": net_cert,
                },
            )
            new_node.join_network()
            network.wait_for_node_commit_sync()


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            default="libloggingenc",
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
