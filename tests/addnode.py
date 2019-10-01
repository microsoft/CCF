# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
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

        LOG.debug("Add a valid node")
        new_node = network.create_and_trust_node(args.package, "localhost", args, True)
        assert new_node

        with primary.node_client() as mc:
            check_commit = infra.ccf.Checker(mc)

            with new_node.user_client(format="json") as c:
                check_commit(
                    c.rpc("LOG_record", {"id": 42, "msg": "Hello world"}), result=True
                )

        if args.enclave_type == "debug":
            LOG.debug("Add an invalid node (unknown code id)")
            assert (
                network.create_and_trust_node(
                    "libluagenericenc", "localhost", args, True
                )
                == None
            ), "Adding node with unknown code id should fail"
        else:
            LOG.warning("Skipping unknown code id test with virtual enclave")

        LOG.debug("Retire node")
        network.retire_node(primary, 0)

        LOG.debug("Add a valid node")
        new_node = network.create_and_trust_node(args.package, "localhost", args)
        assert new_node


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
