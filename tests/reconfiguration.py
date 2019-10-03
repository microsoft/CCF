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


def check_can_progress(node):
    with node.node_client() as mc:
        check_commit = infra.ccf.Checker(mc)
        with node.user_client() as c:
            check_commit(c.rpc("LOG_record", {"id": 42, "msg": "Hello"}), result=True)


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        # Adding as many pending nodes as initial (trusted) nodes should not
        # change the raft consensus rules (i.e. majority)
        number_new_nodes = len(hosts)
        LOG.info(
            f"Adding {number_new_nodes} pending nodes - consensus rules should not change"
        )

        for _ in range(number_new_nodes):
            network.create_and_add_pending_node(args.package, "localhost", args)
        check_can_progress(primary)

        LOG.info("Add a valid node")
        new_node = network.create_and_trust_node(args.package, "localhost", args, True)
        assert new_node
        check_can_progress(primary)

        if args.enclave_type == "debug":
            LOG.info("Add an invalid node (unknown code id)")
            assert (
                network.create_and_trust_node(
                    "libluagenericenc", "localhost", args, True
                )
                == None
            ), "Adding node with unknown code id should fail"
        else:
            LOG.warning("Skipping unknown code id test with virtual enclave")

        LOG.info("Retire node")
        network.retire_node(primary, 0)

        LOG.info("Add a valid node")
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
