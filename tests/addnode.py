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

        # TODO: For now, node is added straight away, without validation by
        # the consortium. See https://github.com/microsoft/CCF/issues/293
        LOG.debug("Add a valid node")
        new_node = network.create_and_add_node("libloggingenc", args)

        with primary.management_client() as mc:
            check_commit = infra.ccf.Checker(mc)

            with new_node.user_client(format="json") as c:
                check_commit(
                    c.rpc("LOG_record", {"id": 42, "msg": "Hello world"}), result=True
                )

        LOG.debug("Add an invalid node (code id not known)")
        assert (
            network.create_and_add_node("libluagenericenc", args) == None
        ), "Adding node with unknown code id should fail"

        LOG.debug("Retire node")
        network.retire_node(primary, 0)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            default="libloggingenc",
        )

    args = e2e_args.cli_args(add)

    if args.enclave_type != "debug":
        LOG.error("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
