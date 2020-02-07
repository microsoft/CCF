# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.ccf
import time
import sys

from loguru import logger as LOG


def run(args):
    hosts = args.node or ["localhost"] * 3

    if not args.verbose:
        LOG.remove()
        LOG.add(
            sys.stdout,
            format="<green>[{time:YYYY-MM-DD HH:mm:ss.SSS}]</green> {message}",
        )
        LOG.disable("infra")

    LOG.info("Starting {} CCF nodes...".format(len(hosts)))
    if args.enclave_type == "virtual":
        LOG.warning("Virtual mode enabled")

    with infra.ccf.network(
        hosts=hosts, binary_directory=args.binary_dir, dbg_nodes=args.debug_nodes
    ) as network:
        network.start_and_join(args)
        primary, backups = network.find_nodes()

        LOG.info("Started CCF network with the following nodes:")
        LOG.info(
            "  Node [{:2d}] = {}:{}".format(
                primary.node_id, primary.pubhost, primary.rpc_port
            )
        )
        for b in backups:
            LOG.info("  Node [{:2d}] = {}:{}".format(b.node_id, b.pubhost, b.rpc_port))

        LOG.info(
            "You can now issue business transactions to the {} application.".format(
                args.package
            )
        )
        LOG.info(
            "See https://microsoft.github.io/CCF/users/issue_commands.html for more information."
        )
        LOG.warning("Press Ctrl+C to shutdown the network.")

        try:
            while True:
                time.sleep(60)

        except KeyboardInterrupt:
            LOG.info("Stopping all CCF nodes...")

    LOG.info("All CCF nodes stopped.")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-n",
            "--node",
            help="List of hostnames[,pub_hostnames:ports]. If empty, two nodes are spawned locally",
            action="append",
        )
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., liblogging)",
            required=True,
        )
        parser.add_argument(
            "-v",
            "--verbose",
            help="If set, start up logs are displayed",
            action="store_true",
            default=False,
        )

    args = infra.e2e_args.cli_args(add)
    run(args)
