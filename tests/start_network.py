# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
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
        LOG.disable("ccf")

    LOG.info(f"Starting {len(hosts)} CCF nodes...")
    if args.enclave_type == "virtual":
        LOG.warning("Virtual mode enabled")

    with infra.network.network(
        hosts=hosts, binary_directory=args.binary_dir, dbg_nodes=args.debug_nodes
    ) as network:
        if args.recover:
            args.label = args.label + "_recover"
            LOG.info("Recovering network from:")
            LOG.info(f" - Ledger: {args.ledger_dir}")
            LOG.info(
                f" - Defunct network public encryption key: {args.network_enc_pubk}"
            )
            LOG.info(f" - Common directory: {args.common_dir}")
            network.start_in_recovery(args, args.ledger_dir, args.common_dir)
            network.recover(args, args.network_enc_pubk)
        else:
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
            f"You can now issue business transactions to the {args.package} application."
        )
        LOG.info(f"Certificates have been copied to {network.common_dir}")
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
        parser.add_argument(
            "-r",
            "--recover",
            help="Start a new network from an existing one",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--ledger-dir", help="Ledger directory to recover from",
        )
        parser.add_argument(
            "--network-enc-pubk",
            help="Defunct network public encryption key (used by members to decrypt recovery shares)",
        )
        parser.add_argument(
            "--common-dir",
            help="Directory containing previous network member identities and network encryption key",
        )

    args = infra.e2e_args.cli_args(add)
    if args.recover and (
        args.ledger_dir is None
        or args.common_dir is None
        or args.network_enc_pubk is None
    ):
        print(
            "Error: --recover requires --ledger, --network-enc-pubk and --common-dir arguments."
        )
        sys.exit(1)
    run(args)
