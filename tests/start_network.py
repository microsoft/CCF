# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import time
import sys
import json
import os
from loguru import logger as LOG


DEFAULT_NODES = ["127.0.0.1:8000"]


def dump_network_info(path, network, node):
    network_info = {}
    network_info["host"] = node.pubhost
    network_info["port"] = node.rpc_port
    network_info["ledger"] = node.remote.ledger_path()
    network_info["common_dir"] = network.common_dir

    with open(path, "w") as network_info_file:
        json.dump(network_info, network_info_file)

    LOG.debug(f"Dumped network information to {os.path.abspath(path)}")


def run(args):
    hosts = args.node or DEFAULT_NODES

    if not args.verbose:
        LOG.remove()
        LOG.add(
            sys.stdout,
            format="<green>[{time:HH:mm:ss.SSS}]</green> {message}",
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
            LOG.info(
                f" - Defunct network public encryption key: {args.network_enc_pubk}"
            )
            LOG.info(f" - Common directory: {args.common_dir}")
            LOG.info(f" - Ledger: {args.ledger_dir}")
            if args.snapshot_dir:
                LOG.info(f" - Snapshots: {args.snapshot_dir}")
            else:
                LOG.warning(
                    "No available snapshot to recover from. Entire transaction history will be replayed."
                )
            network.start_in_recovery(
                args, args.ledger_dir, args.snapshot_dir, args.common_dir
            )
            network.recover(args, args.network_enc_pubk)
        else:
            network.start_and_join(args)

        primary, backups = network.find_nodes()
        max_len = len(str(len(backups)))

        def pad_node_id(nid):
            return (f"{{:{max_len}d}}").format(nid)

        LOG.info("Started CCF network with the following nodes:")
        LOG.info(
            "  Node [{}] = https://{}:{}".format(
                pad_node_id(primary.node_id), primary.pubhost, primary.rpc_port
            )
        )

        for b in backups:
            LOG.info(
                "  Node [{}] = https://{}:{}".format(
                    pad_node_id(b.node_id), b.pubhost, b.rpc_port
                )
            )

        # Dump primary info to file for tutorial testing
        if args.network_info_file is not None:
            dump_network_info(args.network_info_file, network, primary)

        LOG.info(
            f"You can now issue business transactions to the {args.package} application."
        )
        LOG.info(
            f"Keys and certificates have been copied to the common folder: {network.common_dir}"
        )
        LOG.info(
            "See https://microsoft.github.io/CCF/master/users/issue_commands.html for more information."
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
            help=f"List of hostnames[,pub_hostnames:ports]. Default is {DEFAULT_NODES}",
            action="append",
        )
        parser.add_argument(
            "-v",
            "--verbose",
            help="If set, start up logs are displayed",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--network-info-file",
            help="Path to output file where network information will be dumped to (useful for scripting)",
            default=None,
        )
        parser.add_argument(
            "-r",
            "--recover",
            help="Start a new network from an existing one",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--ledger-dir",
            help="Ledger directory to recover from",
        )
        parser.add_argument(
            "--snapshot-dir",
            help="Snapshot directory to recover from (optional)",
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
            "Error: --recover requires --ledger-dir, --network-enc-pubk and --common-dir arguments."
        )
        sys.exit(1)

    run(args)
