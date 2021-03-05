# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import http
import time
import sys
from loguru import logger as LOG


DEFAULT_NODES = ["local://127.0.0.1:8000"]


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

    LOG.info(f"Starting {len(hosts)} CCF node{'s' if len(hosts) > 1 else ''}...")
    if args.enclave_type == "virtual":
        LOG.warning("Virtual mode enabled")

    with infra.network.network(
        hosts=hosts,
        binary_directory=args.binary_dir,
        library_directory=args.library_dir,
        dbg_nodes=args.debug_nodes,
    ) as network:
        if args.recover:
            args.label = args.label + "_recover"
            LOG.info("Recovering network from:")
            LOG.info(f" - Common directory: {args.common_dir}")
            LOG.info(f" - Ledger: {args.ledger_dir}")
            if args.snapshot_dir:
                LOG.info(f" - Snapshots: {args.snapshot_dir}")
            else:
                LOG.warning(
                    "No available snapshot to recover from. Entire transaction history will be replayed."
                )
            network.start_in_recovery(
                args,
                args.ledger_dir,
                snapshot_dir=args.snapshot_dir,
                common_dir=args.common_dir,
            )
            network.recover(args)
        else:
            network.start_and_join(args)

        primary, backups = network.find_nodes()
        max_len = len(str(len(backups)))

        # To be sure, confirm that the app frontend is open on each node
        for node in [primary, *backups]:
            with node.client("user0") as c:
                if args.verbose:
                    r = c.get("/app/commit")
                else:
                    r = c.get("/app/commit", log_capture=[])
                assert r.status_code == http.HTTPStatus.OK, r.status_code

        def pad_node_id(nid):
            return (f"{{:{max_len}d}}").format(nid)

        LOG.info("Started CCF network with the following nodes:")
        LOG.info(
            "  Node [{}] = https://{}:{}".format(
                pad_node_id(primary.local_node_id), primary.pubhost, primary.pubport
            )
        )

        for b in backups:
            LOG.info(
                "  Node [{}] = https://{}:{}".format(
                    pad_node_id(b.local_node_id), b.pubhost, b.pubport
                )
            )

        LOG.info(
            f"You can now issue business transactions to the {args.package} application"
        )
        if args.js_app_bundle is not None:
            LOG.info(f"Loaded JS application: {args.js_app_bundle}")
        LOG.info(
            f"Keys and certificates have been copied to the common folder: {network.common_dir}"
        )
        LOG.info(
            "See https://microsoft.github.io/CCF/main/users/issue_commands.html for more information"
        )
        LOG.warning("Press Ctrl+C to shutdown the network")

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
            help=f"List of (local://|ssh://)hostname:port[,pub_hostnames:pub_port]. Default is {DEFAULT_NODES}",
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
            "--common-dir",
            help="Directory containing previous network member identities",
        )

    args = infra.e2e_args.cli_args(add)
    if args.recover and not all([args.ledger_dir, args.common_dir]):
        print("Error: --recover requires --ledger-dir and --common-dir arguments.")
        sys.exit(1)

    run(args)
