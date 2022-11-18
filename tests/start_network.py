# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.interfaces
import infra.network
import http
import time
import sys
import json
import os
import shutil
from loguru import logger as LOG

DEFAULT_NODES = ["local://127.0.0.1:8000"]


def run(args):
    # Read RPC interfaces from configuration file if specified, otherwise
    # read from command line arguments or default
    if args.config_file is not None:
        with open(args.config_file, encoding="utf-8") as f:
            hosts = [
                infra.interfaces.HostSpec.from_json(
                    json.load(f)["network"]["rpc_interfaces"]
                )
            ]
    else:
        hosts = args.node or DEFAULT_NODES
        hosts = [
            infra.interfaces.HostSpec.from_str(node, http2=args.http2) for node in hosts
        ]

    if not args.verbose:
        LOG.remove()
        LOG.add(
            sys.stdout,
            format="<green>[{time:HH:mm:ss.SSS}]</green> {message}",
        )
        LOG.disable("infra")
        LOG.disable("ccf")

    if args.enclave_platform == "virtual":
        LOG.warning("Virtual mode enabled")
    LOG.info(f"Starting {len(hosts)} CCF node{'s' if len(hosts) > 1 else ''}...")

    try:
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
                if args.snapshots_dir:
                    LOG.info(f" - Snapshots: {args.snapshots_dir}")
                else:
                    LOG.warning(
                        "No available snapshot to recover from. Entire transaction history will be replayed."
                    )

                # Copy the old service cert to a new location, so it isn't overwritten on startup
                previous_service_cert = os.path.join(
                    args.common_dir, "service_cert.pem"
                )
                if not os.path.exists(previous_service_cert):
                    raise ValueError(
                        f"Cannot recover, missing previous service cert {previous_service_cert}"
                    )
                backup_location = os.path.join(
                    args.common_dir, "predecessor_service_cert.pem"
                )
                LOG.warning(f"Storing previous service's cert at {backup_location}")
                shutil.copy(previous_service_cert, backup_location)
                args.previous_service_identity_file = backup_location

                network.start_in_recovery(
                    args,
                    args.ledger_dir,
                    snapshots_dir=args.snapshots_dir,
                    common_dir=args.common_dir,
                )
                network.recover(args)
            else:
                network.start_and_open(args)

            nodes = network.get_joined_nodes()
            max_len = max([len(str(node.local_node_id)) for node in nodes])

            # To be sure, confirm that the app frontend is open on each node
            for node in nodes:
                with node.client() as c:
                    if args.verbose:
                        r = c.get("/app/commit")
                    else:
                        r = c.get("/app/commit", log_capture=[])
                    assert r.status_code == http.HTTPStatus.OK, r.status_code

            def pad_node_id(nid):
                return (f"{{:{max_len}d}}").format(nid)

            LOG.info("Started CCF network with the following nodes:")
            for node in nodes:
                LOG.info(
                    "  Node [{}] = https://{}".format(
                        pad_node_id(node.local_node_id),
                        node.get_public_rpc_address(),
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
                "See https://microsoft.github.io/CCF/main/use_apps/issue_commands.html for more information"
            )
            LOG.warning("Press Ctrl+C to shutdown the network")

            if args.auto_shutdown:
                if args.auto_shutdown_delay_s > 0:
                    LOG.info(
                        f"Waiting {args.auto_shutdown_delay_s}s before automatic shutdown..."
                    )
                    try:
                        time.sleep(args.auto_shutdown_delay_s)

                    except KeyboardInterrupt:
                        LOG.info("Stopping all CCF nodes...")

                LOG.info("Automatically shut down network after successful opening")
            else:
                try:
                    while True:
                        time.sleep(60)

                except KeyboardInterrupt:
                    LOG.info("Stopping all CCF nodes...")

        LOG.info("All CCF nodes stopped.")
    except infra.network.NetworkShutdownError as e:
        LOG.error("Error! Some nodes ran into issues:")
        for node_id, errors in e.errors.items():
            errors = "\n".join(errors)
            LOG.error(f"- Node [{node_id}]:\n{errors}\n")
        LOG.info(
            "Please raise a bug if the issue is unexpected: https://github.com/microsoft/CCF/issues/new?assignees=&labels=bug&template=bug_report.md&title=Unexpected%20error%20when%20running%20sandbox%20script"
        )
        sys.exit(1)


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
            help="Include more infra logs describing startup process",
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
            "--snapshots-dir",
            help="Snapshots directory to recover from (optional)",
        )
        parser.add_argument(
            "--common-dir",
            help="Directory containing previous network member identities",
        )
        parser.add_argument(
            "--auto-shutdown",
            help="If set, service automatically shuts down after successful opening",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--auto-shutdown-delay-s",
            help="If --auto-shutdown is set, delay after which service automatically stops",
            type=int,
            default=0,
        )

    args = infra.e2e_args.cli_args(add)
    if args.recover and not all([args.ledger_dir, args.common_dir]):
        print("Error: --recover requires --ledger-dir and --common-dir arguments.")
        sys.exit(1)

    if args.common_dir is not None:
        args.common_dir = os.path.abspath(args.common_dir)

    run(args)
