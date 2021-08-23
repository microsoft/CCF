# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import json
import http
import random
import infra.network
import infra.proc
import infra.e2e_args
import infra.checker

from loguru import logger as LOG


def run(args):
    # SNIPPET_START: parsing
    with open(args.scenario, encoding="utf-8") as f:
        scenario = json.load(f)

    hosts = scenario.get("hosts", infra.e2e_args.max_nodes(args, f=0))
    args.package = scenario["package"]
    # SNIPPET_END: parsing

    scenario_dir = os.path.dirname(args.scenario)

    # SNIPPET_START: create_network
    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes
    ) as network:
        network.start_and_join(args)
        # SNIPPET_END: create_network

        primary, backups = network.find_nodes()

        with primary.client() as mc:

            check = infra.checker.Checker()
            check_commit = infra.checker.Checker(mc)

            for connection in scenario["connections"]:
                with (
                    primary.client("user0")
                    if not connection.get("on_backup")
                    else random.choice(backups).client("user0")
                ) as client:
                    txs = connection.get("transactions", [])

                    for include_file in connection.get("include", []):
                        with open(
                            os.path.join(scenario_dir, include_file), encoding="utf-8"
                        ) as f:
                            txs += json.load(f)

                    for tx in txs:
                        r = client.call(
                            tx["method"],
                            body=tx["body"],
                            http_verb=tx.get("verb", "POST"),
                        )

                        if tx.get("expected_error") is not None:
                            check(
                                r,
                                error=lambda status, msg, transaction=tx: status
                                # pylint: disable=no-member
                                == http.HTTPStatus(
                                    transaction.get("expected_error")
                                ).value,
                            )

                        elif tx.get("expected_result") is not None:
                            check_commit(r, result=tx.get("expected_result"))

                        else:
                            check_commit(r, result=lambda res: res is not None)

                network.wait_for_node_commit_sync()

    if args.network_only:
        LOG.info("Keeping network alive with the following nodes:")
        LOG.info("  Primary = {}:{}".format(primary.pubhost, primary.pubport))
        for i, f in enumerate(backups):
            LOG.info("  Backup[{}] = {}:{}".format(i, f.pubhost, f.pubport))

        input("Press Enter to shutdown...")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--scenario",
            help="Path to JSON file listing transactions to execute",
            type=str,
            required=True,
        )

    args = infra.e2e_args.cli_args(add=add)
    run(args)
