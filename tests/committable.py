# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import time

from loguru import logger as LOG


def run(args):
    hosts = ["localhost"] * 5

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, backups = network.find_nodes()

        # Suspend three of the backups to prevent commit
        backups[1].suspend()
        backups[2].suspend()
        backups[3].stop()

        txs = []
        # Run some transactions that can't be committed
        with primary.client("user0") as uc:
            for i in range(10):
                txs.append(
                    uc.post("/app/log/private", {"id": 100 + i, "msg": "Hello world"})
                )

        # Wait for a signature to ensure those transactions are committable
        time.sleep(args.sig_tx_interval * 2 / 1000)

        # Kill the primary, restore other backups
        primary.stop()
        backups[1].resume()
        backups[2].resume()
        new_primary, new_term = network.wait_for_new_primary(
            primary.node_id, timeout_multiplier=6
        )
        LOG.debug(f"New primary is {new_primary.node_id} in term {new_term}")
        assert new_primary.node_id == backups[0].node_id

        # Check that uncommitted but committable suffix is preserved
        with new_primary.client("user0") as uc:
            check_commit = infra.checker.Checker(uc)
            for tx in txs:
                check_commit(tx)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., liblogging)",
            default="liblogging",
        )

    args = infra.e2e_args.cli_args(add)
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
