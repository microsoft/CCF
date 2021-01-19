# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http

import infra.logging_app as app
import infra.e2e_args
import infra.network


from loguru import logger as LOG


def save_committed_ledger_files(network, args):
    txs = app.LoggingTxs()
    # Issue txs in a loop to force a signature and a new ledger chunk each time
    for _ in range(1, 10):
        txs.issue(network, 1)

    primary, _ = network.find_primary()
    LOG.error(primary.remote.ledger_path())
    LOG.warning(primary.remote.ledger_read_only_path())


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:

        args.read_only_ledger_dir = "/tmp/lalala"
        network.start_and_join(args)

        save_committed_ledger_files(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    args.initial_user_count = 1
    args.ledger_chunk_bytes = "1"  # Chunk ledger at every signature transaction
    run(args)
