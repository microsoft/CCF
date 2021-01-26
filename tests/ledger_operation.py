# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import os
import shutil

import infra.logging_app as app
import infra.e2e_args
import infra.network
import suite.test_requirements as reqs


from loguru import logger as LOG


@reqs.description("Move committed ledger files to read-only directory")
def save_committed_ledger_files(network, args):
    txs = app.LoggingTxs()
    # Issue txs in a loop to force a signature and a new ledger chunk
    # each time. Record log messages at the same key (repeat=True) so
    # that CCF makes use of historical queries when verifying messages
    for _ in range(1, 5):
        txs.issue(network, 1, repeat=True)

    LOG.info(f"Moving committed ledger files to {args.common_read_only_ledger_dir}")
    primary, _ = network.find_primary()
    for l in os.listdir(primary.remote.ledger_path()):
        if infra.node.is_file_committed(l):
            shutil.move(
                os.path.join(primary.remote.ledger_path(), l),
                os.path.join(args.common_read_only_ledger_dir, l),
            )

    txs.verify(network)
    return network


def run(args):
    with tempfile.TemporaryDirectory() as tmp_dir:

        with infra.network.network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            pdb=args.pdb,
        ) as network:

            args.common_read_only_ledger_dir = tmp_dir
            network.start_and_join(args)

            save_committed_ledger_files(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    args.initial_user_count = 1
    args.ledger_chunk_bytes = "1"  # Chunk ledger at every signature transaction
    run(args)
