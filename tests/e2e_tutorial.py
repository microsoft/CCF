# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import infra.clients


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        for node in network.nodes:
            node.client_impl = infra.clients.CurlClient
        network.start_and_open(args)
        primary, _ = network.find_primary()

    uncommitted_ledger_dir, committed_ledger_dirs = list(primary.get_ledger())
    cmd = [
        "python",
        args.ledger_tutorial,
        *committed_ledger_dirs,
        uncommitted_ledger_dir,
    ]
    rc = infra.proc.ccall(*cmd).returncode
    assert rc == 0, f"Failed to run tutorial script: {rc}"
