# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        for node in network.nodes:
            node.curl = True
        network.start_and_join(args)
        primary, _ = network.find_primary()

        cmd = [
            "python",
            args.client_tutorial,
            network.common_dir,
        ]
        rc = infra.proc.ccall(*cmd).returncode
        assert rc == 0, f"Failed to run tutorial script: {rc}"

    _, committed_ledger_dirs = primary.get_ledger()
    cmd = [
        "python",
        args.ledger_tutorial,
        committed_ledger_dirs[0],
    ]
    rc = infra.proc.ccall(*cmd).returncode
    assert rc == 0, f"Failed to run tutorial script: {rc}"
