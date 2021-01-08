# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        cmd = [
            "python",
            args.tutorial,
            primary.get_ledger()[1],
            network.common_dir,
        ]
        rc = infra.proc.ccall(*cmd).returncode
        assert rc == 0, f"Failed to run tutorial script: {rc}"


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--tutorial",
            help="Path to tutorial file",
            type=str,
        )

    args = infra.e2e_args.cli_args(add)
    args.package = "liblogging"
    args.nodes = ["local://127.0.0.1:8000"]
    args.initial_member_count = 1
    run(args)
