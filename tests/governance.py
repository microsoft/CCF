# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import subprocess
import infra.ccf
import infra.path
import infra.proc
import infra.notification
import infra.net
import infra.e2e_args

from loguru import logger as LOG


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_nodes()

        with primary.client() as mc:
            oed = subprocess.run(
                [
                    args.oesign,
                    "dump",
                    "-e",
                    infra.path.build_lib_path(args.package, args.enclave_type),
                ],
                capture_output=True,
                check=True,
            )
            lines = [
                line
                for line in oed.stdout.decode().split(os.linesep)
                if line.startswith("mrenclave=")
            ]
            expected_mrenclave = lines[0].strip().split("=")[1]

            r = mc.get("/node/quote")
            quotes = r.result["quotes"]
            assert len(quotes) == 1
            primary_quote = quotes[0]
            assert primary_quote["node_id"] == 0
            primary_mrenclave = primary_quote["mrenclave"]
            assert primary_mrenclave == expected_mrenclave, (
                primary_mrenclave,
                expected_mrenclave,
            )

            r = mc.get("/node/quotes")
            quotes = r.result["quotes"]
            assert len(quotes) == len(hosts)
            for quote in quotes:
                mrenclave = quote["mrenclave"]
                assert mrenclave == expected_mrenclave, (mrenclave, expected_mrenclave)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--oesign", help="Path oesign binary", type=str, required=True
        )

    args = infra.e2e_args.cli_args(add=add)

    if args.enclave_type == "virtual":
        LOG.warning("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "liblogging"
    run(args)
