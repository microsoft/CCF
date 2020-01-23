# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import getpass
import time
import logging
import multiprocessing
import shutil
import subprocess
from random import seed
import infra.ccf
import infra.path
import infra.proc
import infra.notification
import infra.net
import e2e_args

from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, (backup,) = network.find_nodes()

        with primary.node_client() as mc:
            check_commit = infra.checker.Checker(mc)
            check = infra.checker.Checker()
            r = mc.rpc("getQuotes", {})
            quotes = r.result["quotes"]
            assert len(quotes) == len(hosts)
            primary_quote = quotes[0]
            assert primary_quote["node_id"] == 0
            mrenclave = primary_quote["mrenclave"]

            oed = subprocess.run(
                [args.oesign, "dump", "-e", infra.path.build_lib_path(args.package)],
                capture_output=True,
                check=True,
            )
            lines = [
                line
                for line in oed.stdout.decode().split(os.linesep)
                if line.startswith("mrenclave=")
            ]
            expected_mrenclave = lines[0].strip().split("=")[1]
            assert mrenclave == expected_mrenclave, (mrenclave, expected_mrenclave)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--oesign", help="Path oesign binary", type=str, required=True
        )

    args = e2e_args.cli_args(add=add)

    if args.enclave_type != "debug":
        LOG.error("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "liblogging"
    run(args)
