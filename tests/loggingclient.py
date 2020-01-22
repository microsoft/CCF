# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc

import logging
import time

from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, term = network.find_primary()

        infra.proc.ccall(
            "./logging_client",
            f"--rpc-address={primary.host}:{primary.rpc_port}",
            "--ca=networkcert.pem",
            "--cert=user1_cert.pem",
            "--privk=user1_privk.pem",
        ).check_returncode()


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = args.app_script and "libluageneric" or "liblogging"
    run(args)
