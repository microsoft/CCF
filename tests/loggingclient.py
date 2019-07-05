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
        primary, others = network.start_and_join(args)

        with primary.user_client() as c:
            with primary.management_client() as mc:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()

                check(c.rpc("REG_record", {"country": 100}), result=True)
                check(c.rpc("REG_get", {"id": 1}), result=100)

                check(c.rpc("REG_record", {"country": 202}), result=True)
                check(c.rpc("REG_get", {"id": 1}), result=202)

                check(c.rpc("TX_record", {"id": 0, "src": 100, "dst": 50, "amt": 99}), result=True)
                check(c.rpc("TX_get", {"id": 0}), result=[100, 50, 99])


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
