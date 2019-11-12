# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import os
import logging
from time import gmtime, strftime, perf_counter
import csv
import random
from loguru import logger as LOG
import json
import subprocess


def run(args):
    hosts = ["localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, others = network.find_nodes()

        if args.run_poll:
            with open("revealed.log", "a+") as stdout:
                subprocess.Popen(
                    [
                        "python3",
                        f"{os.path.realpath(os.path.dirname(__file__))}/poll.py",
                        f"--host={primary.host}",
                        f"--port={primary.rpc_port}",
                    ],
                    stdout=stdout,
                )
        else:
            LOG.warning("")
            LOG.warning(
                "================= Network setup complete, you can run the below command to poll the service. "
                + "Press enter to continue ================="
            )
            LOG.warning("")
            LOG.warning(
                f"python3 {os.path.realpath(os.path.dirname(__file__))}/poll.py --host={primary.host} --port={primary.rpc_port}"
            )
            LOG.warning("")
            input("")

        data = []
        with open(args.lua_script, "r") as f:
            data = f.readlines()
        script = "".join(data)

        regulators = [
            (0, "GB", script, "FCA"),
            (
                1,
                "FR",
                "if tonumber(amt) > 15000 then return true else return false end",
                "SEC",
            ),
        ]
        banks = [(2, "US", 99), (3, "GB", 29), (4, "GR", 99), (5, "FR", 29)]

        for regulator in regulators:
            with primary.user_client(format="msgpack", user_id=regulator[0] + 1) as c:
                check = infra.checker.Checker()

                check(
                    c.rpc(
                        "REG_register",
                        {
                            "country": regulator[1],
                            "script": regulator[2],
                            "name": regulator[3],
                        },
                    ),
                    result=regulator[0],
                )
                check(
                    c.rpc("REG_get", {"id": regulator[0]}),
                    result=[
                        regulator[1].encode(),
                        regulator[2].encode(),
                        regulator[3].encode(),
                    ],
                )

            LOG.debug(f"User {regulator[0]} successfully registered as regulator")

        for bank in banks:
            with primary.user_client(format="msgpack", user_id=bank[0] + 1) as c:
                check = infra.checker.Checker()

                check(c.rpc("BK_register", {"country": bank[1]}), result=bank[0])
                check(c.rpc("BK_get", {"id": bank[0]}), result=bank[1].encode())
            LOG.debug(f"User {bank[0]} successfully registered as bank")

        LOG.success(
            f"{len(regulators)} regulator and {len(banks)} bank(s) successfully setup"
        )

        tx_id = 0  # Tracks how many transactions have been issued
        bank_id = banks[0][0] + 1
        LOG.info(f"Loading scenario file as bank {bank_id}")

        with primary.user_client(format="msgpack", user_id=regulator[0] + 1) as reg_c:

            with primary.user_client(
                format="msgpack", user_id=bank_id, log_file=None
            ) as c:
                with open(args.datafile, newline="") as f:
                    start_time = perf_counter()
                    datafile = csv.DictReader(f)
                    for row in datafile:
                        json_tx = {
                            "src": row["origin"],
                            "dst": row["destination"],
                            "amt": row["amount"],
                            "type": row["type"],
                            "timestamp": strftime(
                                "%a, %d %b %Y %H:%M:%S +0000", gmtime()
                            ),
                            "src_country": row["src_country"],
                            "dst_country": row["dst_country"],
                        }

                        check(c.rpc("TX_record", json_tx), result=tx_id)
                        print(json.dumps(json_tx))
                        tx_id += 1

                        if tx_id % 1000 == 0:
                            elapsed_time = perf_counter() - start_time
                            LOG.info(
                                f"1000 transactions took {elapsed_time}: tx_id: {tx_id}"
                            )
                            start_time = perf_counter()
                LOG.success("Scenario file successfully loaded")

        LOG.warning("Data loading completed, press Enter to shutdown...")
        input()


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--datafile",
            help="Load an existing scenario file (csv)",
            type=str,
            required=True,
        )
        parser.add_argument(
            "--lua-script",
            help="Regulator checker loaded as lua script file",
            type=str,
            required=True,
        )
        parser.add_argument("--run-poll", help="Run the poller", action="store_true")

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
