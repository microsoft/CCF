# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.ccf
import os
import logging
from time import gmtime, strftime, perf_counter
import csv
import random
from loguru import logger as LOG
import json
import subprocess


class AppUser:
    def __init__(self, network, name, country):
        self.name = name
        self.country = country

        primary, _ = network.find_primary()

        network.create_users([self.name])
        network.consortium.add_users(primary, [self.name])

        with primary.user_client(user_id=self.name) as client:
            self.ccf_id = client.get("whoAmI").result["caller_id"]

    def __str__(self):
        return f"{self.ccf_id} ({self.name})"


def run(args):
    hosts = ["localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, others = network.find_nodes()

        regulators = [AppUser(network, "FCA", "GB"), AppUser(network, "SEC", "FR")]
        banks = [
            AppUser(network, f"bank{country}", country)
            for country in ("US", "GB", "GR", "FR")
        ]

        # Give regulators permissions to register regulators and banks
        for regulator in regulators:
            proposal_result, error = network.consortium.propose(
                0,
                primary,
                f"""
                return Calls:call(
                    "set_user_data",
                    {{
                        user_id = {regulator.ccf_id},
                        user_data = {{
                            privileges = {{
                                REGISTER_REGULATORS = true,
                                REGISTER_BANKS = true,
                            }}
                        }}
                    }}
                )
                """,
            )
            network.consortium.vote_using_majority(primary, proposal_result["id"])

        if args.run_poll:
            with open("revealed.log", "a+") as stdout:
                subprocess.Popen(
                    [
                        "python3",
                        f"{os.path.realpath(os.path.dirname(__file__))}/poll.py",
                        f"--host={primary.host}",
                        f"--port={primary.rpc_port}",
                        f"--regulator-name={regulators[0].name}",
                        f"--bank-name={banks[0].name}",
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

        scripts = {}
        scripts["FCA"] = "".join(data)
        scripts[
            "SEC"
        ] = "if tonumber(amt) > 15000 then return true else return false end"

        for regulator in regulators:
            with primary.user_client(format="msgpack", user_id=regulator.name) as c:
                check = infra.checker.Checker()

                check(
                    c.rpc(
                        "REG_register",
                        {
                            "regulator_id": regulator.ccf_id,
                            "country": regulator.country,
                            "script": scripts[regulator.name],
                            "name": regulator.name,
                        },
                    ),
                    result=regulator.ccf_id,
                )
                check(
                    c.rpc("REG_get", {"id": regulator.ccf_id}),
                    result=[
                        regulator.country,
                        scripts[regulator.name],
                        regulator.name,
                    ],
                )

            LOG.debug(f"User {regulator} successfully registered as regulator")

        with primary.user_client(format="msgpack", user_id=regulators[0].name) as c:
            for bank in banks:
                check = infra.checker.Checker()

                check(
                    c.rpc(
                        "BK_register", {"bank_id": bank.ccf_id, "country": bank.country}
                    ),
                    result=bank.ccf_id,
                )
                check(c.rpc("BK_get", {"id": bank.ccf_id}), result=bank.country)
                LOG.debug(f"User {bank} successfully registered as bank")

        LOG.success(
            f"{len(regulators)} regulator and {len(banks)} bank(s) successfully setup"
        )

        tx_id = 0  # Tracks how many transactions have been issued
        LOG.info(f"Loading scenario file as bank {banks[0].ccf_id} ({banks[0].name})")

        with primary.user_client(format="msgpack", user_id=regulators[0].name) as reg_c:
            with primary.user_client(
                format="msgpack", user_id=banks[0].name, log_file=None
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

    args = infra.e2e_args.cli_args(add)
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
