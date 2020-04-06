# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.ccf

import logging
from time import gmtime, strftime
import csv
import random
import http

from loguru import logger as LOG


class AppUser:
    def __init__(self, network, name, country, curve):
        self.name = name
        self.country = country

        primary, _ = network.find_primary()

        network.create_users([self.name], curve)
        network.consortium.add_users(primary, [self.name])

        with primary.user_client(user_id=self.name) as client:
            self.ccf_id = client.get("whoAmI").result["caller_id"]

    def __str__(self):
        return f"{self.ccf_id} ({self.name})"


def check_status(rc):
    return lambda status, _msg: status == rc.value


def run(args):
    hosts = ["localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        check = infra.checker.Checker()
        network.start_and_join(args)
        primary, others = network.find_nodes()

        script = "if tonumber(amt) > 200000 then return true else return false end"
        if args.lua_script is not None:
            data = []
            with open(args.lua_script, "r") as f:
                data = f.readlines()
            script = "".join(data)

        manager = AppUser(network, "manager", "GB", args.participants_curve)
        regulator = AppUser(network, "auditor", "GB", args.participants_curve)
        banks = [
            AppUser(network, f"bank{country}", country, args.participants_curve)
            for country in ("US", "GB", "GR", "FR")
        ]
        transactions = []

        with open(args.datafile, newline="") as f:
            datafile = csv.DictReader(f)
            for i, row in enumerate(datafile):
                # read first 10 lines
                if i > 10:
                    break
                json_tx = {
                    "src": row["origin"],
                    "dst": row["destination"],
                    "amt": row["amount"],
                    "type": row["type"],
                    "timestamp": strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime()),
                    "src_country": row["src_country"],
                    "dst_country": row["dst_country"],
                }
                transactions.append(json_tx)

        # Manager is granted special privileges by members, which is later read by app to enforce access restrictions
        proposal = network.consortium.get_any_active_member().propose(
            primary,
            f"""
            return Calls:call(
                "set_user_data",
                {{
                    user_id = {manager.ccf_id},
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
        network.consortium.vote_using_majority(primary, proposal)

        # Check permissions are enforced
        with primary.user_client(user_id=regulator.name) as c:
            check(
                c.rpc("REG_register"), error=check_status(http.HTTPStatus.FORBIDDEN),
            )
            check(
                c.rpc("BK_register"), error=check_status(http.HTTPStatus.FORBIDDEN),
            )

        with primary.user_client(user_id=banks[0].name) as c:
            check(
                c.rpc("REG_register"), error=check_status(http.HTTPStatus.FORBIDDEN),
            )
            check(
                c.rpc("BK_register"), error=check_status(http.HTTPStatus.FORBIDDEN),
            )

        # As permissioned manager, register regulator and banks
        with primary.node_client() as mc:
            check_commit = infra.checker.Checker(mc)

            with primary.user_client(user_id=manager.name) as c:
                check(
                    c.rpc(
                        "REG_register",
                        {
                            "regulator_id": regulator.ccf_id,
                            "country": regulator.country,
                            "script": script,
                        },
                    ),
                    result=regulator.ccf_id,
                )
                check(
                    c.rpc("REG_get", {"id": regulator.ccf_id}),
                    result=[regulator.country, script],
                )

                check(
                    c.rpc(
                        "BK_register",
                        {"bank_id": regulator.ccf_id, "country": regulator.country},
                    ),
                    error=check_status(http.HTTPStatus.BAD_REQUEST),
                )
                LOG.debug(f"User {regulator} successfully registered as regulator")

                for bank in banks:
                    check(
                        c.rpc(
                            "BK_register",
                            {"bank_id": bank.ccf_id, "country": bank.country},
                        ),
                        result=bank.ccf_id,
                    )
                    check(c.rpc("BK_get", {"id": bank.ccf_id}), result=bank.country)

                    check(
                        c.rpc(
                            "REG_register",
                            {"regulator_id": bank.ccf_id, "country": bank.country},
                        ),
                        error=check_status(http.HTTPStatus.BAD_REQUEST),
                    )
                    LOG.debug(f"User {bank} successfully registered as bank")

        LOG.success(f"{1} regulator and {len(banks)} bank(s) successfully setup")

        tx_id = 0  # Tracks how many transactions have been issued
        # tracks flagged/non flagged and revealed/non revealed transactions for validation
        flagged_txs = {}
        revealed_tx_ids = []
        flagged_ids = []
        non_flagged_ids = []
        flagged_amt = 200000

        for i, bank in enumerate(banks):
            with primary.user_client(user_id=bank.name) as c:
                # Destination account is the next one in the list of banks
                for transaction in transactions:
                    print(transaction)
                    amount = transaction["amt"]

                    check(c.rpc("TX_record", transaction), result=tx_id)
                    check(
                        c.rpc("TX_get", {"tx_id": tx_id}),
                        result={
                            "amt": amount,
                            "bank_id": bank.ccf_id,
                            "dst": transaction["dst"],
                            "dst_country": transaction["dst_country"],
                            "src": transaction["src"],
                            "src_country": transaction["src_country"],
                            "timestamp": transaction["timestamp"],
                            "type": transaction["type"],
                        },
                    )
                    if float(amount) > flagged_amt:
                        check(
                            c.rpc("FLAGGED_TX_get", {"tx_id": tx_id}),
                            result=[regulator.ccf_id, False, transaction["timestamp"]],
                        )
                        flagged_tx = {
                            "amt": amount,
                            "bank_id": bank.ccf_id,
                            "dst": transaction["dst"],
                            "dst_country": transaction["dst_country"],
                            "src": transaction["src"],
                            "src_country": transaction["src_country"],
                            "timestamp": transaction["timestamp"],
                            "tx_id": tx_id,
                            "type": transaction["type"],
                        }
                        flagged_ids.append(tx_id)
                        flagged_txs[tx_id] = flagged_tx
                    else:
                        check(
                            c.rpc("FLAGGED_TX_get", {"tx_id": tx_id}),
                            error=check_status(http.HTTPStatus.BAD_REQUEST),
                        )
                        non_flagged_ids.append(tx_id)

                    tx_id += 1
        LOG.success(f"{tx_id} transactions have been successfully issued")

        # bank that issued first flagged transaction
        with primary.user_client(user_id=bank.name) as c:
            # try to poll flagged but fail as you are not a regulator
            check(
                c.rpc("REG_poll_flagged"),
                error=check_status(http.HTTPStatus.FORBIDDEN),
            )

            # bank reveal some transactions that were flagged
            for i, tx_id in enumerate(flagged_ids):
                if i % 2 == 0:
                    check(c.rpc("TX_reveal", {"tx_id": tx_id}), result=True)
                    revealed_tx_ids.append(tx_id)

            # bank try to reveal non flagged txs
            for tx_id in non_flagged_ids:
                check(
                    c.rpc("TX_reveal", {"tx_id": tx_id}),
                    error=check_status(http.HTTPStatus.BAD_REQUEST),
                )

        # regulator poll for transactions that are flagged
        with primary.node_client() as mc:
            with primary.user_client(user_id=regulator.name) as c:
                # assert that the flagged txs that we poll for are correct
                resp = c.rpc("REG_poll_flagged")
                poll_flagged_ids = []
                for poll_flagged in resp.result:
                    # poll flagged is a list [tx_id, regulator_id]
                    poll_flagged_ids.append(poll_flagged[0])
                poll_flagged_ids.sort()
                assert poll_flagged_ids == flagged_ids

                for tx_id in flagged_ids:
                    # get from flagged txs, try to get the flagged one that was not revealed
                    if tx_id not in revealed_tx_ids:
                        check(
                            c.rpc("REG_get_revealed", {"tx_id": tx_id}),
                            error=check_status(http.HTTPStatus.BAD_REQUEST),
                        )

                # get from flagged txs, try to get the flagged ones that were revealed
                for tx_id in revealed_tx_ids:
                    check(
                        c.rpc("REG_get_revealed", {"tx_id": tx_id}),
                        result=flagged_txs[tx_id],
                    )


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--lua-script", help="Regulator checker loaded as lua script file", type=str
        )
        parser.add_argument(
            "--datafile", help="Load an existing scenario file (csv)", type=str
        )

    args = infra.e2e_args.cli_args(add)
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
