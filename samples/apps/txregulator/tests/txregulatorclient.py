# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf

import logging
from time import gmtime, strftime
import csv
import random

from loguru import logger as LOG


def run(args):
    hosts = ["localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, others = network.find_nodes()

        script = "if tonumber(amt) > 200000 then return true else return false end"
        if args.lua_script is not None:
            data = []
            with open(args.lua_script, "r") as f:
                data = f.readlines()
            script = "".join(data)

        regulator = (0, "GB", script)
        banks = [(1, "US", 99), (1, "GB", 29), (2, "GR", 99), (2, "FR", 29)]
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

        with primary.node_client() as mc:
            with primary.user_client(format="msgpack", user_id=regulator[0] + 1) as c:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()

                check(
                    c.rpc(
                        "REG_register",
                        {"country": regulator[1], "script": regulator[2]},
                    ),
                    result=regulator[0],
                )
                check(
                    c.rpc("REG_get", {"id": regulator[0]}),
                    result=[regulator[1].encode(), regulator[2].encode()],
                )

                check(
                    c.rpc("BK_register", {"country": regulator[1]}),
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value,
                )
            LOG.debug(f"User {regulator[0]} successfully registered as regulator")

        for bank in banks:
            with primary.user_client(format="msgpack", user_id=bank[0] + 1) as c:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()

                check(c.rpc("BK_register", {"country": bank[1]}), result=bank[0])
                check(c.rpc("BK_get", {"id": bank[0]}), result=bank[1].encode())

                check(
                    c.rpc("REG_register", {"country": bank[1]}),
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value,
                )
            LOG.debug(f"User {bank[0]} successfully registered as bank")

        LOG.success(f"{1} regulator and {len(banks)} bank(s) successfully setup")

        tx_id = 0  # Tracks how many transactions have been issued
        # tracks flagged/non flagged and revealed/non revealed transactions for validation
        flagged_txs = {}
        revealed_tx_ids = []
        flagged_ids = []
        non_flagged_ids = []
        flagged_amt = 200000

        for i, bank in enumerate(banks):
            bank_id = bank[0] + 1
            reg_id = regulator[0]
            with primary.user_client(format="msgpack", user_id=bank_id) as c:
                # Destination account is the next one in the list of banks
                for transaction in transactions:
                    print(transaction)
                    amount = transaction["amt"]

                    check(c.rpc("TX_record", transaction), result=tx_id)
                    check(
                        c.rpc("TX_get", {"tx_id": tx_id}),
                        result={
                            "amt": amount.encode(),
                            "bank_id": bank[0],
                            "dst": transaction["dst"].encode(),
                            "dst_country": transaction["dst_country"].encode(),
                            "src": transaction["src"].encode(),
                            "src_country": transaction["src_country"].encode(),
                            "timestamp": transaction["timestamp"].encode(),
                            "type": transaction["type"].encode(),
                        },
                    )
                    if float(amount) > flagged_amt:
                        check(
                            c.rpc("FLAGGED_TX_get", {"tx_id": tx_id}),
                            result=[reg_id, False, transaction["timestamp"].encode()],
                        )
                        flagged_tx = {
                            "amt": amount.encode(),
                            "bank_id": bank[0],
                            "dst": transaction["dst"].encode(),
                            "dst_country": transaction["dst_country"].encode(),
                            "src": transaction["src"].encode(),
                            "src_country": transaction["src_country"].encode(),
                            "timestamp": transaction["timestamp"].encode(),
                            "tx_id": tx_id,
                            "type": transaction["type"].encode(),
                        }
                        flagged_ids.append(tx_id)
                        flagged_txs[tx_id] = flagged_tx
                    else:
                        check(
                            c.rpc("FLAGGED_TX_get", {"tx_id": tx_id}),
                            error=lambda e: e is not None
                            and e["code"]
                            == infra.jsonrpc.ErrorCode.INVALID_PARAMS.value,
                        )
                        non_flagged_ids.append(tx_id)

                    tx_id += 1
        LOG.success(f"{tx_id} transactions have been successfully issued")

        # bank that issued first flagged transaction
        with primary.user_client(format="msgpack", user_id=bank[0] + 1) as c:
            # try to poll flagged but fail as you are not a regulator
            check(
                c.rpc("REG_poll_flagged", {}),
                error=lambda e: e is not None
                and e["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value,
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
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.INVALID_PARAMS.value,
                )

        # regulator poll for transactions that are flagged
        with primary.node_client() as mc:
            with primary.user_client(format="msgpack", user_id=regulator[0] + 1) as c:
                # assert that the flagged txs that we poll for are correct
                resp = c.rpc("REG_poll_flagged", {})
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
                            error=lambda e: e is not None
                            and e["code"]
                            == infra.jsonrpc.ErrorCode.INVALID_PARAMS.value,
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

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
