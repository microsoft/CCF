# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf

import logging
from time import gmtime, strftime
import csv
import random
from enum import IntEnum

from loguru import logger as LOG


class TransactionType(IntEnum):
    PAYMENT = 1
    TRANSFER = 2
    CASH_OUT = 3
    DEBIT = 4
    CASH_IN = 5


KNOWN_COUNTRIES = ["us", "gbr", "fr", "grc"]


def run(args):
    hosts = ["localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        script = "if amt == 99 then return true else return false end"
        if args.lua_script is not None:
            data = []
            with open(args.lua_script, "r") as f:
                data = f.readlines()
            script = "".join(data)

        regulator = (0, "gbr", script)
        banks = [(1, "us", 99), (1, "gbr", 29), (2, "grc", 99), (2, "fr", 29)]

        with primary.management_client() as mc:
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
        revealed_tx = None
        # [id, reg_id]
        flagged_tx_ids = [[0, regulator[0]], [2, regulator[0]]]
        revealed_tx_id = 2
        non_revealed_tx_id = 3
        flagged_amt = 99

        for i, bank in enumerate(banks):
            bank_id = bank[0] + 1
            reg_id = regulator[0]
            with primary.user_client(format="msgpack", user_id=bank_id) as c:

                # Destination account is the next one in the list of banks
                dst = banks[(i + 1) % len(banks)]
                amt = banks[i][2]

                src_country = bank[1]
                tmstamp = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
                check(
                    c.rpc(
                        "TX_record",
                        {
                            "src": bank[0],
                            "dst": dst[0],
                            "amt": amt,
                            "type": TransactionType.TRANSFER.value,
                            "timestamp": tmstamp,
                            "src_country": src_country,
                            "dst_country": dst[1],
                        },
                    ),
                    result=tx_id,
                )
                check(
                    c.rpc("TX_get", {"tx_id": tx_id}),
                    result={
                        "bank_id": bank[0],
                        "dst_country": dst[1].encode(),
                        "src": bank[0],
                        "type": TransactionType.TRANSFER.value,
                        "timestamp": tmstamp.encode(),
                        "amt": amt,
                        "src_country": bank[1].encode(),
                        "dst": dst[0],
                    },
                )
                if amt == flagged_amt:
                    check(
                        c.rpc("FLAGGED_TX_get", {"tx_id": tx_id}),
                        result=[reg_id, False, tmstamp.encode()],
                    )
                    if tx_id == revealed_tx_id:
                        revealed_tx = {
                            "amt": amt,
                            "bank_id": bank[0],
                            "dst": dst[0],
                            "dst_country": dst[1].encode(),
                            "src": bank[0],
                            "src_country": bank[1].encode(),
                            "timestamp": tmstamp.encode(),
                            "tx_id": tx_id,
                            "type": TransactionType.TRANSFER.value,
                        }
                else:
                    check(
                        c.rpc("FLAGGED_TX_get", {"tx_id": tx_id}),
                        error=lambda e: e is not None
                        and e["code"] == infra.jsonrpc.ErrorCode.INVALID_PARAMS.value,
                    )
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

            # bank reveal first transaction that was flagged
            check(c.rpc("TX_reveal", {"tx_id": revealed_tx_id}), result=True)

            # bank try to reveal non flagged tx
            check(
                c.rpc("TX_reveal", {"tx_id": non_revealed_tx_id}),
                error=lambda e: e is not None
                and e["code"] == infra.jsonrpc.ErrorCode.INVALID_PARAMS.value,
            )

        # regulator poll for transactions that are flagged
        with primary.management_client() as mc:
            with primary.user_client(format="msgpack", user_id=regulator[0] + 1) as c:
                check(c.rpc("REG_poll_flagged", {}), result=flagged_tx_ids)

                # get from flagged txs, try to get the flagged one that was not revealed
                check(
                    c.rpc("REG_get_revealed", {"tx_id": non_revealed_tx_id}),
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.INVALID_PARAMS.value,
                )
                # get from flagged txs, try to get the flagged one that was revealed
                check(
                    c.rpc("REG_get_revealed", {"tx_id": revealed_tx_id}),
                    result=revealed_tx,
                )


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--lua-script", help="Regulator checker loaded as lua script file", type=str
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
