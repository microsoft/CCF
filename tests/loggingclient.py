# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf

import logging
import time

from iso3166 import countries

from loguru import logger as LOG


def run(args):
    hosts = ["localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        # TODO: Use check_commit for Write RPCs
        regulators = [(0, "gbr", "if amt == 99 then return true else return false end")]
        banks = [(1, "us", 99), (1, "gbr", 29), (2, "grc", 99), (2, "fr", 29)]

        for reg in regulators:
            with primary.management_client() as mc:

                with primary.user_client(format="msgpack", user_id=reg[0] + 1) as c:
                    check_commit = infra.ccf.Checker(mc)
                    check = infra.ccf.Checker()

                    check(
                        c.rpc(
                            "REG_register",
                            {
                                "country": countries.get(reg[1]).numeric,
                                "script": reg[2],
                            },
                        ),
                        result=reg[0],
                    )
                    check(
                        c.rpc("REG_get", {"id": reg[0]}),
                        result=[
                            countries.get(reg[1]).numeric.encode(),
                            reg[2].encode(),
                        ],
                    )

                    check(
                        c.rpc(
                            "BK_register", {"country": countries.get(reg[1]).numeric}
                        ),
                        error=lambda e: e is not None
                        and e["code"]
                        == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value,
                    )
                LOG.debug(f"User {reg[0]} successfully registered as regulator")

        for bank in banks:
            with primary.user_client(format="msgpack", user_id=bank[0] + 1) as c:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()

                check(
                    c.rpc("BK_register", {"country": countries.get(bank[1]).numeric}),
                    result=bank[0],
                )
                check(
                    c.rpc("BK_get", {"id": bank[0]}),
                    result=countries.get(bank[1]).numeric.encode(),
                )

                check(
                    c.rpc("REG_register", {"country": countries.get(bank[1]).numeric}),
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value,
                )
            LOG.debug(f"User {bank[0]} successfully registered as bank")

        LOG.success(
            f"{len(regulators)} regulator(s) and {len(banks)} bank(s) successfully setup"
        )

        tx_id = 0  # Tracks how many transactions have been issued
        # tracks flagged/non flagged and revealed/non revealed transactions for validation
        revealed_tx = None
        flagged_tx_ids = [0, 2]
        not_flagged_tx_ids = [1, 3]
        revealed_tx_id = 2
        non_revealed_tx_id = 3
        flagged_amt = 99
        for i, bank in enumerate(banks):
            bank_id = bank[0] + 1
            with primary.user_client(format="msgpack", user_id=bank_id) as c:

                # Destination account is the next one in the list of banks
                dst = banks[(i + 1) % len(banks)]
                amt = banks[i][2]

                src_country = countries.get(bank[1]).numeric
                check(
                    c.rpc(
                        "TX_record",
                        {
                            "dst": dst[0],
                            "amt": amt,
                            "type": 2,
                            "src_country": src_country,
                            "dst_country": countries.get(dst[1]).numeric,
                        },
                    ),
                    result=tx_id,
                )
                check(
                    c.rpc("TX_get", {"tx_id": tx_id}),
                    result=[
                        bank[0],  # user id is the identity of the sender
                        dst[0],
                        amt,
                        2,
                        countries.get(bank[1]).numeric.encode(),
                        countries.get(dst[1]).numeric.encode(),
                    ],
                )
                if amt == flagged_amt:
                    check(
                        c.rpc("FLAGGED_TX_get", {"tx_id": tx_id}),
                        result=[src_country.encode(), False],
                    )
                    if tx_id == revealed_tx_id:
                        revealed_tx = [
                            bank[0],  # user id is the identity of the sender
                            dst[0],
                            amt,
                            2,
                            countries.get(bank[1]).numeric.encode(),
                            countries.get(dst[1]).numeric.encode(),
                        ]
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
        reg = regulators[0]
        with primary.management_client() as mc:
            with primary.user_client(format="msgpack", user_id=reg[0] + 1) as c:
                check(c.rpc("REG_poll_flagged", {}), result=flagged_tx_ids)

                # get from flagged txs, try to get the flagged one that was not revealed
                check(
                    c.rpc("REG_get_revealed", {"tx_id": flagged_tx_ids[0]}),
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.INVALID_PARAMS.value,
                )
                # get from flagged txs, try to get the flagged one that was revealed
                check(
                    c.rpc("REG_get_revealed", {"tx_id": flagged_tx_ids[1]}),
                    result=revealed_tx,
                )


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
