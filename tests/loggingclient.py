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
        regulators = [(0, "gbr")]
        banks = [(1, "us"), (2, "fr")]

        for reg in regulators:
            with primary.management_client() as mc:

                with primary.user_client(format="msgpack", user_id=reg[0] + 1) as c:
                    check_commit = infra.ccf.Checker(mc)
                    check = infra.ccf.Checker()

                    check(
                        c.rpc(
                            "REG_register", {"country": countries.get(reg[1]).numeric}
                        ),
                        result=reg[0],
                    )
                    check(
                        c.rpc("REG_get", {"id": reg[0]}),
                        result=countries.get(reg[1]).numeric.encode(),
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

        tx_id = 0 # Tracks how many transactions have been issued

        for i, bank in enumerate(banks):
            with primary.user_client(format="msgpack", user_id=bank[0] + 1) as c:

                # Destination account is the next one in the list of banks
                dst = banks[(i + 1) % len(banks)]
                check(
                    c.rpc(
                        "TX_record",
                        {
                            "dst": dst[0],
                            "amt": 99,
                            "type": 2,
                            "src_country": countries.get(bank[1]).numeric,
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
                        99,
                        2,
                        countries.get(bank[1]).numeric.encode(),
                        countries.get(dst[1]).numeric.encode(),
                    ],
                )
                tx_id += 1
        LOG.success(f"{tx_id} transactions have been successfully issued")


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
