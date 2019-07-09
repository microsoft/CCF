# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf

import logging
import time
import csv
from iso3166 import countries
from loguru import logger as LOG
import argparse
from infra.jsonrpc import client


def run(args):
    regulator = (0, "gbr", None)
    banks = [(1, "us", 99), (1, "gbr", 29), (2, "grc", 99), (2, "fr", 29)]
    revealed = []

    reg_id = regulator[0] + 1
    with client(
        host=args.host,
        port=args.port,
        format="msgpack",
        cert="user{}_cert.pem".format(reg_id),
        key="user{}_privk.pem".format(reg_id),
        cafile="networkcert.pem",
    ) as reg_c:
        bank_id = user_id = banks[0][0] + 1
        with client(
            host=args.host,
            port=args.port,
            format="msgpack",
            cert="user{}_cert.pem".format(bank_id),
            key="user{}_privk.pem".format(bank_id),
            cafile="networkcert.pem",
        ) as c:
            while True:
                time.sleep(1)
                resp = reg_c.rpc("REG_poll_flagged", {}).to_dict()
                if "result" in resp:
                    flagged_txs = resp["result"]
                    for flagged in flagged_txs:
                        # bank reveal the transaction
                        c.rpc("TX_reveal", {"tx_id": flagged})
                        # regulator get the transaction
                        tx = reg_c.rpc("REG_get_revealed", {"tx_id": flagged}).to_dict()[
                            "result"
                        ]
                        tx["src_country"] = countries.get(
                            tx["src_country"].decode()
                        ).alpha2.lower()
                        tx["dst_country"] = countries.get(
                            tx["dst_country"].decode()
                        ).alpha2.lower()
                        revealed.append(tx)
                    LOG.info(flagged_txs)
                    LOG.info(revealed)
                    revealed = []


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Load an existing scenario file (csv)", type=str)
    parser.add_argument("--port", help="Load an existing scenario file (csv)", type=int)

    args = parser.parse_args()
    run(args)
