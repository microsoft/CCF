# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf

import logging
import time
import csv
from loguru import logger as LOG
import argparse
from infra.jsonrpc import client

import json


def convert(data):
    if isinstance(data, bytes):
        return data.decode("ascii")
    elif isinstance(data, dict):
        return dict(map(convert, data.items()))
    elif isinstance(data, tuple):
        return map(convert, data)
    else:
        return data


def run(args):
    revealed = []

    with client(
        host=args.host,
        port=args.port,
        format="msgpack",
        cert="user{}_cert.pem".format(args.regulator_name),
        key="user{}_privk.pem".format(args.regulator_name),
        cafile="networkcert.pem",
    ) as reg_c:
        with client(
            host=args.host,
            port=args.port,
            format="msgpack",
            cert="user{}_cert.pem".format(args.bank_name),
            key="user{}_privk.pem".format(args.bank_name),
            cafile="networkcert.pem",
        ) as c:
            while True:
                time.sleep(1)
                resp = reg_c.rpc("REG_poll_flagged", {}).to_dict()

                if "result" in resp:
                    flagged_txs = resp["result"]

                    for flagged in flagged_txs:
                        # bank reveal the transaction
                        c.rpc("TX_reveal", {"tx_id": flagged[0]})
                        # regulator get the transaction
                        tx_resp = reg_c.rpc(
                            "REG_get_revealed", {"tx_id": flagged[0]}
                        ).to_dict()
                        if "result" in tx_resp:
                            tx = tx_resp["result"]

                            # Convert transaction for json serialisation
                            tx["reg_name"] = flagged[2]
                            stringified_tx = {k: convert(v) for k, v in tx.items()}
                            print(json.dumps(stringified_tx))

                            tx["src_country"] = tx["src_country"].decode()
                            tx["dst_country"] = tx["dst_country"].decode()
                            revealed.append(tx)
                    LOG.info(flagged_txs)
                    LOG.info(revealed)
                    revealed = []


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Hostname that service is running on", type=str)
    parser.add_argument("--port", help="Port that service is running on", type=int)
    parser.add_argument(
        "--regulator-name",
        help="Name of cert/key to use for regulator connection",
        type=str,
    )
    parser.add_argument(
        "--bank-name", help="Name of cert/key to user for bank connection", type=str
    )

    args = parser.parse_args()
    run(args)
