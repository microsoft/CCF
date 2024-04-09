# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import httpx
import random
import json
import argparse

"""
1. Run sandbox

~/CCF/build$ ../tests/sandbox/sandbox.sh --js-app-bundle ../samples/apps/basic_tv/js/ -n local://127.0.0.1:8000 -n local://127.0.0.1:8001
...

2. Run tvc.py

~/CCF/tests$ python3 tvc.py -t https://127.0.0.1:8000 -t https://127.0.0.1:8001 --ca ../build/workspace/sandbox_common/service_cert.pem --txs 10

3. Things happen

{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 0}
{"action": "RwTxResponseAction", "type": "RwTxRequest", "tx": 0, "tx_id": [2, 197]}
{"action": "StatusCommittedResponseAction", "type": "TxStatusReceived", "tx_id": [2, 197], "status": "CommittedStatus"}
{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 1}
{"action": "RwTxResponseAction", "type": "RwTxRequest", "tx": 1, "tx_id": [2, 199]}
{"action": "StatusCommittedResponseAction", "type": "TxStatusReceived", "tx_id": [2, 199], "status": "CommittedStatus"}
{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 2}
{"action": "RwTxResponseAction", "type": "RwTxRequest", "tx": 2, "tx_id": [2, 201]}

TODO:

- Add new entry point instead of sandbox, with
  - Node suspend with timeout of 1.5 * checkQuorum interval
  - Node partition with timeout of 1.5 * checkQuorum interval
"""

KEY = "0"
VALUE = "value"


def log(**kwargs):
    print(json.dumps(kwargs))


def tx_id(string):
    view, seqno = string.split(".")
    return int(view), int(seqno)


def run(targets, cacert, txs):
    session = httpx.Client(verify=cacert)
    for tx in range(txs):
        target = random.choice(targets)
        # Always start with a write, to avoid having to handle missing values
        txtype = random.choice(["Ro", "Rw"]) if tx else "Rw"
        log(action=f"{txtype}TxRequestAction", type=f"{txtype}TxRequest", tx=tx)
        if txtype == "Ro":
            response = session.get(f"{target}/records/{KEY}")
            assert response.status_code == 200
            assert response.text == VALUE
            txid = response.headers["x-ms-ccf-transaction-id"]
            log(
                action="RoTxResponseAction",
                type="RoTxRequest",
                tx=tx,
                tx_id=tx_id(txid),
            )
        elif txtype == "Rw":
            response = session.put(f"{target}/records/{KEY}", data=VALUE)
            assert response.status_code == 204
            txid = response.headers["x-ms-ccf-transaction-id"]
            log(
                action="RwTxResponseAction",
                type="RwTxRequest",
                tx=tx,
                tx_id=tx_id(txid),
            )
            status = "Pending"
            final = False
            while not final:
                response = session.get(f"{target}/tx?transaction_id={txid}")
                status = response.json()["status"]
                if status in ("Committed", "Invalid"):
                    log(
                        action=f"Status{status}ResponseAction",
                        type="TxStatusReceived",
                        tx_id=tx_id(txid),
                        status=f"{status}Status",
                    )
                    final = True
        else:
            raise ValueError(f"Unknown Tx type: {txtype}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run --txs steps, a ~50% mix of reads and writes, randomly distributed across --target nodes"
    )
    parser.add_argument("-t", "--target", help="Host to connect to", action="append")
    parser.add_argument("--ca", help="CA for the server")
    parser.add_argument("--txs", type=int, help="Number of transactions")
    args = parser.parse_args()

    run(args.target, args.ca, args.txs)
