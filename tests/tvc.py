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

~/CCF/tests$ python3 tvc.py -t https://127.0.0.1:8000 -t https://127.0.0.1:8001 --ca ../build/workspace/sandbox_common/service_cert.pem

3. Trace is printed to stdout

{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 0}
{"action": "RwTxResponseAction", "type": "RwTxRequest", "tx": 0, "tx_id": [2, 197]}
{"action": "StatusCommittedResponseAction", "type": "TxStatusReceived", "tx_id": [2, 197], "status": "CommittedStatus"}
{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 1}
{"action": "RwTxResponseAction", "type": "RwTxRequest", "tx": 1, "tx_id": [2, 199]}
{"action": "StatusCommittedResponseAction", "type": "TxStatusReceived", "tx_id": [2, 199], "status": "CommittedStatus"}
{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 2}
{"action": "RwTxResponseAction", "type": "RwTxRequest", "tx": 2, "tx_id": [2, 201]}
"""

KEY = "0"
VALUE = "value"


def log(**kwargs):
    print(json.dumps(kwargs))


def tx_id(string):
    view, seqno = string.split(".")
    return int(view), int(seqno)


def run(targets, cacert):
    session = httpx.Client(verify=cacert)
    tx = 0
    while True:
        target = random.choice(targets)
        # Always start with a write, to avoid having to handle missing values
        txtype = random.choice(["Ro", "Rw"]) if tx else "Rw"
        if txtype == "Ro":
            response = session.get(f"{target}/records/{KEY}")
            if response.status_code == 200:
                log(action=f"{txtype}TxRequestAction", type=f"{txtype}TxRequest", tx=tx)
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
            if response.status_code == 204:
                log(action=f"{txtype}TxRequestAction", type=f"{txtype}TxRequest", tx=tx)
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
                    if response.status_code == 200:
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
                        # if our target has gone away or does not know who is primary, try another one
                        target = random.choice(targets)
        else:
            raise ValueError(f"Unknown Tx type: {txtype}")
        tx += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run --txs steps, a ~50% mix of reads and writes, randomly distributed across --target nodes"
    )
    parser.add_argument("-t", "--target", help="Host to connect to", action="append")
    parser.add_argument("--ca", help="CA for the server")
    args = parser.parse_args()

    try:
        run(args.target, args.ca)
    except KeyboardInterrupt:
        pass
