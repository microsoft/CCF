# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import httpx
import sys
import random
import json
import argparse

"""
1. Run sandbox

~/CCF/build$ ../tests/sandbox/sandbox.sh --js-app-bundle ../samples/apps/basic_tv/js/
...

2. Run tvc.py

~/CCF/tests$ python3 tvc.py --target https://127.0.0.1:8000 --ca ../build/workspace/sandbox_common/service_cert.pem --writes 10

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

- Single key
- Reads
- Point them at multiple nodes
- Add new entry point instead of sandbox, with
  - Node suspend with timeout of 1.5 * checkQuorum interval
  - Node partition with timeout of 1.5 * checkQuorum interval
"""


def log(**kwargs):
    print(json.dumps(kwargs))


def tx_id(string):
    view, seqno = string.split(".")
    return int(view), int(seqno)


def run(targets, cacert, writes):
    session = httpx.Client(verify=cacert)
    for write in range(writes):
        log(action="RwTxRequestAction", type="RwTxRequest", tx=write)
        key = random.randrange(0, 10000)
        value = random.randrange(0, 10000)
        response = session.put(f"{targets[0]}/records/{key}", data=f"{value}")
        assert response.status_code == 204
        txid = response.headers["x-ms-ccf-transaction-id"]
        log(
            action="RwTxResponseAction", type="RwTxRequest", tx=write, tx_id=tx_id(txid)
        )
        status = "Pending"
        final = False
        while not final:
            response = session.get(f"{targets[0]}/tx?transaction_id={txid}")
            status = response.json()["status"]
            if status in ("Committed", "Invalid"):
                log(
                    action=f"Status{status}ResponseAction",
                    type="TxStatusReceived",
                    tx_id=tx_id(txid),
                    status=f"{status}Status",
                )
                final = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Host to connect to", action="append")
    parser.add_argument("--ca", help="CA for the server")
    parser.add_argument("--writes", type=int, help="Number of writes to perform")
    args = parser.parse_args()

    run(args.target, args.ca, args.writes)
