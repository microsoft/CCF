# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import httpx
import httpcore
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
{"action": "RwTxResponseAction", "type": "RwTxResponse", "tx": 0, "tx_id": [2, 197]}
{"action": "StatusCommittedResponseAction", "type": "TxStatusReceived", "tx_id": [2, 197], "status": "CommittedStatus"}
{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 1}
{"action": "RwTxResponseAction", "type": "RwTxResponse", "tx": 1, "tx_id": [2, 199]}
{"action": "StatusCommittedResponseAction", "type": "TxStatusReceived", "tx_id": [2, 199], "status": "CommittedStatus"}
{"action": "RwTxRequestAction", "type": "RwTxRequest", "tx": 2}
{"action": "RwTxResponseAction", "type": "RwTxResponse", "tx": 2, "tx_id": [2, 201]}
"""

KEY = "0"
VALUE = "value"


def log(**kwargs):
    print(json.dumps(kwargs))


def tx_id(string):
    view, seqno = string.split(".")
    return int(view), int(seqno)


def retry(call, urls, **kwargs):
    """
    Retry http calls if they time out (process suspended during execution),
    or return a non-200/204 code (unable to forward because primary unknown).
    Pick a random URL, to avoid getting stuck too long on a suspended node.
    """
    response = None
    while response is None or response.status_code not in (200, 204):
        try:
            url = random.choice(urls)
            response = call(url, **kwargs)
        except (httpx.ReadTimeout, httpx.ConnectTimeout):
            pass
    return response


def run(targets, cacert):
    session = httpx.Client(verify=cacert)
    tx = -1
    key_urls = [f"{target}/records/{KEY}" for target in targets]
    while True:
        tx += 1
        # Always start with a write, to avoid having to handle missing values
        txtype = random.choice(["Ro", "Rw"]) if tx else "Rw"
        if txtype == "Ro":
            response = retry(session.get, key_urls)
            log(action=f"{txtype}TxRequestAction", type=f"{txtype}TxRequest", tx=tx)
            assert response.text == VALUE
            txid = response.headers["x-ms-ccf-transaction-id"]
            log(
                action="RoTxResponseAction",
                type="RoTxResponse",
                tx=tx,
                tx_id=tx_id(txid),
            )
        elif txtype == "Rw":
            response = retry(session.put, key_urls, data=VALUE)
            log(action=f"{txtype}TxRequestAction", type=f"{txtype}TxRequest", tx=tx)
            txid = response.headers["x-ms-ccf-transaction-id"]
            log(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx_id=tx_id(txid),
                tx=tx,
            )
            log(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=tx,
                tx_id=tx_id(txid),
            )
            done = False
            while not done:
                tx_urls = [f"{target}/tx?transaction_id={txid}" for target in targets]
                response = retry(session.get, tx_urls)
                status = response.json()["status"]
                if status in ("Committed", "Invalid"):
                    log(
                        action=f"Status{status}ResponseAction",
                        type="TxStatusReceived",
                        tx_id=tx_id(txid),
                        status=f"{status}Status",
                    )
                    done = True
        else:
            raise ValueError(f"Unknown Tx type: {txtype}")


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
