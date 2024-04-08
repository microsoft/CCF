import httpx
import sys
import random

"""
1. Run sandbox

~/CCF/build$ ../tests/sandbox/sandbox.sh --js-app-bundle ../samples/apps/basic_tv/js/
...

2. Run tvc.py

~/CCF/tests$ python3 tvc.py https://127.0.0.1:8000 ../build/workspace/sandbox_common/service_cert.pem 10

3. Things happen

5755 -> 3656 (2.127)
2.127 -> Committed
7053 -> 5225 (2.129)
2.129 -> Committed
4048 -> 4951 (2.131)
2.131 -> Committed
3403 -> 2415 (2.133)
2.133 -> Committed

TODO:

- Reads
- Request ids are awkward across clients - do we need to validate that part?
- Format to JSON to be consumed by TLA+
- Elections
- Start lots of tvcs
- Point them at multiple nodes

"""

def run(host, cacert, writes):
    session = httpx.Client(verify=cacert)
    for write in range(writes):
        key = random.randrange(0, 10000)
        value = random.randrange(0, 10000)
        response = session.put(f"{host}/records/{key}", data=f"value")
        assert response.status_code == 204
        txid = response.headers['x-ms-ccf-transaction-id']
        print(f"{key} -> {value} ({txid})")
        status = "Pending"
        final = False
        while not final:
            response = session.get(f"{host}/tx?transaction_id={txid}")
            status = response.json()['status']
            if status in ("Committed", "Invalid"):
                print(f"{txid} -> {status}")
                final = True

if __name__ == "__main__":
    host = sys.argv[1]
    cacert = sys.argv[2]
    writes = int(sys.argv[3])
    run(host, cacert, writes)