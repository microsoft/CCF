# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from time import time, sleep
import infra.e2e_args
import infra.network
import infra.node
import infra.logging_app as app
import infra.checker
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
import http

from loguru import logger as LOG


def bench(
    primary,
    msg: bytes,
    num_signatures=10,
    defensive=False,
    retry_timeout=10,
    public_key=None,
):
    time_before = time()
    session_ids = []
    LOG.info(f"Submitting {num_signatures} signing requests...")
    msg_bytes_string = base64.b64encode(msg).decode("ascii")
    for _ in range(num_signatures):
        timeout_before = time()
        while time() < timeout_before + retry_timeout:
            with primary.client(timeout=60) as c:
                res = c.post(
                    "/node/splitid/sign",
                    {"message": msg_bytes_string, "defensive": defensive, "app_id": 0},
                    # log_capture=[],
                    timeout=60,
                )
                if res.status_code == http.HTTPStatus.OK.value:
                    session_ids.append(res.body.json()["session_id"])
                    break
                elif res.status_code == http.HTTPStatus.BAD_REQUEST.value:
                    sleep(0.1)

    signatures = []
    timeout_before = time()
    LOG.info(f"Collecting {num_signatures} signing responses...")
    while time() < timeout_before + retry_timeout and session_ids:
        have_result = []
        for session_id in session_ids:
            with primary.client(timeout=60) as c:
                res = c.post(
                    "/node/splitid/get-signature",
                    {"session_id": session_id},
                    # log_capture=[],
                    timeout=60,
                )
                if res.status_code != http.HTTPStatus.NOT_FOUND.value:
                    sig = res.body.json()["signature"]
                    have_result.append(session_id)
                    signatures.append(sig)
        for session_id in have_result:
            session_ids.remove(session_id)
        have_result.clear()

    if session_ids:
        raise RuntimeError("Signatures not produced within timeout")

    elapsed = time() - time_before
    LOG.info(f"# signatures: {num_signatures}")
    LOG.info(f"signing time: {elapsed:.2f} sec")
    LOG.info(f"time/signature: {elapsed/num_signatures:.2f} sec")
    LOG.info(f"{num_signatures/elapsed:.2f} signatures/sec")

    if public_key:
        LOG.info(f"Verifying {len(signatures)} signatures...")
        pk = load_pem_public_key(public_key.encode("ascii"))
        alg = ec.ECDSA(hashes.SHA256())
        for sig in signatures:
            sig = base64.b64decode(sig)
            pk.verify(sig, msg, alg)

    return signatures


def wait_for_identity(primary, retry_timeout):
    # Note: After the initial identity has been sampled, the get-identity endpoint will report errors while resharing sessions are going on.
    have_identity = False
    public_key = ""
    with primary.client(timeout=60) as c:
        timeout_before = time()
        while time() < timeout_before + retry_timeout:
            res = c.post("/node/splitid/get-identity", timeout=60)
            if (
                res.status_code == http.HTTPStatus.NOT_FOUND.value
                or res.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE.value
            ):
                sleep(1)
            elif res.status_code == http.HTTPStatus.OK:
                have_identity = True
                public_key = res.body.json()["pem"]
                break
            else:
                break
    if not have_identity:
        raise RuntimeError("split identity not established in time")
    return public_key


def run(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        retry_timeout = 120
        defensive = False

        msg = "themessage".encode("ascii")

        # Wait until the split identity is available
        public_key = wait_for_identity(primary, retry_timeout)

        bench(
            primary,
            msg,
            num_signatures=10,
            defensive=defensive,
            retry_timeout=retry_timeout,
            public_key=public_key,
        )

        # trigger resharing by adding a node
        new_node = network.create_node("local://localhost")
        args.timeout = 60
        network.join_node(new_node, args.package, args, from_snapshot=False)
        network.trust_node(new_node, args)
        with new_node.client() as c:
            s = c.get("/node/state")
            assert s.body.json()["node_id"] == new_node.node_id
            assert (
                s.body.json()["startup_seqno"] == 0
            ), "Node started without snapshot but reports startup seqno != 0"
        assert new_node

        with primary.client() as c:
            timeout_before = time()
            while time() < timeout_before + retry_timeout:
                s = c.get("/node/consensus")
                rj = s.body.json()
                rjd = rj["details"]
                LOG.info(f"current consensus details: {rjd}")
                if len(rj["details"]["configs"]) > 1:
                    LOG.info("reconfiguration still in progress")
                    sleep(1.0)
                else:
                    cfg = rj["details"]["configs"][0]
                    if new_node.node_id in rj["details"]["configs"][0]["nodes"]:
                        LOG.info(f"active config: {cfg}")
                        break
                    else:
                        LOG.info(f"configuration does not contain new node yet: {cfg}")
                        sleep(1.0)

        # Wait until resharing is done
        public_key2 = wait_for_identity(primary, retry_timeout)
        assert public_key == public_key2

        bench(
            primary,
            msg,
            num_signatures=10,
            defensive=defensive,
            retry_timeout=retry_timeout,
            public_key=public_key,
        )


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    # args.max_message_size = 26 # Some messages may become large
    args.consensus = "bft"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    # args.bft_view_change_timeout_ms=20000
    # args.nodes = ["local://localhost"] * 4

    run(args)
