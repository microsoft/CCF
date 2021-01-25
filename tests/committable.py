# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import time
import http
from ccf.tx_status import TxStatus

from loguru import logger as LOG


def wait_for_pending(client, view, seqno, timeout=3):
    end_time = time.time() + timeout
    while time.time() < end_time:
        r = client.get(f"/node/tx?view={view}&seqno={seqno}")
        assert (
            r.status_code == http.HTTPStatus.OK
        ), f"tx request returned HTTP status {r.status_code}"
        status = TxStatus(r.body.json()["status"])
        if status == TxStatus.Pending:
            return
        elif status == TxStatus.Invalid:
            raise RuntimeError(
                f"Transaction ID {view}.{seqno} is marked invalid and will never be committed"
            )
        elif status == TxStatus.Committed:
            raise RuntimeError(
                f"Transaction ID {view}.{seqno} is unexpectedly marked committed"
            )
        else:
            time.sleep(0.1)
    raise TimeoutError("Timed out waiting for commit")


def run(args):
    # This is deliberately 5, because the rest of the test depends on this
    # to grow a prefix and allow just enough nodes to resume to reach the
    # desired election result. Conversion to a general f isn't trivial.
    hosts = ["local://localhost"] * 5

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, backups = network.find_nodes()

        # Suspend three of the backups to prevent commit
        backups[1].suspend()
        backups[2].suspend()
        network.stop_node(backups[3])

        txs = []
        # Run some transactions that can't be committed
        with primary.client("user0") as uc:
            for i in range(3):
                txs.append(
                    uc.post("/app/log/private", {"id": 100 + i, "msg": "Hello world"})
                )

        sig_view, sig_seqno = txs[-1].view, txs[-1].seqno + 1
        with backups[0].client() as bc:
            wait_for_pending(bc, sig_view, sig_seqno)

        # Kill the primary, restore other backups
        network.stop_node(primary)
        backups[1].resume()
        backups[2].resume()
        new_primary, new_term = network.wait_for_new_primary(
            primary.node_id, timeout_multiplier=6
        )
        LOG.debug(f"New primary is {new_primary.node_id} in term {new_term}")

        # Check that uncommitted but committable suffix is preserved
        with new_primary.client("user0") as uc:
            check_commit = infra.checker.Checker(uc)
            for tx in txs:
                check_commit(tx)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    run(args)
