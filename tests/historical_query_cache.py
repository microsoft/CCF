# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.clients
import infra.network
import http
import time
import random

from loguru import logger as LOG


def large_message(idx):
    """
    ~1kb transaction
    """
    return "x" * 1024 + str(idx)


def submit_log_entry(primary, idx):
    with primary.client("user0") as c:
        msg = large_message(idx)
        r = c.post(
            "/app/log/private",
            {
                "id": idx,
                "msg": msg,
            },
            log_capture=None,
        )
        assert r.status_code == http.HTTPStatus.OK
        c.wait_for_commit(r)
        return f"{r.view}.{r.seqno}"


def fetch_historical(client, idx, tx_id, timeout=10):
    end_time = time.time() + timeout
    while time.time() < end_time:
        r = client.get(
            f"/app/log/private/historical?id={idx}",
            headers={infra.clients.CCF_TX_ID_HEADER: tx_id},
        )
        if r.status_code == http.HTTPStatus.ACCEPTED:
            time.sleep(0.1)
            continue
        if r.status_code == http.HTTPStatus.NOT_FOUND:
            err = r.body.json().get("error", {})
            if err.get("code") == "TransactionPendingOrUnknown":
                time.sleep(0.1)
                continue
        return r
    raise TimeoutError(f"Historical query did not complete for tx_id={tx_id}")


def get_and_verify_entry(client, idx, tx_id, timeout=10, msg_idx=None):
    if msg_idx is None:
        msg_idx = idx
    r = fetch_historical(client, idx, tx_id, timeout=timeout)
    if r.status_code == http.HTTPStatus.OK:
        assert r.body.json()["msg"] == large_message(msg_idx)
        return
    raise ValueError(
        f"Unexpected status code from historical query: {r.status_code} - {r.body}"
    )


def test_historical_query_cache_overflow(network, args):
    """Write repeatedly to the same index, and after each write fetch the
    corresponding historical value at that transaction."""

    primary, _ = network.find_primary()
    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])

    target_id = 42
    # 20kb limit, roughly 1kb*50 = 50kb of TXs.
    max_entries = 50
    tx_ids = []

    with node.client("user0") as historical_client:
        for i in range(1, max_entries + 1):
            msg = large_message(i)
            with primary.client("user0") as c:
                r = c.post(
                    "/app/log/private",
                    {
                        "id": target_id,
                        "msg": msg,
                    },
                    log_capture=None,
                )
                assert r.status_code == http.HTTPStatus.OK
                c.wait_for_commit(r)
                tx_id = f"{r.view}.{r.seqno}"
                tx_ids.append((i, tx_id))

            get_and_verify_entry(historical_client, target_id, tx_id, msg_idx=i)

    return network, tx_ids


def fetch_sparse(client, target_id, seqnos, timeout=10):
    seqnos_s = ",".join(str(s) for s in seqnos)
    path = f"/app/log/private/historical/sparse?id={target_id}&seqnos={seqnos_s}"
    LOG.info(f"Sparse query: seqnos={seqnos_s}")
    end_time = time.time() + timeout
    while time.time() < end_time:
        r = client.get(path)
        if r.status_code == http.HTTPStatus.OK:
            return r
        elif r.status_code == http.HTTPStatus.ACCEPTED:
            time.sleep(0.1)
            continue
        else:
            raise ValueError(
                f"Unexpected status from historical/sparse: {r.status_code} - {r.body}"
            )
    raise TimeoutError("Historical sparse query did not complete")


def test_historical_query_sparse_consecutive(network, args, tx_ids):
    """10 attempts of 5 random consecutive seqnos via /historical/sparse,
    never including the last seqno."""

    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])
    target_id = 42

    all_seqnos = sorted(int(tx_id.split(".")[1]) for _, tx_id in tx_ids)
    # Exclude the last seqno
    seqnos_pool = all_seqnos[:-1]

    with node.client("user0") as c:
        for i in range(10):
            start_idx = random.randint(0, len(seqnos_pool) - 5)
            seqnos = seqnos_pool[start_idx : start_idx + 5]
            LOG.info(f"Sparse consecutive {i + 1}/10")
            fetch_sparse(c, target_id, seqnos)

    return network


def test_historical_query_sparse_random(network, args, tx_ids):
    """100 attempts of 3 randomly chosen seqnos via /historical/sparse."""

    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])
    target_id = 42

    all_seqnos = [int(tx_id.split(".")[1]) for _, tx_id in tx_ids]

    with node.client("user0") as c:
        for i in range(100):
            seqnos = random.sample(all_seqnos, 3)
            LOG.info(f"Sparse random {i + 1}/100")
            fetch_sparse(c, target_id, seqnos)

    return network


def test_historical_query_batched(network, args):
    """Submit transactions in batches so that consecutive user txs appear
    in the ledger without interleaved signatures, then fetch each one."""

    primary, _ = network.find_primary()
    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])

    target_id = 42
    max_entries = 50
    batch_size = 3
    tx_ids = []

    with node.client("user0") as historical_client:
        for batch_start in range(1, max_entries + 1, batch_size):
            batch_end = min(batch_start + batch_size, max_entries + 1)
            batch = []
            with primary.client("user0") as c:
                for i in range(batch_start, batch_end):
                    msg = large_message(i)
                    r = c.post(
                        "/app/log/private",
                        {
                            "id": target_id,
                            "msg": msg,
                        },
                        log_capture=None,
                    )
                    assert r.status_code == http.HTTPStatus.OK
                    batch.append((i, f"{r.view}.{r.seqno}"))
                # Only wait for commit on the last tx in the batch
                c.wait_for_commit(r)

            tx_ids.extend(batch)
            for msg_idx, tx_id in batch:
                get_and_verify_entry(
                    historical_client, target_id, tx_id, msg_idx=msg_idx
                )

    return network, tx_ids


def test_historical_query_all_seqnos(network, args, first_seqno):
    """Iterate over every seqno from first_seqno up to the last committed,
    fetching each one.  Txs that don't contain the target key return 204."""

    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])
    target_id = 42

    with node.client("user0") as c:
        r = c.get("/node/commit")
        assert r.status_code == http.HTTPStatus.OK
        committed = r.body.json()["transaction_id"]
        view, last_seqno = committed.split(".")
        view = int(view)
        last_seqno = int(last_seqno)

    LOG.info(f"All-seqnos test: iterating {first_seqno}..{last_seqno}")

    with node.client("user0") as historical_client:
        for seqno in range(first_seqno, last_seqno + 1):
            tx_id = f"{view}.{seqno}"
            r = fetch_historical(historical_client, target_id, tx_id)
            assert r.status_code in (
                http.HTTPStatus.OK,
                http.HTTPStatus.NO_CONTENT,
                http.HTTPStatus.NOT_FOUND,
            ), f"Unexpected status {r.status_code} for {tx_id}: {r.body}"

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network, tx_ids = test_historical_query_cache_overflow(network, args)
        network, batched_tx_ids = test_historical_query_batched(network, args)
        all_tx_ids = tx_ids + batched_tx_ids
        network = test_historical_query_sparse_consecutive(network, args, all_tx_ids)
        network = test_historical_query_sparse_random(network, args, all_tx_ids)
        network = test_historical_query_all_seqnos(
            network, args, first_seqno=int(tx_ids[0][1].split(".")[1])
        )


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/logging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.initial_member_count = 1
    args.sig_ms_interval = 1000  # Set to cchost default value
    args.historical_cache_soft_limit = "20KB"

    run(args)
