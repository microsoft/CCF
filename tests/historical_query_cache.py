# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.clients
import infra.network
import infra.proc
import infra.commit
import http
import infra.jwt_issuer
import time
import infra.bencher

from loguru import logger as LOG


def message(idx):
    """
    4k+ transaction
    """
    return "x" * (4 * 1024) + str(idx)


def submit_log_entry(primary, idx):
    with primary.client("user0") as c:
        msg = message(idx)
        r = c.post(
            "/app/log/public",
            {
                "id": idx,
                "msg": msg,
            },
            log_capture=None,
        )
        assert r.status_code == http.HTTPStatus.OK
        return (r.view, r.seqno)


def get_and_verify_entry(client, idx):
    start_time = time.time()
    end_time = start_time + 10
    entries = []
    path = f"/app/log/public/historical/range?id={idx}"
    while time.time() < end_time:
        r = client.get(path, headers={})
        if r.status_code == http.HTTPStatus.OK:
            j_body = r.body.json()
            entries += j_body["entries"]
            if "@nextLink" in j_body:
                path = j_body["@nextLink"]
                continue
            else:
                # No @nextLink means we've reached end of range
                assert entries[0]["msg"] == message(idx)
                return
        elif r.status_code == http.HTTPStatus.ACCEPTED:
            # Ignore retry-after header, retry soon
            time.sleep(0.1)
            continue
        else:
            raise ValueError(f"""
                Unexpected status code from historical range query: {r.status_code}

                {r.body}
                """)

    raise TimeoutError("Historical range not available")


def test_historical_query_stress_cache(network, args):
    """This test loads the historical cache good enough so it's force to
    lru_shrink. We go over the range twice and make sure we're able to load new
    entries after they get evicted from the cache."""

    jwt_issuer = infra.jwt_issuer.JwtIssuer()
    jwt_issuer.register(network)
    jwt = jwt_issuer.issue_jwt()

    primary, _ = network.find_primary()

    start = 1
    end = 100
    last_seqno = None
    last_view = None
    for i in range(start, end + 1):
        last_view, last_seqno = submit_log_entry(primary, i)

    with primary.client("user0") as c:
        infra.commit.wait_for_commit(c, seqno=last_seqno, view=last_view, timeout=10)

    network.wait_for_all_nodes_to_commit(primary=primary)
    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])

    with node.client(common_headers={"authorization": f"Bearer {jwt}"}) as c:
        for cycle in range(0, 2):
            LOG.info(f"Polling [{start}:{end + 1}] range. Attempt=[{cycle}]")
            for idx in range(start, end + 1):
                get_and_verify_entry(c, idx)

    return network


def test_historical_query_same_index(network, args, max_entries=1000):
    """Write repeatedly to the same index, and after each write fetch the
    corresponding historical value at that transaction."""

    primary, _ = network.find_primary()
    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])

    target_id = 42

    def get_and_verify_entry_at_tx(client, idx, tx_id, expected_msg, timeout=10):
        end_time = time.time() + timeout
        while time.time() < end_time:
            r = client.get(
                f"/app/log/private/historical?id={idx}",
                headers={infra.clients.CCF_TX_ID_HEADER: tx_id},
            )

            if r.status_code == http.HTTPStatus.OK:
                assert r.body.json()["msg"] == expected_msg
                return

            if r.status_code == http.HTTPStatus.ACCEPTED:
                time.sleep(0.1)
                continue

            if r.status_code == http.HTTPStatus.NOT_FOUND:
                err = r.body.json().get("error", {})
                if err.get("code") == "TransactionPendingOrUnknown":
                    time.sleep(0.1)
                    continue

            raise ValueError(
                f"Unexpected status code from historical query: {r.status_code} - {r.body}"
            )

        raise TimeoutError(
            f"Historical query did not complete for tx_id={tx_id}, id={idx}"
        )

    with node.client("user0") as historical_client:
        for i in range(1, max_entries + 1):
            msg = message(i)
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

            get_and_verify_entry_at_tx(historical_client, target_id, tx_id, msg)

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_historical_query_same_index(
            network,
            args,
            max_entries=args.historical_query_max_entries,
        )


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--historical-query-max-entries",
            type=int,
            default=1000,
            help="Number of sequential writes/historical reads at the same key",
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "samples/apps/logging/logging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.initial_member_count = 1
    args.sig_ms_interval = 1000  # Set to cchost default value

    args.historical_cache_soft_limit = "8KB"

    run(args)
