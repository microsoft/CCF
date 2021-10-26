# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import ccf.commit
import http
from e2e_logging import get_all_entries
import cimetrics.upload
import threading
import time
import statistics

from loguru import logger as LOG


def steady_submit(primary, id, shutdown_event, active_event):
    durations = []

    is_active = False

    def print_stats():
        LOG.warning(
            f"Submitted {len(durations)} requests ({'ACTIVE' if is_active else 'INACTIVE'})"
        )
        LOG.warning(f"Duration:")
        LOG.warning(f"  mean={statistics.mean(durations):.03f}s")
        LOG.warning(f"  std dev={statistics.pstdev(durations):.03f}s")
        LOG.warning(f"  min={min(durations):.03f}s")
        LOG.warning(f"  max={max(durations):.03f}s")
        percentiles = statistics.quantiles(durations, n=100, method="inclusive")
        # TODO: What am I missing here? Why the off-by-one?
        LOG.warning(
            f"  50%={percentiles[49]:.03f}s, 90%={percentiles[89]:.03f}s, 95%={percentiles[94]:.03f}s, 99%={percentiles[98]:.03f}s"
        )

    with primary.client("user0") as c:
        i = 0
        last_print = time.time()
        while not shutdown_event.is_set():
            if not is_active and active_event.is_set():
                print_stats()
                is_active = True
                durations.clear()
            start = time.time()
            r = c.post(
                "/app/log/private",
                {
                    "id": id,
                    "msg": f"Message {i}",
                },
                log_capture=[],
            )
            end = time.time()
            assert r.status_code == http.HTTPStatus.OK
            i += 1
            durations.append(end - start)
            if end - last_print > 10:
                last_print = time.time()
                print_stats()
            time.sleep(0.01)

    print_stats()


def test_historical_query_range(network, args):
    first_seqno = None
    last_seqno = None

    id_single = 1
    id_a = 2
    id_b = 3
    id_c = 4

    id_pattern = [id_a, id_a, id_a, id_b, id_b, id_c]

    n_entries = 20000

    jwt_issuer = infra.jwt_issuer.JwtIssuer()
    jwt_issuer.register(network)
    jwt = jwt_issuer.issue_jwt()

    primary, _ = network.find_primary()

    id_submit = 100
    shutdown_event = threading.Event()
    active_event = threading.Event()
    submitter_thread = threading.Thread(
        target=steady_submit, args=(primary, id_submit, shutdown_event, active_event)
    )
    submitter_thread.start()

    with primary.client("user0") as c:
        # Submit many transactions, overwriting the same IDs
        msgs = {}

        def id_for(i):
            # id_single is used for a single entry, in the middle of the range
            if i == n_entries // 2:
                return id_single
            else:
                return id_pattern[i % len(id_pattern)]

        LOG.info(f"Submitting {n_entries} entries")
        for i in range(n_entries):
            idx = id_for(i)

            msg = f"Unique message {i}"
            r = c.post(
                "/app/log/private",
                {
                    "id": idx,
                    "msg": msg,
                },
                # Print logs for every 1000th submission, to show progress
                log_capture=None if i % 1000 == 0 else [],
            )
            assert r.status_code == http.HTTPStatus.OK

            seqno = r.seqno
            view = r.view
            msgs[seqno] = msg

            if first_seqno is None:
                first_seqno = seqno

            last_seqno = seqno

        ccf.commit.wait_for_commit(c, seqno=last_seqno, view=view, timeout=3)

    LOG.info(
        f"Total ledger contains {last_seqno} entries, of which we expect our transactions to be spread over a range of ~{last_seqno - first_seqno} transactions"
    )

    # Total fetch time depends on number of entries. We expect to be much faster than this, but
    # to set a safe timeout allow for a rate as low as 100 fetches per second
    timeout = n_entries / 100

    # Ensure all nodes have reached committed state before querying a backup for historical state
    network.wait_for_all_nodes_to_commit(primary=primary)

    active_event.set()

    entries = {}
    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])
    with node.client(common_headers={"authorization": f"Bearer {jwt}"}) as c:
        entries[id_a], duration_a = get_all_entries(c, id_a, timeout=timeout)
        entries[id_b], duration_b = get_all_entries(c, id_b, timeout=timeout)
        entries[id_c], duration_c = get_all_entries(c, id_c, timeout=timeout)

    shutdown_event.set()
    submitter_thread.join()

    id_a_fetch_rate = len(entries[id_a]) / duration_a
    id_b_fetch_rate = len(entries[id_b]) / duration_b
    id_c_fetch_rate = len(entries[id_c]) / duration_c

    average_fetch_rate = (id_a_fetch_rate + id_b_fetch_rate + id_c_fetch_rate) / 3

    with cimetrics.upload.metrics(complete=False) as metrics:
        upload_name = "Historical query (/s)^"
        LOG.debug(f"Uploading metric: {upload_name} = {average_fetch_rate}")
        metrics.put(upload_name, average_fetch_rate)

    # NB: The similar test in e2e_logging checks correctness, so we make no duplicate
    # assertions here

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        network = test_historical_query_range(network, args)


if __name__ == "__main__":

    def add(parser):
        pass

    args = infra.e2e_args.cli_args(add=add)
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_member_count = 1
    args.sig_ms_interval = 1000  # Set to cchost default value
    run(args)
