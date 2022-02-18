# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import infra.commit
import http
from e2e_logging import get_all_entries
import cimetrics.upload
from concurrent import futures

from loguru import logger as LOG


def submit_range(primary, id_pattern, start, end, format_width):
    LOG.info(f"Starting submission of {start:>{format_width}} to {end:>{format_width}}")

    def id_for(i):
        return id_pattern[i % len(id_pattern)]

    first_seqno = None
    last_seqno = None
    view = None
    seqno = None
    with primary.client("user0") as c:
        for i in range(start, end):
            idx = id_for(i)

            msg = f"Unique message {i}"
            r = c.post(
                "/app/log/public",
                {
                    "id": idx,
                    "msg": msg,
                },
                # Print logs for every 1000th submission, to show progress
                log_capture=None if i % 1000 == 500 else [],
            )
            assert r.status_code == http.HTTPStatus.OK

            seqno = r.seqno
            view = r.view

            if first_seqno is None:
                first_seqno = seqno

            last_seqno = seqno

    return (first_seqno, view, last_seqno)


def test_historical_query_range(network, args):
    id_a = 2
    id_b = 3
    id_c = 4

    # NB: Because we submit from multiple concurrent threads, the actual pattern
    # on the ledger will not match this but will be interleaved. But the final
    # ratio of transactions will match this
    id_pattern = [id_a, id_a, id_a, id_b, id_b, id_c]

    n_entries = 30000
    format_width = len(str(n_entries))

    jwt_issuer = infra.jwt_issuer.JwtIssuer()
    jwt_issuer.register(network)
    jwt = jwt_issuer.issue_jwt()

    primary, _ = network.find_primary()

    # Submit many transactions, overwriting the same IDs
    LOG.info(f"Submitting {n_entries} entries")

    submissions_per_job = 1000
    assigned = 0

    fs = []
    with futures.ThreadPoolExecutor() as executor:
        while assigned < n_entries:
            start = assigned
            end = min(n_entries, assigned + submissions_per_job)
            fs.append(
                executor.submit(
                    submit_range, primary, id_pattern, start, end, format_width
                )
            )
            assigned = end

    results = [f.result() for f in fs]
    first_seqno = min(res[0] for res in results)
    view = max(res[1] for res in results)
    last_seqno = max(res[2] for res in results)

    with primary.client("user0") as c:
        infra.commit.wait_for_commit(c, seqno=last_seqno, view=view, timeout=3)

    LOG.info(
        f"Total ledger contains {last_seqno} entries, of which we expect our transactions to be spread over a range of ~{last_seqno - first_seqno} transactions"
    )

    # Total fetch time depends on number of entries. We expect to be much faster than this, but
    # to set a safe timeout allow for a rate as low as 100 fetches per second
    timeout = n_entries / 100

    # Ensure all nodes have reached committed state before querying a backup for historical state
    network.wait_for_all_nodes_to_commit(primary=primary)

    entries = {}
    node = network.find_node_by_role(role=infra.network.NodeRole.BACKUP, log_capture=[])
    with node.client(common_headers={"authorization": f"Bearer {jwt}"}) as c:
        # Index is currently built lazily to avoid impacting other perf tests using the same app
        # So pre-fetch to ensure index is fully constructed
        get_all_entries(c, id_a, timeout=timeout)
        get_all_entries(c, id_b, timeout=timeout)
        get_all_entries(c, id_c, timeout=timeout)

        entries[id_a], duration_a = get_all_entries(c, id_a, timeout=timeout)
        entries[id_b], duration_b = get_all_entries(c, id_b, timeout=timeout)
        entries[id_c], duration_c = get_all_entries(c, id_c, timeout=timeout)

        c.get("/node/memory")

    id_a_fetch_rate = len(entries[id_a]) / duration_a
    id_b_fetch_rate = len(entries[id_b]) / duration_b
    id_c_fetch_rate = len(entries[id_c]) / duration_c

    average_fetch_rate = (id_a_fetch_rate + id_b_fetch_rate + id_c_fetch_rate) / 3

    with cimetrics.upload.metrics(complete=False) as metrics:
        upload_name = "hist_sgx_cft^"
        LOG.debug(f"Uploading metric: {upload_name} = {average_fetch_rate}")
        metrics.put(upload_name, average_fetch_rate)

    # NB: The similar test in e2e_logging checks correctness, so we make no duplicate
    # assertions here

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

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
