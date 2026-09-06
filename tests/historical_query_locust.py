# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Locust benchmark for public historical range queries."""

import argparse
import collections
import http
import time
from concurrent import futures

import infra.commit
import infra.e2e_args
import infra.jwt_issuer
import infra.locust_benchmark
import infra.network
from loguru import logger as LOG

LOCUST_FILE_NAME = "historical_query_locustfile.py"
QUERY_STATISTICS_NAME = "Historical range query"
DEFAULT_ENTRY_COUNT = 30000
DEFAULT_TIMEOUT_S = 10
SUBMISSIONS_PER_JOB = 1000
RECORD_ID_PATTERN = (2, 2, 2, 3, 3, 4)


def submit_range(primary, start, end, format_width):
    LOG.info(f"Starting submission of {start:>{format_width}} to {end:>{format_width}}")

    first_seqno = None
    last_seqno = None
    view = None
    with primary.client("user0") as client:
        for i in range(start, end):
            record_id = RECORD_ID_PATTERN[i % len(RECORD_ID_PATTERN)]
            response = client.post(
                "/app/log/public",
                {
                    "id": record_id,
                    "msg": f"Unique message {i}",
                },
                log_capture=None if i % 1000 == 500 else [],
            )
            if response.status_code != http.HTTPStatus.OK:
                raise RuntimeError(
                    f"Setup write returned unexpected status {response.status_code}"
                )

            if first_seqno is None:
                first_seqno = response.seqno
            last_seqno = response.seqno
            view = response.view

    return first_seqno, view, last_seqno


def populate_ledger(primary, entry_count):
    LOG.info(f"Submitting {entry_count} entries")
    format_width = len(str(entry_count))
    jobs = []
    with futures.ThreadPoolExecutor() as executor:
        for start in range(0, entry_count, SUBMISSIONS_PER_JOB):
            end = min(entry_count, start + SUBMISSIONS_PER_JOB)
            jobs.append(
                executor.submit(submit_range, primary, start, end, format_width)
            )

    results = [job.result() for job in jobs]
    first_seqno = min(result[0] for result in results)
    _, last_view, last_seqno = max(results, key=lambda result: result[2])

    with primary.client("user0") as client:
        infra.commit.wait_for_commit(
            client, seqno=last_seqno, view=last_view, timeout=3
        )

    LOG.info(f"Submitted entries from seqno {first_seqno} to {last_seqno}")


def fetch_all_entries(client, record_id, timeout):
    path = f"/app/log/public/historical/range?id={record_id}"
    end_time = time.monotonic() + timeout
    entry_count = 0

    while time.monotonic() < end_time:
        response = client.get(path, log_capture=[])
        if response.status_code == http.HTTPStatus.OK:
            body = response.body.json()
            entry_count += len(body["entries"])
            path = body.get("@nextLink")
            if path is None:
                return entry_count
        elif response.status_code == http.HTTPStatus.ACCEPTED:
            time.sleep(0.1)
        else:
            raise RuntimeError(
                "Historical range query returned unexpected status "
                f"{response.status_code}: {response.body}"
            )

    raise TimeoutError(
        f"Historical range for record {record_id} was not available after {timeout}s"
    )


def prepare_workload(args, network, primary) -> infra.locust_benchmark.Workload:
    jwt_issuer = infra.jwt_issuer.JwtIssuer()
    jwt_issuer.register(network)
    jwt = jwt_issuer.issue_jwt()

    populate_ledger(primary, args.entry_count)
    network.wait_for_all_nodes_to_commit(primary=primary)

    target = network.find_node_by_role(
        role=infra.network.NodeRole.BACKUP, log_capture=[]
    )
    target.remote.remote.shutdown_timeout *= 10

    record_counts = collections.Counter(
        RECORD_ID_PATTERN[i % len(RECORD_ID_PATTERN)] for i in range(args.entry_count)
    )
    timeout = max(DEFAULT_TIMEOUT_S, args.entry_count / 100)
    with target.client(
        common_headers=infra.jwt_issuer.make_bearer_header(jwt)
    ) as client:
        for record_id, expected_count in record_counts.items():
            actual_count = fetch_all_entries(client, record_id, timeout)
            if actual_count != expected_count:
                raise RuntimeError(
                    f"Historical range for record {record_id} returned "
                    f"{actual_count} entries, expected {expected_count}"
                )

    workload_arguments = [
        "--query-statistics-name",
        QUERY_STATISTICS_NAME,
    ]
    for record_id, entry_count in record_counts.items():
        workload_arguments.extend(["--record", str(record_id), str(entry_count)])

    return infra.locust_benchmark.Workload(
        locust_file_name=LOCUST_FILE_NAME,
        arguments=tuple(workload_arguments),
        environment={infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE: jwt},
        statistics_name=QUERY_STATISTICS_NAME,
        response_length_as_throughput_units=True,
        throughput_unit="entries",
        target_node=target,
    )


def cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    infra.locust_benchmark.add_cli_arguments(parser)
    parser.add_argument(
        "--entry-count",
        help="Number of public records written before querying historical state",
        type=infra.locust_benchmark.positive_int,
        default=DEFAULT_ENTRY_COUNT,
    )
    return infra.e2e_args.cli_args(parser=parser, accept_unknown=False)


if __name__ == "__main__":
    args = cli_args()
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_member_count = 1
    infra.locust_benchmark.run(args, prepare_workload)
