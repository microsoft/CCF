# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
"Basic Blocking Locust" benchmark.

Measures the throughput of blocking writes (PUT /records/blocking/{key}), which
only return once the transaction has committed. This covers the same ground as
the piccolo-driven "Basic Blocking" benchmark, but drives load with locust
instead, so that the client count can be ramped up and the workload described
in Python rather than in a pre-generated parquet file.

The load itself is defined in infra/basicperf_locustfile.py. This script owns
the network, runs locust against it, and converts locust's statistics into
bencher metrics.
"""

import argparse
import csv
import os
import subprocess

import infra.bencher
import infra.e2e_args
import infra.interfaces
import infra.key_space
import infra.network
import infra.proc
from loguru import logger as LOG

LOCUST_FILE_NAME = "basicperf_locustfile.py"

# Prefix for the CSV files locust writes. Locust appends _stats.csv,
# _failures.csv, and so on.
CSV_PREFIX = "locust"

# Name of the row holding totals across all request types in locust's stats CSV.
AGGREGATED_ROW_NAME = "Aggregated"


def locust_file_path() -> str:
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "infra", LOCUST_FILE_NAME
    )


def run_locust(args, network, primary) -> dict:
    """Run locust to completion against the given node, and return the
    aggregated statistics it recorded."""
    csv_prefix = os.path.join(network.common_dir, CSV_PREFIX)

    session_auth = primary.session_auth("user0")["session_auth"]
    host = "https://" + infra.interfaces.make_address(
        primary.get_public_rpc_host(), primary.get_public_rpc_port()
    )

    cmd = ["locust"]
    cmd += ["--headless"]
    cmd += ["--locustfile", locust_file_path()]
    cmd += ["--host", host]

    # Client authentication
    cmd += ["--ca", primary.session_ca()["ca"]]
    cmd += ["--cert", session_auth.cert]
    cmd += ["--key", session_auth.key]

    cmd += ["--key-space-size", f"{args.key_space_size}"]

    # Load profile
    cmd += ["--users", f"{args.users}"]
    cmd += ["--spawn-rate", f"{args.spawn_rate}"]
    cmd += ["--run-time", f"{args.run_time_s}s"]

    # A single locust process cannot saturate the service, because it drives
    # all of its users from one thread. Fork enough workers to keep the client
    # from being the bottleneck.
    cmd += ["--processes", f"{args.locust_processes}"]

    # Discard everything recorded while users were still being spawned, so the
    # reported numbers describe steady state at the full user count.
    cmd += ["--reset-stats"]

    cmd += ["--csv", csv_prefix]

    LOG.info(f"Starting locust: {' '.join(cmd)}")
    # Locust exits non-zero if any request failed, which should fail the test.
    subprocess.run(cmd, check=True)

    return read_aggregated_stats(f"{csv_prefix}_stats.csv")


def read_aggregated_stats(stats_path: str) -> dict:
    with open(stats_path, "r") as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        if row["Name"] == AGGREGATED_ROW_NAME:
            return row

    raise RuntimeError(f"No {AGGREGATED_ROW_NAME} row found in {stats_path}")


def run(args):
    LOG.info(f"Starting nodes on {args.nodes}")
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_primary()

        infra.key_space.create_and_fill_key_space(args.key_space_size, primary)

        stats = run_locust(args, network, primary)

        request_count = int(stats["Request Count"])
        failure_count = int(stats["Failure Count"])
        throughput = float(stats["Requests/s"])
        # Locust reports response times in milliseconds.
        median_latency_ms = float(stats["Median Response Time"])
        p99_latency_ms = float(stats["99%"])
        min_latency_ms = float(stats["Min Response Time"])

        LOG.info(
            f"{request_count} requests ({failure_count} failures) "
            f"=> {throughput:.1f} tx/s"
        )
        LOG.info(
            f"Latency: min={min_latency_ms:.1f}ms p50={median_latency_ms:.1f}ms "
            f"p99={p99_latency_ms:.1f}ms"
        )

        if request_count == 0:
            raise RuntimeError("Locust recorded no requests")

        # Locust should already have exited non-zero, but do not report a
        # throughput figure built from failed requests under any circumstances.
        if failure_count != 0:
            raise RuntimeError(
                f"Locust recorded {failure_count} failures out of {request_count} requests"
            )

        mem = infra.proc.get_proc_memory_stats(primary.remote.remote.proc.pid)

        network.stop_all_nodes()

        bf = infra.bencher.Bencher()
        bf.set(args.perf_label, infra.bencher.Throughput(round(throughput, 1)))
        bf.set(
            args.perf_label,
            infra.bencher.Latency(
                value=median_latency_ms,
                high_value=p99_latency_ms,
                low_value=min_latency_ms,
            ),
        )
        if mem is not None:
            bf.set_memory(args.perf_label, mem)


def cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--users",
        help="Number of concurrent locust users, each sending one blocking write at a time",
        type=int,
        default=128,
    )
    parser.add_argument(
        "--spawn-rate",
        help="Number of users to start per second",
        type=int,
        default=128,
    )
    parser.add_argument(
        "--run-time-s",
        help="Duration of the load, in seconds, excluding the time taken to spawn users",
        type=int,
        default=20,
    )
    parser.add_argument(
        "--locust-processes",
        help="Number of locust worker processes to fork",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--key-space-size",
        help="Size of the key space which is pre-populated and written to",
        type=int,
        default=1000,
    )
    return infra.e2e_args.cli_args(
        parser=parser, accept_unknown=False, ledger_chunk_bytes_override="5MB"
    )


if __name__ == "__main__":
    args = cli_args()
    # A single node is enough: the benchmark measures the time taken to commit
    # on the primary, and additional nodes only add replication cost.
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    run(args)
