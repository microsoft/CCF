# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
"Basic Blocking Locust" benchmark.

Measures the throughput of blocking writes (PUT /records/blocking/{key}), which
only return once the transaction has committed. Locust lets the client count be
ramped up and the workload be described in Python rather than in a pre-generated
parquet file.

The load itself is defined in infra/basicperf_locustfile.py. This script owns
the network, runs locust against it, and converts locust's statistics into
bencher metrics.
"""

import argparse
import csv
import math
import os
import subprocess

import infra.bencher
import infra.e2e_args
import infra.interfaces
import infra.key_space
import infra.net
import infra.network
import infra.proc
from loguru import logger as LOG

LOCUST_FILE_NAME = "basicperf_locustfile.py"

# Prefix for the CSV files locust writes. Locust appends _stats.csv,
# _failures.csv, and so on.
CSV_PREFIX = "locust"

# Name of the row holding totals across all request types in locust's stats CSV.
AGGREGATED_ROW_NAME = "Aggregated"

# Slack allowed on top of the expected spawn and measurement time before the
# run is considered stuck and killed by locust's own --run-time.
RUN_TIME_MARGIN_S = 60

# Shortest measurement window, as a fraction of the one requested, which is
# still accepted as describing steady state.
MIN_MEASURED_FRACTION = 0.9


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
    cmd += ["--measure-time-s", f"{args.measure_time_s}"]

    # The run is normally ended by the locustfile, a fixed time after the last
    # user has spawned. This is only a backstop against a run which never
    # finishes spawning, so it is deliberately generous: locust's --run-time
    # includes the ramp, and pre-empting the real deadline would silently
    # shorten the measurement window.
    spawn_time_s = math.ceil(args.users / args.spawn_rate)
    run_time_ceiling_s = spawn_time_s + args.measure_time_s + RUN_TIME_MARGIN_S
    cmd += ["--run-time", f"{run_time_ceiling_s}s"]

    # A single locust process cannot saturate the service, because it drives
    # all of its users from one thread. Fork enough workers to keep the client
    # from being the bottleneck.
    cmd += ["--processes", f"{args.locust_processes}"]

    # Workers reach the master over TCP, on a fixed port 5557 by default. Pick
    # a free one instead, so that a second locust run on the same machine, from
    # another test or another checkout, does not fail to bind.
    master_port = infra.net.probably_free_local_port("localhost")
    cmd += ["--master-bind-port", f"{master_port}"]
    cmd += ["--master-port", f"{master_port}"]

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


def stat_as_float(stats: dict, column: str) -> float:
    """Read one numeric column from locust's statistics.

    Locust writes "N/A" rather than a number when it has too few samples to
    produce a percentile, so a run which barely gathered any data would
    otherwise fail here with a bare ValueError, after the network has already
    been torn down and the evidence lost.
    """
    value = stats[column]
    try:
        return float(value)
    except ValueError as e:
        raise RuntimeError(
            f"Locust reported {column!r} as {value!r} rather than a number, "
            "which means it had too few samples to compute it. The run did "
            "not gather enough data to describe steady state."
        ) from e


def measure(args, sig_ms_interval: int) -> dict:
    """Run the workload against a fresh network with the given signature
    interval, and return the statistics locust recorded."""
    args.sig_ms_interval = sig_ms_interval
    # A response is only sent once its transaction commits, and commit cannot
    # be observed any faster than the primary sends consensus updates. Move
    # that in step with the signature interval, as commit_latency.py does,
    # otherwise the shorter intervals are gated by the 100ms default and the
    # setting has no effect.
    args.consensus_update_timeout_ms = sig_ms_interval

    LOG.info(f"Starting nodes on {args.nodes} with {sig_ms_interval}ms signatures")
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_primary()

        infra.key_space.create_and_fill_key_space(args.key_space_size, primary)

        stats = run_locust(args, network, primary)

        request_count = int(stats["Request Count"])
        failure_count = int(stats["Failure Count"])
        throughput = stat_as_float(stats, "Requests/s")
        # Locust reports response times in milliseconds.
        median_latency_ms = stat_as_float(stats, "Median Response Time")
        p99_latency_ms = stat_as_float(stats, "99%")
        min_latency_ms = stat_as_float(stats, "Min Response Time")

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

        # Locust reports throughput over the window its statistics cover, so
        # the two together give the length of that window. Check it against the
        # window that was asked for: a short window still yields a plausible
        # looking throughput, so without this a truncated run would be reported
        # as a valid result.
        measured_duration_s = request_count / throughput
        if measured_duration_s < args.measure_time_s * MIN_MEASURED_FRACTION:
            raise RuntimeError(
                f"Measured over {measured_duration_s:.1f}s, but expected "
                f"{args.measure_time_s}s. The run was cut short, so this "
                "result does not describe steady state."
            )
        LOG.info(f"Measured over {measured_duration_s:.1f}s")

        # Locust should already have exited non-zero, but do not report a
        # throughput figure built from failed requests under any circumstances.
        if failure_count != 0:
            raise RuntimeError(
                f"Locust recorded {failure_count} failures out of {request_count} requests"
            )

        mem = infra.proc.get_proc_memory_stats(primary.remote.remote.proc.pid)

        network.stop_all_nodes()

        return {
            "throughput": throughput,
            "median_latency_ms": median_latency_ms,
            "p99_latency_ms": p99_latency_ms,
            "min_latency_ms": min_latency_ms,
            "memory": mem,
        }


def run(args):
    # Each interval needs its own network, since the signature interval is
    # fixed in the node's configuration at startup.
    results = {}
    for sig_ms_interval in args.sig_ms_intervals:
        results[sig_ms_interval] = measure(args, sig_ms_interval)

    bf = infra.bencher.Bencher()
    for sig_ms_interval, result in results.items():
        label = f"{args.perf_label} (sig_ms_interval={sig_ms_interval}ms)"
        bf.set(label, infra.bencher.Throughput(round(result["throughput"], 1)))
        bf.set(
            label,
            infra.bencher.Latency(
                value=result["median_latency_ms"],
                high_value=result["p99_latency_ms"],
                low_value=result["min_latency_ms"],
            ),
        )
        if result["memory"] is not None:
            bf.set_memory(label, result["memory"])

    LOG.info("Summary:")
    for sig_ms_interval, result in results.items():
        LOG.info(
            f"  {sig_ms_interval:>5}ms signatures: "
            f"{result['throughput']:>9.1f} tx/s, "
            f"p50 {result['median_latency_ms']:.1f}ms"
        )


def cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--users",
        help="Number of concurrent locust users, each sending one blocking write at a time",
        type=int,
        default=320,
    )
    parser.add_argument(
        "--spawn-rate",
        help="Number of users to start per second",
        type=int,
        default=320,
    )
    parser.add_argument(
        "--measure-time-s",
        help="Seconds to measure for, once all users have spawned",
        type=int,
        default=20,
    )
    parser.add_argument(
        "--locust-processes",
        help="Number of locust worker processes to fork",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--sig-ms-intervals",
        help="Signature intervals, in milliseconds, to measure the workload at. "
        "Each is measured against its own network.",
        type=int,
        nargs="+",
        default=[2, 20, 100],
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
