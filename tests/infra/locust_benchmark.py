# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Shared orchestration and reporting for Locust benchmarks."""

import argparse
import csv
import dataclasses
import math
import os
import subprocess
from collections.abc import Callable, Mapping
from typing import Any

from loguru import logger as LOG

import infra.bencher
import infra.interfaces
import infra.net
import infra.network
import infra.proc

CSV_PREFIX = "locust"
AGGREGATED_ROW_NAME = "Aggregated"
RUN_TIME_MARGIN_S = 60
MIN_MEASURED_FRACTION = 0.9
JWT_ENVIRONMENT_VARIABLE = "CCF_LOCUST_JWT"


@dataclasses.dataclass(frozen=True)
class Workload:
    locust_file_name: str
    arguments: tuple[str, ...] = ()
    environment: Mapping[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class Result:
    throughput: float
    median_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    memory: dict[str, int] | None


PrepareWorkload = Callable[[argparse.Namespace, Any, Any], Workload]


def positive_int(value: str) -> int:
    parsed_value = int(value)
    if parsed_value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed_value


def add_cli_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--users",
        help="Number of concurrent Locust users, each sending one request at a time",
        type=positive_int,
        default=320,
    )
    parser.add_argument(
        "--spawn-rate",
        help="Number of users to start per second",
        type=positive_int,
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
        help="Number of Locust worker processes to fork",
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


def locust_file_path(file_name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), file_name)


def run_locust(
    args: argparse.Namespace, network: Any, primary: Any, workload: Workload
) -> dict[str, str]:
    """Run Locust to completion and return its aggregated statistics."""
    csv_prefix = os.path.join(network.common_dir, CSV_PREFIX)
    host = "https://" + infra.interfaces.make_address(
        primary.get_public_rpc_host(), primary.get_public_rpc_port()
    )

    cmd = [
        "locust",
        "--headless",
        "--locustfile",
        locust_file_path(workload.locust_file_name),
        "--host",
        host,
        "--ca",
        primary.session_ca()["ca"],
        "--users",
        str(args.users),
        "--spawn-rate",
        str(args.spawn_rate),
        "--measure-time-s",
        str(args.measure_time_s),
    ]
    cmd.extend(workload.arguments)

    # The locustfile ends the run after a full measurement window following the
    # ramp. Locust's own deadline is only a generous backstop for a stuck ramp.
    spawn_time_s = math.ceil(args.users / args.spawn_rate)
    run_time_ceiling_s = spawn_time_s + args.measure_time_s + RUN_TIME_MARGIN_S
    cmd += ["--run-time", f"{run_time_ceiling_s}s"]

    # Fork workers so the single-threaded client is not the bottleneck.
    cmd += ["--processes", str(args.locust_processes)]

    # Avoid colliding with another Locust master on its default port.
    master_port = infra.net.probably_free_local_port("localhost")
    cmd += ["--master-bind-port", str(master_port), "--master-port", str(master_port)]

    # Report only steady state, at the full user count.
    cmd += ["--reset-stats", "--csv", csv_prefix]

    LOG.info(f"Starting Locust: {' '.join(cmd)}")
    process_environment = os.environ.copy()
    process_environment.update(workload.environment)
    # Locust exits non-zero if any request failed, which should fail the test.
    subprocess.run(cmd, check=True, env=process_environment)

    return read_aggregated_stats(f"{csv_prefix}_stats.csv")


def read_aggregated_stats(stats_path: str) -> dict[str, str]:
    with open(stats_path, encoding="utf-8", newline="") as stats_file:
        for row in csv.DictReader(stats_file):
            if row.get("Name") == AGGREGATED_ROW_NAME:
                return {
                    key: value
                    for key, value in row.items()
                    if key is not None and value is not None
                }

    raise RuntimeError(f"No {AGGREGATED_ROW_NAME} row found in {stats_path}")


def stat_as_float(stats: Mapping[str, str], column: str) -> float:
    """Read one numeric column from Locust's statistics."""
    value = stats[column]
    try:
        return float(value)
    except ValueError as exc:
        raise RuntimeError(
            f"Locust reported {column!r} as {value!r} rather than a number, "
            "which means it had too few samples to compute it. The run did "
            "not gather enough data to describe steady state."
        ) from exc


def stat_as_int(stats: Mapping[str, str], column: str) -> int:
    value = stats[column]
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(
            f"Locust reported {column!r} as {value!r} rather than an integer"
        ) from exc


def parse_result(
    stats: Mapping[str, str], measure_time_s: int, memory: dict[str, int] | None
) -> Result:
    request_count = stat_as_int(stats, "Request Count")
    failure_count = stat_as_int(stats, "Failure Count")
    throughput = stat_as_float(stats, "Requests/s")
    median_latency_ms = stat_as_float(stats, "Median Response Time")
    p99_latency_ms = stat_as_float(stats, "99%")
    min_latency_ms = stat_as_float(stats, "Min Response Time")

    if request_count == 0:
        raise RuntimeError("Locust recorded no requests")
    if failure_count != 0:
        raise RuntimeError(
            f"Locust recorded {failure_count} failures out of {request_count} requests"
        )
    if throughput <= 0:
        raise RuntimeError(f"Locust reported non-positive throughput {throughput}")

    measured_duration_s = request_count / throughput
    if measured_duration_s < measure_time_s * MIN_MEASURED_FRACTION:
        raise RuntimeError(
            f"Measured over {measured_duration_s:.1f}s, but expected "
            f"{measure_time_s}s. The run was cut short, so this result does "
            "not describe steady state."
        )

    LOG.info(f"{request_count} requests => {throughput:.1f} tx/s")
    LOG.info(
        f"Latency: min={min_latency_ms:.1f}ms p50={median_latency_ms:.1f}ms "
        f"p99={p99_latency_ms:.1f}ms"
    )
    LOG.info(f"Measured over {measured_duration_s:.1f}s")

    return Result(
        throughput=throughput,
        median_latency_ms=median_latency_ms,
        p99_latency_ms=p99_latency_ms,
        min_latency_ms=min_latency_ms,
        memory=memory,
    )


def measure(
    args: argparse.Namespace,
    sig_ms_interval: int,
    prepare_workload: PrepareWorkload,
) -> Result:
    """Run one workload against a fresh network at one signature interval."""
    args.sig_ms_interval = sig_ms_interval
    # Keep consensus updates in step with signatures. This is required by
    # workloads which wait for commit and gives all workloads consistent
    # interval configuration.
    args.consensus_update_timeout_ms = sig_ms_interval

    LOG.info(f"Starting nodes on {args.nodes} with {sig_ms_interval}ms signatures")
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()
        workload = prepare_workload(args, network, primary)
        stats = run_locust(args, network, primary, workload)
        memory = infra.proc.get_proc_memory_stats(primary.remote.remote.proc.pid)
        result = parse_result(stats, args.measure_time_s, memory)
        network.stop_all_nodes()
        return result


def run(args: argparse.Namespace, prepare_workload: PrepareWorkload) -> None:
    # Each interval needs its own network because the signature interval is
    # fixed in the node's configuration at startup.
    results = {
        sig_ms_interval: measure(args, sig_ms_interval, prepare_workload)
        for sig_ms_interval in args.sig_ms_intervals
    }

    bencher = infra.bencher.Bencher()
    for sig_ms_interval, result in results.items():
        label = (
            args.perf_label
            if len(results) == 1
            else f"{args.perf_label} (sig_ms_interval={sig_ms_interval}ms)"
        )
        bencher.set(label, infra.bencher.Throughput(round(result.throughput, 1)))
        bencher.set(
            label,
            infra.bencher.Latency(
                value=result.median_latency_ms,
                high_value=result.p99_latency_ms,
                low_value=result.min_latency_ms,
            ),
        )
        if result.memory is not None:
            bencher.set_memory(label, result.memory)

    LOG.info("Summary:")
    for sig_ms_interval, result in results.items():
        LOG.info(
            f"  {sig_ms_interval:>5}ms signatures: "
            f"{result.throughput:>9.1f} tx/s, "
            f"p50 {result.median_latency_ms:.1f}ms"
        )
