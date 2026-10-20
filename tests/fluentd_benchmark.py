# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Paired Raft export benchmark using a local Fluentd-compatible TCP drain."""

import copy
import itertools
import json
import pathlib

import basicperf_locust
import infra.e2e_args
import infra.locust_benchmark
from infra.fluentd import Collector
from loguru import logger as LOG


def run(args):
    args.nodes = infra.e2e_args.nodes(args, 2)
    for interval, enabled in itertools.product(args.sig_ms_intervals, (False, True)):
        variant = copy.deepcopy(args)
        mode = "on" if enabled else "off"
        variant.label += f"_{interval}ms_{mode}"
        variant.sig_ms_intervals = [interval]
        variant.perf_label = (
            f"Fluentd TCP drain {mode} (2 nodes, {interval}ms signatures)"
        )
        with Collector() as collector:
            variant.observability = {"fluentd": collector.endpoint} if enabled else None
            infra.locust_benchmark.run(variant, basicperf_locust.prepare_workload)
        if enabled:
            assert (
                collector.records > 0 and len(collector.processes) == 2
            ), "Both nodes must emit Raft events to the configured collector"
        else:
            assert collector.bytes == 0
        counts = {"records": collector.records, "bytes": collector.bytes}
        pathlib.Path(f"{variant.label}_received.json").write_text(
            json.dumps(counts), encoding="utf-8"
        )
        LOG.info(f"{variant.perf_label}: {counts}")


if __name__ == "__main__":
    run(basicperf_locust.cli_args())
