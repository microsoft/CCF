# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import time
import http
import statistics
import cimetrics.upload
import infra.e2e_args
import infra.network
import suite.test_requirements as reqs
from infra.log_capture import flush_info
from infra.tx_status import TxStatus

from loguru import logger as LOG


def poll_for_commit(client, view, seqno, timeout=3):
    start_time = time.time()
    end_time = start_time + timeout
    logs = []
    while time.time() < end_time:
        logs.clear()
        r = client.get(
            f"/node/tx?transaction_id={view}.{seqno}",
            log_capture=logs,
        )
        assert r.status_code == http.HTTPStatus.OK, r
        status = TxStatus(r.body.json()["status"])
        if status == TxStatus.Committed:
            return time.time() - start_time
        elif status == TxStatus.Invalid:
            flush_info(logs)
            raise RuntimeError(
                f"Transaction ID {view}.{seqno} is marked invalid and will never be committed"
            )
        # else retry immediately
    flush_info(logs)
    raise TimeoutError(f"Did not find commit for {view}.{seqno} after {timeout}s")


class Stats:
    def __init__(self, label, ns, units="s"):
        self.label = label
        self.ns = ns
        self.units = units
        self.stats = {
            "min": min(ns),
            "max": max(ns),
            "mean": statistics.mean(ns),
            "stdev": statistics.stdev(ns),
        }

    def display(self, print_fn):
        print_fn(f"{self.label} ({len(self.ns)} entries)")
        keylen = max(len(k) for k in self.stats.keys())
        valuelen = max(len(f"{v:.2f}") for v in self.stats.values())

        for k, v in self.stats.items():
            print_fn(
                f" - {{:>{keylen}}} = {{:>{valuelen}.2f}}{{}}".format(k, v, self.units)
            )

    def mean(self):
        return self.stats["mean"]


@reqs.description("Measure commit latency")
def measure_commit_latency(args, sig_interval=100):
    args.sig_ms_interval = sig_interval
    args.consensus_update_timeout_ms = sig_interval

    iterations = 20

    times = []
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_nodes()

        with primary.client("user0") as c:
            for _ in range(iterations):
                r = c.post(
                    "/app/log/private",
                    {"id": 42, "msg": "Hello world"},
                    log_capture=[],
                )
                assert r.status_code == http.HTTPStatus.OK, r
                poll_time_s = poll_for_commit(c, r.view, r.seqno)
                poll_time_ms = poll_time_s * 1000
                times.append(poll_time_ms)

    stats = Stats(
        f"Commit latency with {args.sig_ms_interval}ms sig interval", times, units="ms"
    )
    return stats


def run(args):
    all_stats = {}
    for sig_interval in (
        1,
        2,
        4,
        8,
        16,
        32,
        64,
        128,
        256,
    ):
        all_stats[sig_interval] = measure_commit_latency(
            args, sig_interval=sig_interval
        )

    factors = []
    for sig_interval, stats in all_stats.items():
        factor = stats.mean() / sig_interval
        print_fn = (
            LOG.success if factor <= 1 else LOG.warning if factor < 2 else LOG.error
        )
        stats.display(print_fn)
        print_fn(f"Mean commit latency / sig_interval = {factor:.2f}")
        factors.append(factor)

    with cimetrics.upload.metrics(complete=False) as metrics:
        metrics.put("Commit latency factor", statistics.mean(factors))


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    run(args)
