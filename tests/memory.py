# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import http
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import infra.logging_app as app
from ccf.log_capture import flush_info

from loguru import logger as LOG


class HeapSize:
    max_total = None
    previous_peak = None

    def __init__(self, j):
        self.max = j["max_total_heap_size"]
        self.peak = j["peak_allocated_heap_size"]
        self.current = j["current_allocated_heap_size"]

        assert self.peak <= self.max
        assert self.current <= self.peak

        # Max heap should not change
        if HeapSize.max_total is None:
            HeapSize.max_total = self.max
        else:
            assert self.max == HeapSize.max_total

        # Peak should never decrease
        if HeapSize.previous_peak is not None:
            assert self.peak >= HeapSize.previous_peak
        HeapSize.previous_peak = self.peak


def get_heap_size(node):
    with node.client() as nc:
        r = nc.get("/node/memory")
        assert r.status_code == http.HTTPStatus.OK.value
        return HeapSize(r.body.json())


@reqs.description("Test memory use of logging app")
def test_logging_memory(network, args):
    primary, _ = network.find_primary()
    logs = []

    initial_heap = get_heap_size(primary)

    msg_body = "Some small simple message body: {}"

    # Logging many new entries should increase heap consumption
    total_keys_count = 5000
    LOG.info(f"Logging to {total_keys_count} new keys")
    with primary.client("user0") as c:
        for i in range(total_keys_count):
            logs = []
            c.post(
                "/app/log/private",
                {"id": i, "msg": msg_body.format(i)},
                log_capture=logs,
            )
    flush_info(logs, None, 0)

    grown_heap = get_heap_size(primary)
    assert grown_heap.current >= initial_heap.current

    # Additional changes within the same working set should not increase memory use
    small_working_set = total_keys_count // 100
    repeats = 5
    LOG.info(f"Rewriting {small_working_set} keys {repeats} times")
    with primary.client("user0") as c:
        for n in range(repeats):
            for i in range(small_working_set):
                logs = []
                c.post(
                    "/app/log/private",
                    {"id": i, "msg": msg_body.format(n * i)},
                    log_capture=logs,
                )
    flush_info(logs, None, 0)

    reused_heap = get_heap_size(primary)
    assert reused_heap.current <= grown_heap.current

    return network


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "bft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_logging_memory(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    if args.enclave_type == "virtual":
        LOG.warning("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "liblogging"
    run(args)
