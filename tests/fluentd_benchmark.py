# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Paired Raft export benchmark using a local Fluentd-compatible TCP drain."""

import copy
import itertools
import json
import pathlib
import selectors
import socket
import threading
import time

import basicperf_locust
import infra.e2e_args
import infra.locust_benchmark
from loguru import logger as LOG

import msgpack


class Collector:
    """Decode Forward messages without retaining events or writing them to disk."""

    def __enter__(self):
        self.records = 0
        self.bytes = 0
        self.processes = set()
        self.error = None
        self.stop = threading.Event()
        self.selector = selectors.DefaultSelector()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ)
        self.endpoint = {
            "host": "127.0.0.1",
            "port": str(self.listener.getsockname()[1]),
            "queue_capacity": 4096,
        }
        self.thread = threading.Thread(target=self.run)
        self.thread.start()
        return self

    def run(self):
        try:
            while True:
                events = self.selector.select(timeout=0.1)
                for key, _ in events:
                    if key.fileobj is self.listener:
                        connection, _ = self.listener.accept()
                        if len(self.selector.get_map()) > 2:
                            connection.close()
                            raise RuntimeError("Expected at most two node connections")
                        connection.setblocking(False)
                        self.selector.register(
                            connection,
                            selectors.EVENT_READ,
                            msgpack.Unpacker(raw=False, max_buffer_size=1024 * 1024),
                        )
                    else:
                        data = key.fileobj.recv(65536)
                        if not data:
                            self.selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        self.bytes += len(data)
                        key.data.feed(data)
                        for tag, timestamp, record in key.data:
                            if tag != "ccf.raft_trace":
                                raise RuntimeError(f"Unexpected trace tag: {tag}")
                            if (
                                not isinstance(timestamp, msgpack.ExtType)
                                or timestamp.code != 0
                                or len(timestamp.data) != 8
                            ):
                                raise RuntimeError("Expected Fluentd EventTime")
                            self.records += 1
                            self.processes.add(record["process_id"])
                            if len(self.processes) > 2:
                                raise RuntimeError("Expected at most two process IDs")
                if self.stop.is_set() and (
                    time.monotonic() >= self.deadline
                    or (not events and len(self.selector.get_map()) == 1)
                ):
                    break
        except Exception as error:  # Propagate collector failures on the main thread.
            self.error = error

    def __exit__(self, *_):
        # Nodes have stopped. Allow buffered TCP data to reach EOF, but never
        # wait indefinitely for a peer.
        self.deadline = time.monotonic() + 3
        self.stop.set()
        self.thread.join()
        for key in list(self.selector.get_map().values()):
            key.fileobj.close()
        self.selector.close()
        if self.error:
            raise self.error


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
            ), "Both nodes must emit Raft events; build with CCF_RAFT_TRACING=ON"
        else:
            assert collector.bytes == 0
        counts = {"records": collector.records, "bytes": collector.bytes}
        pathlib.Path(f"{variant.label}_received.json").write_text(
            json.dumps(counts), encoding="utf-8"
        )
        LOG.info(f"{variant.perf_label}: {counts}")


if __name__ == "__main__":
    run(basicperf_locust.cli_args())
