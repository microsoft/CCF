# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Local Fluentd-compatible TCP collectors for tests and benchmarks."""

import collections
import io
import json
import selectors
import socket
import threading
import time
from dataclasses import dataclass, field

import msgpack


class Collector:
    """Decode Forward messages without retaining events or writing them to disk."""

    def __init__(self, node_count=2, record_callback=None):
        if node_count < 1:
            raise ValueError("The collector requires at least one node")
        self.node_count = node_count
        self.record_callback = record_callback

    def __enter__(self):
        self.records = 0
        self.bytes = 0
        self.processes = set()
        self.tags = set()
        self.error = None
        self.stop = threading.Event()
        self.selector = selectors.DefaultSelector()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(self.node_count)
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
                        if len(self.selector.get_map()) > self.node_count:
                            connection.close()
                            raise RuntimeError(
                                f"Expected at most {self.node_count} node connections"
                            )
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
                            if (
                                not isinstance(timestamp, msgpack.ExtType)
                                or timestamp.code != 0
                                or len(timestamp.data) != 8
                            ):
                                raise RuntimeError("Expected Fluentd EventTime")
                            self.records += 1
                            self.tags.add(tag)
                            self.processes.add(record["process_id"])
                            if self.record_callback is not None:
                                self.record_callback(tag, timestamp, record)
                            if len(self.processes) > self.node_count:
                                raise RuntimeError(
                                    f"Expected at most {self.node_count} process IDs"
                                )
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


@dataclass
class Connection:
    data: bytearray = field(default_factory=bytearray)
    eof: bool = False


class Recorder:
    """Retain each connection's raw Forward stream until closed.

    Unlike Collector, any number of nodes may connect, and the listener runs on
    a daemon thread so that a recorder which is never closed cannot keep the
    test process alive.
    """

    def __init__(self):
        self.connections = []
        self.error = None
        self.closed = False
        self.deadline = None
        self.stop = threading.Event()
        self.selector = selectors.DefaultSelector()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ)
        self.endpoint = {
            "host": "127.0.0.1",
            "port": str(self.listener.getsockname()[1]),
        }
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while True:
                # Only an idle select that starts after stop shows that no
                # connection or data is still queued.
                stopping = self.stop.is_set()
                events = self.selector.select(timeout=0.1)
                for key, _ in events:
                    if key.fileobj is self.listener:
                        peer, _ = self.listener.accept()
                        peer.setblocking(False)
                        self.connections.append(Connection())
                        self.selector.register(
                            peer, selectors.EVENT_READ, self.connections[-1]
                        )
                        continue
                    try:
                        data = key.fileobj.recv(65536)
                    except BlockingIOError:
                        continue
                    except OSError:
                        data = None
                    if data:
                        key.data.data += data
                        continue
                    key.data.eof = data == b""
                    self.selector.unregister(key.fileobj)
                    key.fileobj.close()
                if stopping and (
                    (not events and len(self.selector.get_map()) == 1)
                    or time.monotonic() >= self.deadline
                ):
                    break
        except Exception as error:  # Reported by the capture, not raised.
            self.error = error

    def close(self, timeout=5):
        """Wait up to timeout seconds for every connection to reach EOF, then
        stop listening. Idempotent; returns the recorded connections."""
        if not self.closed:
            self.closed = True
            self.deadline = time.monotonic() + timeout
            self.stop.set()
            self.thread.join(timeout + 1)
            if self.thread.is_alive():
                self.error = self.error or RuntimeError("Recorder did not stop")
            for key in list(self.selector.get_map().values()):
                key.fileobj.close()
            self.selector.close()
        return self.connections


def write_cft_trace(connections, path):
    """Decode recorded ccf.cft events into one NDJSON file of {process_id,
    h_ts, msg} records, in connection order.

    Returns the record count per process ID, and any reasons the recorded
    streams may be incomplete.
    """
    counts = collections.Counter()
    problems = []
    with open(path, "w", encoding="utf-8") as output:
        for i, connection in enumerate(connections):
            if not connection.eof:
                problems.append(f"Connection {i} did not reach EOF")
            unpacker = msgpack.Unpacker(io.BytesIO(connection.data), raw=False)
            decoded = 0
            try:
                for tag, _, record in unpacker:
                    if tag != "ccf.cft" or set(record) != {"process_id", "h_ts", "msg"}:
                        raise ValueError(f"Unexpected {tag} event: {sorted(record)}")
                    output.write(json.dumps(record, allow_nan=False) + "\n")
                    counts[record["process_id"]] += 1
                    decoded = unpacker.tell()
            except Exception as error:
                problems.append(f"Connection {i} is malformed: {error}")
            else:
                if decoded != len(connection.data):
                    problems.append(
                        f"Connection {i} ends with "
                        f"{len(connection.data) - decoded} undecoded bytes"
                    )
    return counts, problems
