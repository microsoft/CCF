# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Local Fluentd-compatible TCP collectors for tests and benchmarks."""

import collections
import io
import json
import selectors
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

import msgpack


def event_time_ns(timestamp):
    """Nanoseconds since the epoch of a Forward event's Fluentd EventTime."""
    if (
        not isinstance(timestamp, msgpack.ExtType)
        or timestamp.code != 0
        or len(timestamp.data) != 8
    ):
        raise RuntimeError("Expected Fluentd EventTime")
    seconds, nanoseconds = struct.unpack(">II", timestamp.data)
    return seconds * 10**9 + nanoseconds


class _Server:
    """Accept Forward connections on a loopback port, and read them on a
    daemon thread until closed. Subclasses decide what to keep, and must set
    their own state before calling __init__, which starts the thread."""

    def __init__(self, host="127.0.0.1"):
        self.error = None
        self.deadline = None  # Set by close
        self.selector = selectors.DefaultSelector()
        self.listener = socket.create_server(
            (host, 0), family=socket.AF_INET6 if ":" in host else socket.AF_INET
        )
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ)
        self.endpoint = {"host": host, "port": str(self.listener.getsockname()[1])}
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def connected(self):
        """Return the state to keep for a new connection."""
        raise NotImplementedError

    def received(self, connection, data):
        raise NotImplementedError

    def disconnected(self, connection, eof):
        pass

    def run(self):
        try:
            while True:
                # Only an idle select that starts after close shows that no
                # connection or data is still queued.
                deadline = self.deadline
                events = self.selector.select(timeout=0.1)
                for key, _ in events:
                    if key.fileobj is self.listener:
                        peer, _ = self.listener.accept()
                        peer.setblocking(False)
                        self.selector.register(
                            peer, selectors.EVENT_READ, self.connected()
                        )
                        continue
                    try:
                        data = key.fileobj.recv(65536)
                    except BlockingIOError:
                        continue
                    except OSError:
                        data = None
                    if data:
                        self.received(key.data, data)
                        continue
                    self.disconnected(key.data, eof=data == b"")
                    self.selector.unregister(key.fileobj)
                    key.fileobj.close()
                if deadline is not None and (
                    (not events and len(self.selector.get_map()) == 1)
                    or time.monotonic() >= deadline
                ):
                    break
        except Exception as error:  # Reported by the subclass's user.
            self.error = error

    def close(self, timeout=5):
        """Wait up to timeout seconds for every connection to end, then stop
        listening. Idempotent."""
        if self.deadline is None:
            self.deadline = time.monotonic() + timeout
            self.thread.join()
            for key in list(self.selector.get_map().values()):
                key.fileobj.close()
            self.selector.close()


class Collector(_Server):
    """Count Forward events from at most node_count nodes, without retaining
    them or writing them to disk."""

    def __init__(self, node_count=2, record_callback=None):
        if node_count < 1:
            raise ValueError("The collector requires at least one node")
        self.node_count = node_count
        self.record_callback = record_callback
        self.records = 0
        self.bytes = 0
        self.processes = set()
        self.tags = set()
        super().__init__()
        self.endpoint["queue_capacity"] = 4096

    def __enter__(self):
        return self

    def connected(self):
        if len(self.selector.get_map()) > self.node_count:
            raise RuntimeError(f"Expected at most {self.node_count} node connections")
        return msgpack.Unpacker(raw=False, max_buffer_size=1024 * 1024)

    def received(self, connection, data):
        self.bytes += len(data)
        connection.feed(data)
        for tag, timestamp, record in connection:
            event_time_ns(timestamp)
            self.records += 1
            self.tags.add(tag)
            self.processes.add(record["pid"])
            if self.record_callback is not None:
                self.record_callback(tag, timestamp, record)
            if len(self.processes) > self.node_count:
                raise RuntimeError(f"Expected at most {self.node_count} process IDs")

    def __exit__(self, *_):
        # Nodes have stopped. Allow buffered TCP data to reach EOF, but never
        # wait indefinitely for a peer.
        self.close(timeout=3)
        if self.error:
            raise self.error


@dataclass
class Connection:
    data: bytearray = field(default_factory=bytearray)
    eof: bool = False


class Recorder(_Server):
    """Retain each connection's raw Forward stream, from any number of nodes,
    as connections."""

    def __init__(self, ipv6=False):
        self.connections = []
        super().__init__("::1" if ipv6 else "127.0.0.1")

    def connected(self):
        self.connections.append(Connection())
        return self.connections[-1]

    def received(self, connection, data):
        connection.data += data

    def disconnected(self, connection, eof):
        connection.eof = eof


def write_cft_trace(connections, path):
    """Decode recorded ccf.cft events into one NDJSON file of {pid, m_ts, msg}
    records, in connection order, adding each event's emission time in
    nanoseconds as ts.

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
                for tag, timestamp, record in unpacker:
                    if tag != "ccf.cft" or set(record) != {"pid", "m_ts", "msg"}:
                        raise ValueError(f"Unexpected {tag} event: {sorted(record)}")
                    record["ts"] = event_time_ns(timestamp)
                    output.write(json.dumps(record, allow_nan=False) + "\n")
                    counts[record["pid"]] += 1
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
