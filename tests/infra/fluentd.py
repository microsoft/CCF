# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Local Fluentd-compatible TCP collector for benchmarks."""

import selectors
import socket
import threading
import time

import msgpack


class _Connection:
    __slots__ = ("base", "buf", "consumed", "unpacker")

    def __init__(self, capture_frames):
        # Log messages need not be valid UTF-8.
        self.unpacker = msgpack.Unpacker(
            raw=False,
            max_buffer_size=1024 * 1024,
            unicode_errors="replace",
        )
        self.buf = bytearray() if capture_frames else None
        self.base = 0
        self.consumed = 0


class Collector:
    """Decode Forward messages without retaining events or writing them to disk."""

    def __init__(
        self,
        node_count=2,
        record_callback=None,
        host="127.0.0.1",
        frame_callback=None,
    ):
        if node_count < 1:
            raise ValueError("The collector requires at least one node")
        self.node_count = node_count
        self.record_callback = record_callback
        self.frame_callback = frame_callback
        self.host = host

    def __enter__(self):
        self.records = 0
        self.bytes = 0
        self.processes = set()
        self.tags = set()
        self.error = None
        self.stop = threading.Event()
        self.selector = selectors.DefaultSelector()
        self.listener = socket.socket(
            socket.AF_INET6 if ":" in self.host else socket.AF_INET
        )
        self.listener.bind((self.host, 0))
        self.listener.listen(self.node_count)
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ)
        self.endpoint = {
            "host": self.host,
            "port": str(self.listener.getsockname()[1]),
            "queue_capacity": 4096,
        }
        # A daemon, so that a collector that is never exited cannot keep the
        # test process alive.
        self.thread = threading.Thread(target=self.run, daemon=True)
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
                            _Connection(self.frame_callback is not None),
                        )
                    else:
                        data = key.fileobj.recv(65536)
                        if not data:
                            self.selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        self.bytes += len(data)
                        conn = key.data
                        if conn.buf is not None:
                            conn.buf.extend(data)
                        conn.unpacker.feed(data)
                        for tag, timestamp, record in conn.unpacker:
                            if (
                                not isinstance(timestamp, msgpack.ExtType)
                                or timestamp.code != 0
                                or len(timestamp.data) != 8
                            ):
                                raise RuntimeError("Expected Fluentd EventTime")
                            self.records += 1
                            self.tags.add(tag)
                            self.processes.add(record["pid"])
                            if self.frame_callback is not None:
                                end = conn.unpacker.tell()
                                start = conn.consumed - conn.base
                                frame = bytes(conn.buf[start : end - conn.base])
                                conn.consumed = end
                                self.frame_callback(frame)
                            if self.record_callback is not None:
                                self.record_callback(tag, timestamp, record)
                            if len(self.processes) > self.node_count:
                                raise RuntimeError(
                                    f"Expected at most {self.node_count} process IDs"
                                )
                        if conn.buf is not None and conn.consumed > conn.base:
                            del conn.buf[: conn.consumed - conn.base]
                            conn.base = conn.consumed
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
