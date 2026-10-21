# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Capture Fluentd Message-mode records in the Raft driver's recorded order."""

import pathlib
import socket
import struct
import subprocess
import threading

import msgpack


def unique_map(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate MessagePack key: {key}")
        result[key] = value
    return result


def run_driver(driver, scenario, timeout=60):
    records = []
    errors = []
    done = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)

        def collect():
            try:
                while True:
                    try:
                        peer, _ = listener.accept()
                    except TimeoutError:
                        if done.is_set():
                            break
                        continue
                    with peer:
                        peer.settimeout(timeout)
                        unpacker = msgpack.Unpacker(
                            raw=False, object_pairs_hook=unique_map
                        )
                        received = complete = 0
                        while data := peer.recv(65536):
                            received += len(data)
                            unpacker.feed(data)
                            for tag, timestamp, record in unpacker:
                                assert tag == "ccf.raft_trace"
                                assert isinstance(timestamp, msgpack.ExtType)
                                assert timestamp.code == 0
                                seconds, nanos = struct.unpack(">II", timestamp.data)
                                assert seconds > 0 and nanos < 10**9
                                assert set(record) == {"process_id", "h_ts", "msg"}
                                records.append(record)
                                complete = unpacker.tell()
                        assert received == complete, "Truncated MessagePack stream"
            except Exception as error:
                errors.append(error)

        collector = threading.Thread(target=collect)
        collector.start()
        host, port = listener.getsockname()
        try:
            result = subprocess.run(
                [
                    str(pathlib.Path(driver).resolve()),
                    str(pathlib.Path(scenario).resolve()),
                    host,
                    str(port),
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        finally:
            done.set()
            collector.join(timeout + 1)
        assert not collector.is_alive(), "Collector failed to stop"
    if errors:
        raise errors[0]
    if not records:
        with pathlib.Path(scenario).open(encoding="utf-8") as source:
            for line in source:
                line = line.split("#", 1)[0].rstrip(" \t\n\r\f\v")
                if line.startswith("===="):
                    break
                assert not line, f"No Raft trace records captured for {scenario}"
    for sequence, record in enumerate(records):
        assert (
            record["h_ts"] == sequence
        ), "Missing, duplicate or reordered trace sequence"
        assert record["process_id"] == records[0]["process_id"]
    return result, records


def as_log_lines(records):
    """Adapt protocol callbacks for the legacy TLA consumer, not Lean replay.

    Native operation boundaries are observations, not TLA protocol steps.
    The Lean collector preserves the original records without this adapter.
    """
    return [
        (
            {"tag": "raft_trace", **record["msg"]}
            if "cmd" in record["msg"]
            else {
                "tag": "raft_trace",
                "h_ts": str(record["h_ts"]),
                "msg": record["msg"],
            }
        )
        for record in records
        if record["msg"].get("function") != "operation_boundary"
    ]
