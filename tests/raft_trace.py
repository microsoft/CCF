# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Capture and order Fluentd Message-mode records from the Raft driver."""

import json
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


def check_connection_timeout(driver, scenario):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        host, port = reservation.getsockname()
        result = subprocess.run(
            [
                str(pathlib.Path(driver).resolve()),
                str(pathlib.Path(scenario).resolve()),
                host,
                str(port),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    assert result.returncode != 0, "Driver proceeded without a collector"
    assert "Timed out waiting for Fluentd connection" in result.stdout


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
    records.sort(key=lambda record: record["h_ts"])
    for sequence, record in enumerate(records):
        assert record["h_ts"] == sequence, "Missing or duplicate trace sequence"
        assert record["process_id"] == records[0]["process_id"]
    return result, records


def as_log_lines(records):
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
    ]


def compare(baseline_driver, candidate_driver, scenarios):
    """Compare all event fields against an upstream JSON-tracing driver."""
    total = 0
    paths = sorted(
        path for path in pathlib.Path(scenarios).rglob("*") if path.is_file()
    )
    assert paths, "No scenarios found"
    for scenario in paths:
        baseline = subprocess.run(
            [str(pathlib.Path(baseline_driver).resolve()), str(scenario)],
            capture_output=True,
            text=True,
            check=True,
        )
        expected = []
        for line in baseline.stdout.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("tag") == "raft_trace":
                expected.append(
                    {"cmd": entry["cmd"]} if "cmd" in entry else entry["msg"]
                )
        assert expected, f"{scenario}: baseline has no trace events"
        result, records = run_driver(candidate_driver, scenario)
        result.check_returncode()
        actual = [record["msg"] for record in records]
        assert actual == expected, f"{scenario}: event parity mismatch"
        total += len(records)
    print(f"{total} records match across {len(paths)} scenarios")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=compare.__doc__)
    parser.add_argument("baseline_driver")
    parser.add_argument("candidate_driver")
    parser.add_argument("scenarios")
    args = parser.parse_args()
    compare(args.baseline_driver, args.candidate_driver, args.scenarios)
