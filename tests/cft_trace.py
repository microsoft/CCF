# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Capture CCF consensus protocol Fluentd records in the driver's recorded order."""

import pathlib
import socket
import struct
import subprocess
import threading

import msgpack


class CaptureError(RuntimeError):
    """A failed collection with unchanged process bytes and received records."""

    def __init__(self, error, stdout, stderr, records):
        super().__init__(f"{type(error).__name__}: {error}")
        self.stdout = stdout
        self.stderr = stderr
        self.records = list(records)


def unique_map(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate MessagePack key: {key}")
        result[key] = value
    return result


def run_driver(driver, scenario, timeout=60, *, text=True):
    """Run the named scenario and collect its structured records.

    Console output is decoded for text consumers unless text is False.
    """
    records = []
    stdout = stderr = b""
    try:
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
                                    assert tag == "ccf.cft"
                                    assert isinstance(timestamp, msgpack.ExtType)
                                    assert timestamp.code == 0
                                    seconds, nanos = struct.unpack(
                                        ">II", timestamp.data
                                    )
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
                    [str(pathlib.Path(driver).resolve()), scenario, host, str(port)],
                    capture_output=True,
                    timeout=timeout,
                    check=False,
                )
                stdout, stderr = result.stdout, result.stderr
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b"", error.stderr or b""
                raise
            finally:
                done.set()
                collector.join(timeout + 1)
            assert not collector.is_alive(), "Collector failed to stop"
        if errors:
            raise errors[0]
        if result.returncode == 0:
            assert records, f"No cft trace records captured for {scenario}"
        for sequence, record in enumerate(records):
            assert (
                record["h_ts"] == sequence
            ), "Missing, duplicate or reordered trace sequence"
            assert record["process_id"] == records[0]["process_id"]
        return (
            subprocess.CompletedProcess(
                result.args,
                result.returncode,
                stdout.decode("utf-8") if text else stdout,
                stderr.decode("utf-8") if text else stderr,
            ),
            records,
        )
    except Exception as error:
        raise CaptureError(error, stdout, stderr, records) from error
