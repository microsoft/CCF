# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import raft_trace
import raft_trace_capture
from raft_scenarios_runner import preprocess_for_trace_validation

import msgpack


def pack_record(record):
    return msgpack.packb(
        ["ccf.raft_trace", msgpack.ExtType(0, struct.pack(">II", 1, 0)), record]
    )


def write_driver(root, wire, stdout, stderr, returncode=0, delay=0):
    driver = root / "driver"
    driver.with_suffix(".msgpack").write_bytes(wire)
    driver.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, socket, sys, time\n"
        "wire = pathlib.Path(__file__).with_suffix('.msgpack').read_bytes()\n"
        "if wire:\n"
        "    with socket.create_connection((sys.argv[-2], int(sys.argv[-1]))) as peer:\n"
        "        peer.sendall(wire)\n"
        f"os.write(1, {stdout!r})\n"
        f"os.write(2, {stderr!r})\n"
        f"time.sleep({delay!r})\n"
        f"sys.exit({returncode!r})\n",
        encoding="utf-8",
    )
    driver.chmod(0o755)
    return driver


class CaptureTests(unittest.TestCase):
    def collect(self, sequences):
        def driver(args, **_):
            with socket.create_connection((args[-2], int(args[-1]))) as peer:
                for sequence in sequences:
                    peer.sendall(
                        pack_record(
                            {
                                "process_id": "one",
                                "h_ts": sequence,
                                "msg": {"cmd": "state_all"},
                            }
                        )
                    )
            return subprocess.CompletedProcess(args, 0, b"native stdout\n", b"")

        with patch("raft_trace.subprocess.run", side_effect=driver):
            return raft_trace.run_driver("driver", "scenario")

    def test_preserves_order_and_rejects_gaps(self):
        _, records = self.collect([0, 1, 2])
        self.assertEqual([row["h_ts"] for row in records], [0, 1, 2])
        for sequences in ([1, 0], [0, 0], [0, 2], [1]):
            with self.subTest(sequences=sequences), self.assertRaisesRegex(
                raft_trace.CaptureError, "trace sequence"
            ):
                self.collect(sequences)

    def test_real_success_preserves_caller_contract(self):
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            driver = write_driver(root, pack_record(record), b"native\r\n\x00", b"")
            result, records = raft_trace.run_driver(driver, root / "scenario")
            self.assertEqual(result.stdout, "native\r\n\x00")
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(records, [record])

    def test_binary_diagnostics_do_not_constrain_structured_capture(self):
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        for stdout, stderr in (
            (b"native progress\xff\n", b"stderr before failure\r\n"),
            (b"native progress\r\n", b"stderr before failure\xff\n"),
        ):
            with self.subTest(
                stdout=stdout, stderr=stderr
            ), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                driver = write_driver(root, pack_record(record), stdout, stderr)
                output = root / "capture.stdout"
                raft_trace_capture.capture(driver, root / "scenario", output)
                self.assertEqual(
                    pathlib.Path(str(output) + ".driver.stdout").read_bytes(),
                    stdout,
                )
                self.assertEqual(
                    pathlib.Path(str(output) + ".driver.stderr").read_bytes(),
                    stderr,
                )
                self.assertEqual(
                    [json.loads(line) for line in output.read_text().splitlines()],
                    [{"tag": "ccf.raft_trace", **record}],
                )

    def test_text_consumers_still_reject_invalid_encoding(self):
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            driver = write_driver(root, pack_record(record), b"\xff", b"")
            with self.assertRaises(raft_trace.CaptureError) as failure:
                raft_trace.run_driver(driver, root / "scenario")
            self.assertIsInstance(failure.exception.__cause__, UnicodeError)
            self.assertEqual(failure.exception.stdout, b"\xff")
            self.assertEqual(failure.exception.records, [record])

    def test_partial_transport_and_sequence_failures_preserve_records(self):
        first = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        second = {**first, "h_ts": 1}
        gap = {**first, "h_ts": 2}
        packer = msgpack.Packer()
        duplicate = (
            packer.pack_array_header(3)
            + packer.pack("ccf.raft_trace")
            + packer.pack(msgpack.ExtType(0, struct.pack(">II", 1, 0)))
            + packer.pack_map_header(4)
            + b"".join(
                packer.pack(key) + packer.pack(value)
                for key, value in [
                    ("process_id", "one"),
                    ("h_ts", 1),
                    ("msg", {"cmd": "state_all"}),
                    ("msg", {"cmd": "state_all"}),
                ]
            )
        )
        for name, suffix, received, diagnostic in (
            ("malformed", b"\xc1", [first], "FormatError"),
            ("truncated", pack_record(second)[:-1], [first], "Truncated"),
            ("sequence", pack_record(gap), [first, gap], "trace sequence"),
            ("duplicate", duplicate, [first], "Duplicate"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                stdout, stderr = b"native progress\r\n", b"transport diagnostic\n"
                driver = write_driver(root, pack_record(first) + suffix, stdout, stderr)
                output = root / "capture.stdout"
                with self.assertRaisesRegex(
                    raft_trace.CaptureError, diagnostic
                ) as failure:
                    raft_trace_capture.capture(driver, root / "scenario", output)
                self.assertEqual(failure.exception.records, received)
                self.assertFalse(output.exists())
                self.assertEqual(
                    pathlib.Path(str(output) + ".driver.stdout").read_bytes(), stdout
                )
                self.assertEqual(
                    pathlib.Path(str(output) + ".driver.stderr").read_bytes(), stderr
                )
                self.assertEqual(
                    [
                        json.loads(line)
                        for line in output.with_suffix(".partial")
                        .read_text()
                        .splitlines()
                    ],
                    [{"tag": "ccf.raft_trace", **record} for record in received],
                )

    def test_subprocess_timeout_preserves_partial_evidence(self):
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stdout, stderr = b"native progress\r\n", b"timeout diagnostic\xff\n"
            driver = write_driver(root, pack_record(record), stdout, stderr, delay=2)
            output = root / "capture.stdout"
            with self.assertRaises(raft_trace.CaptureError) as failure:
                raft_trace_capture.capture(
                    driver, root / "scenario", output, timeout=0.5
                )
            self.assertIsInstance(
                failure.exception.__cause__, subprocess.TimeoutExpired
            )
            self.assertEqual(failure.exception.records, [record])
            self.assertFalse(output.exists())
            self.assertEqual(
                pathlib.Path(str(output) + ".driver.stdout").read_bytes(), stdout
            )
            self.assertEqual(
                pathlib.Path(str(output) + ".driver.stderr").read_bytes(), stderr
            )

    def test_serialization_failure_preserves_unsupported_values(self):
        first = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        second = {
            **first,
            "h_ts": 1,
            "msg": {"cmd": msgpack.ExtType(7, b"unsupported")},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            driver = write_driver(
                root, pack_record(first) + pack_record(second), b"native\n", b""
            )
            output = root / "capture.stdout"
            with self.assertRaises(TypeError):
                raft_trace_capture.capture(driver, root / "scenario", output)
            self.assertFalse(output.exists())
            self.assertEqual(
                msgpack.unpackb(
                    pathlib.Path(str(output) + ".driver.records.msgpack").read_bytes(),
                    raw=False,
                ),
                [first, second],
            )
            self.assertEqual(
                [
                    json.loads(line)
                    for line in output.with_suffix(".partial").read_text().splitlines()
                ],
                [{"tag": "ccf.raft_trace", **first}],
            )

    def test_spawn_failure_retains_empty_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "capture.stdout"
            with self.assertRaises(raft_trace.CaptureError) as failure:
                raft_trace_capture.capture(
                    root / "missing-driver", root / "scenario", output
                )
            self.assertIsInstance(failure.exception.__cause__, FileNotFoundError)
            self.assertEqual(failure.exception.records, [])
            self.assertFalse(output.exists())
            for path in (
                pathlib.Path(str(output) + ".driver.stdout"),
                pathlib.Path(str(output) + ".driver.stderr"),
                output.with_suffix(".partial"),
            ):
                self.assertEqual(path.read_bytes(), b"")

    def test_native_failures_publish_only_partial_records(self):
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        for stderr in (b"diagnostic\r\n", b"diagnostic\xff\n"):
            with self.subTest(
                stderr=stderr
            ), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                driver = write_driver(
                    root,
                    pack_record(record),
                    b"native\r\n\x00",
                    stderr,
                    3,
                )
                output = root / "capture.stdout"
                with self.assertRaisesRegex(RuntimeError, "exited 3"):
                    raft_trace_capture.capture(driver, root / "scenario", output)
                self.assertFalse(output.exists())
                self.assertEqual(
                    pathlib.Path(str(output) + ".driver.stdout").read_bytes(),
                    b"native\r\n\x00",
                )
                self.assertEqual(
                    pathlib.Path(str(output) + ".driver.stderr").read_bytes(),
                    stderr,
                )
                self.assertEqual(
                    [
                        json.loads(line)
                        for line in output.with_suffix(".partial")
                        .read_text()
                        .splitlines()
                    ],
                    [{"tag": "ccf.raft_trace", **record}],
                )

    def test_cli_attempts_remaining_after_collection_failure(self):
        record = {"process_id": "one", "h_ts": 0, "msg": {"cmd": "state_all"}}
        error = raft_trace.CaptureError(
            ValueError("transport failure"), b"native\xff", b"", [record]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scenarios, output = root / "scenarios", root / "output"
            scenarios.mkdir()
            for name in ("01-fail", "02-next"):
                (scenarios / name).write_text("scenario")
            with patch(
                "sys.argv",
                ["capture", str(scenarios), str(output), "--driver", "driver"],
            ), patch(
                "raft_trace.run_driver",
                side_effect=[
                    error,
                    (subprocess.CompletedProcess([], 0, b"native", b""), [record]),
                ],
            ), self.assertRaisesRegex(
                RuntimeError, "1/2 scenarios failed"
            ):
                raft_trace_capture.main()
            self.assertFalse((output / "01-fail.stdout").exists())
            self.assertTrue((output / "01-fail.partial").exists())
            self.assertTrue((output / "02-next.stdout").exists())
            self.assertEqual(
                (output / "01-fail.stdout.driver.stdout").read_bytes(), b"native\xff"
            )

    def test_output_ancestor_is_rejected_before_touching_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scenarios = root / "inventory"
            (scenarios / "inventory").mkdir(parents=True)
            (scenarios / "inventory/victim").write_text("scenario")
            victim = scenarios / "victim.stdout"
            victim.write_bytes(b"protected input\xff")
            with patch(
                "sys.argv", ["capture", str(scenarios), str(root), "--driver", "driver"]
            ), self.assertRaisesRegex(ValueError, "disjoint"):
                raft_trace_capture.main()
            self.assertEqual(victim.read_bytes(), b"protected input\xff")

    def test_duplicate_keys_fail(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            raft_trace.unique_map([("msg", 1), ("msg", 2)])

    def test_writes_records_without_protocol_mapping(self):
        result, records = self.collect([0, 1])
        result = subprocess.CompletedProcess(
            result.args,
            result.returncode,
            result.stdout.encode(),
            result.stderr.encode(),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "nested" / "trace.stdout"
            with patch("raft_trace.run_driver", return_value=(result, records)):
                raft_trace_capture.capture("driver", "scenario", output)
            observed = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(
                observed, [{"tag": "ccf.raft_trace", **r} for r in records]
            )
            self.assertEqual(
                pathlib.Path(str(output) + ".driver.stdout").read_bytes(), result.stdout
            )

    def test_legacy_adapter_preserves_callback_order(self):
        command = {"cmd": "periodic_one,0,10"}
        callback = {"function": "send_append_entries"}
        records = [
            {"process_id": "one", "h_ts": index, "msg": message}
            for index, message in enumerate((command, callback))
        ]
        self.assertEqual(
            raft_trace.as_log_lines(records),
            [
                {"tag": "raft_trace", **command},
                {"tag": "raft_trace", "h_ts": "1", "msg": callback},
            ],
        )

    def test_legacy_adapter_supplies_native_pre_vote_without_mutating_records(self):
        source = pathlib.Path(__file__).resolve().parents[1]
        fixture = source / "lean/ccf-raft/replay/tests/fixtures/startup.ndjson"
        records = [json.loads(line) for line in fixture.read_text().splitlines()]
        original = json.dumps(records, sort_keys=True)
        legacy = raft_trace.as_log_lines(records)
        trace = preprocess_for_trace_validation([json.dumps(row) for row in legacy])
        self.assertTrue(trace)
        for line in trace:
            self.assertIs(json.loads(line)["msg"]["state"]["pre_vote_enabled"], True)
        self.assertEqual(json.dumps(records, sort_keys=True), original)
        for record in records:
            if "state" in record["msg"]:
                self.assertNotIn("pre_vote_enabled", record["msg"]["state"])

    def test_failed_capture_cannot_leave_success_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scenarios = root / "scenarios"
            scenarios.mkdir()
            (scenarios / "one").touch()
            output = root / "output"
            output.mkdir()
            trace = output / "one.stdout"
            trace.write_text("stale success")
            result = subprocess.CompletedProcess([], 1, b"native failure", b"")
            with (
                patch(
                    "sys.argv",
                    ["capture", str(scenarios), str(output), "--driver", "driver"],
                ),
                patch("raft_trace.run_driver", return_value=(result, [])),
                self.assertRaisesRegex(RuntimeError, "1/1 scenarios failed"),
            ):
                raft_trace_capture.main()
            self.assertFalse(trace.exists())
            self.assertTrue((output / "one.partial").exists())
            self.assertEqual(
                (output / "one.stdout.driver.stdout").read_text(), "native failure"
            )


if __name__ == "__main__":
    unittest.main()
