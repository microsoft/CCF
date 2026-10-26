# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Fixture refresh retains native bytes, sequence coordinates and provenance."""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from refresh_fixtures import copy_fixture


class RefreshFixturesTests(unittest.TestCase):
    def test_committed_capture_slices(self):
        fixtures = Path(__file__).with_name("fixtures")
        fragments = [
            fixtures / name
            for name in (
                "bootstrap.ndjson",
                "configuration_callback.ndjson",
                "missing_prefix_response.ndjson",
            )
        ]
        prefix = b"".join(path.read_bytes() for path in fragments)
        self.assertTrue(
            (fixtures / "drop_resend.ndjson").read_bytes().startswith(prefix)
        )
        for path in sorted(fixtures.iterdir()):
            if path.name == "terminal_retirement.stdout":
                continue
            with self.subTest(fixture=path.name):
                records = [json.loads(line) for line in path.read_bytes().splitlines()]
                self.assertTrue(records)
                first = records[0]["h_ts"]
                for sequence, record in enumerate(records, first):
                    self.assertEqual(record["tag"], "ccf.raft_trace")
                    self.assertEqual(record["process_id"], records[0]["process_id"])
                    self.assertEqual(record["h_ts"], sequence)
                    message = record["msg"]
                    self.assertNotIn("cmd", record)
                    self.assertNotIn("args", message)
                    if message.get("function") in ("commit", "add_configuration"):
                        self.assertIn("idx", message)
                    if message.get("function") == "add_configuration":
                        self.assertIn("nodes", message)

    def test_preserves_native_slice(self):
        records = [
            {
                "tag": "ccf.raft_trace",
                "process_id": "native-process",
                "h_ts": sequence,
                "msg": {
                    "function": "commit",
                    "idx": sequence,
                    "unused": {"future": True},
                },
            }
            for sequence in range(3)
        ]
        lines = [(json.dumps(record) + "\r\n").encode() for record in records]
        source = b"".join(lines)
        selected = b"".join(lines[1:])
        original = Path("captures/events.stdout")
        with (
            patch.object(Path, "read_bytes", side_effect=[source, selected, source]),
            patch.object(Path, "write_bytes") as write,
        ):
            origin = copy_fixture("commit.ndjson", original, 1, None, Path("fixtures"))
        write.assert_called_once_with(selected)
        self.assertEqual(origin["first_line"], 2)
        self.assertEqual(origin["last_line"], 3)
        self.assertEqual(origin["fixture_sha256"], hashlib.sha256(selected).hexdigest())
        self.assertEqual(origin["capture_sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(origin["capture"], str(original.resolve()))

    def test_rejects_legacy_without_rewriting(self):
        for source in (
            b'{"tag":"raft_trace","cmd":"start_node,0"}\n',
            b'{"tag":"ccf.raft_trace"}\n{"tag":"raft_trace","msg":{}}\n',
            b"",
        ):
            with (
                self.subTest(source=source),
                patch.object(Path, "read_bytes", return_value=source),
                patch.object(Path, "write_bytes") as write,
            ):
                with self.assertRaisesRegex(ValueError, "ccf.raft_trace"):
                    copy_fixture(
                        "fixture.ndjson", Path("native.stdout"), 0, None, Path(".")
                    )
                write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
