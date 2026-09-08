# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import infra.interfaces
from infra.node import Node


class SnapshotFilesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.writable = self.root / "snapshots"
        self.read_only = self.root / "snapshots.ro"
        self.writable.mkdir()
        self.read_only.mkdir()
        self.node = Node(0, infra.interfaces.HostSpec(rpc_interfaces={}))
        self.node.remote = SimpleNamespace(
            remote=SimpleNamespace(root=str(self.root)),
            snapshots_dir_name=self.writable.name,
            read_only_snapshots_dir_name=self.read_only.name,
        )
        self.node.common_dir = str(self.root / "common")
        self.node.client = Mock(side_effect=AssertionError("Unexpected HTTP request"))

    def tearDown(self):
        self.node.client.assert_not_called()
        self.assertFalse(Path(self.node.common_dir).exists())

    def snapshot(self, name, directory=None):
        path = (directory if directory is not None else self.writable) / name
        path.write_bytes(b"snapshot")
        return str(path)

    def test_committed_files_in_sequence_order(self):
        newer = self.snapshot("snapshot_100_101.committed")
        older = self.snapshot("snapshot_20_21.committed")
        self.snapshot("snapshot_200_201")
        self.snapshot("snapshot_300_301.committed.ignored")
        self.snapshot("not_a_snapshot.committed")
        (self.writable / "snapshot_400_401.committed").mkdir()
        self.assertEqual(self.node.get_snapshots(), [older, newer])

    def test_read_only_is_explicit_and_preserves_paths(self):
        name = "snapshot_20_21.committed"
        writable = self.snapshot(name)
        read_only = self.snapshot(name, self.read_only)
        self.assertEqual(self.node.get_snapshots(), [writable])
        self.assertEqual(
            self.node.get_snapshots(include_read_only=True), [writable, read_only]
        )
        self.node.remote.read_only_snapshots_dir_name = None
        self.assertEqual(self.node.get_snapshots(include_read_only=True), [writable])

    def test_missing_directory_is_empty(self):
        self.writable.rmdir()
        self.assertEqual(self.node.get_snapshots(), [])

    def test_wait_uses_snapshot_state_not_evidence(self):
        self.snapshot("snapshot_20_100.committed")
        target = self.snapshot("snapshot_30_101.committed")
        self.assertEqual(self.node.wait_for_snapshot(30, timeout=0), target)
        with self.assertRaises(TimeoutError):
            self.node.wait_for_snapshot(31, timeout=0)

    def test_wait_is_pinned_to_writable_directory(self):
        self.snapshot("snapshot_100_101.committed", self.read_only)
        other_node = self.root / "other_node"
        other_node.mkdir()
        self.snapshot("snapshot_100_101.committed", other_node)
        with self.assertRaisesRegex(TimeoutError, "node 0.*seqno 100"):
            self.node.wait_for_snapshot(100, timeout=0)

    def test_wait_observes_commit_rename(self):
        pending = Path(self.snapshot("snapshot_20_21"))
        committed = pending.with_name(pending.name + ".committed")
        with patch(
            "infra.node.time.sleep", side_effect=lambda _: pending.rename(committed)
        ) as sleep:
            self.assertEqual(self.node.wait_for_snapshot(20, timeout=1), str(committed))
        sleep.assert_called_once()

    def test_filesystem_errors_propagate(self):
        with (
            patch("infra.node.os.scandir", side_effect=PermissionError("denied")),
            self.assertRaises(PermissionError),
        ):
            self.node.get_snapshots()

    def test_wait_timeout_is_not_restarted(self):
        with (
            patch("infra.node.time.monotonic", side_effect=[0, 0.9, 1]),
            patch("infra.node.time.sleep") as sleep,
            self.assertRaises(TimeoutError),
        ):
            self.node.wait_for_snapshot(20, timeout=1)
        sleep.assert_called_once()
        self.assertAlmostEqual(sleep.call_args.args[0], 0.1)


if __name__ == "__main__":
    unittest.main()
