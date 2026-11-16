# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Unit tests for CCF ledger filename handling."""

import ccf.ledger
import pytest


def test_committed_prefix_filename_range():
    """Committed-prefix names expose their closed sequence-number range."""
    assert ccf.ledger.range_from_filename("ledger_42-100.committed_prefix") == (42, 100)


def test_committed_prefix_is_not_canonical_committed_file():
    """Committed prefixes stay excluded from committed-only discovery."""
    assert not ccf.ledger.is_ledger_chunk_committed("ledger_42-100.committed_prefix")


def test_ledger_directory_ignores_committed_prefix(tmp_path):
    """Committed prefixes are never discovered as part of a ledger directory."""
    (tmp_path / "ledger_42-100.committed_prefix").write_bytes(b"")

    assert len(ccf.ledger.Ledger([str(tmp_path)])) == 0
    assert len(ccf.ledger.Ledger([str(tmp_path)], committed_only=False)) == 0
    assert (
        len(
            ccf.ledger.Ledger(
                [str(tmp_path)], committed_only=False, read_recovery_files=True
            )
        )
        == 0
    )


@pytest.mark.parametrize(
    "filename",
    [
        "ledger_0-100.committed_prefix",
        "ledger_42-41.committed_prefix",
        "ledger_42.committed_prefix",
        "ledger_ledger_42-100.committed_prefix",
        "ledger_42x-100.committed_prefix",
        "ledger_42-100.committed_prefix.recovery",
    ],
)
def test_committed_prefix_filename_rejects_invalid_ranges(filename: str):
    """Committed-prefix names must contain one valid, closed range."""
    with pytest.raises(ValueError):
        ccf.ledger.range_from_filename(filename)


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("ledger_1", (1, None)),
        ("ledger_0", (0, None)),
        ("ledger_42-100", (42, 100)),
        ("ledger_42-42.committed", (42, 42)),
        ("ledger_42-100.committed.recovery", (42, 100)),
        ("ledger_42.recovery", (42, None)),
        ("/path/to/ledger_42-100.committed", (42, 100)),
    ],
)
def test_filename_range(filename: str, expected: tuple[int, int | None]):
    """Ordinary ledger chunk names expose their sequence-number range."""
    assert ccf.ledger.range_from_filename(filename) == expected


@pytest.mark.parametrize(
    "filename",
    [
        "0",
        "42-100",
        "ledger_42-41",
        "ledger_42-41.committed",
        "ledger_ledger_42-100",
        "chunk_ledger_42-100",
        "ledger_-42",
        "ledger_+42-100",
        "ledger_ 42-100",
        "ledger_4_2-100",
        "ledger_\u0664\u0662-100",
        "ledger_42-100-101",
        "ledger_42-",
        "ledger_",
        "ledger_42-100.ignored",
    ],
)
def test_filename_range_rejects_invalid_names(filename: str):
    """Ordinary ledger chunk names must contain ASCII decimal, ordered seqnos."""
    with pytest.raises(ValueError):
        ccf.ledger.range_from_filename(filename)


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("snapshot_10_11", (10, 11)),
        ("snapshot_10_11.committed", (10, 11)),
        ("/path/to/snapshot_10_11.committed", (10, 11)),
    ],
)
def test_snapshot_index(filename: str, expected: tuple[int, int]):
    """Snapshot names expose their seqno and evidence seqno."""
    assert ccf.ledger.snapshot_index_from_filename(filename) == expected


@pytest.mark.parametrize(
    "filename",
    [
        "10_11",
        "snapshot_-1_2",
        "snapshot_+5_6",
        "snapshot_5_ 6",
        "snapshot_\u0665_6",
        "snapshot_5_6_7",
        "snapshot_5_6.committed_7",
        "snapshot_snapshot_5_6",
        "snapshot_5",
    ],
)
def test_snapshot_index_rejects_invalid_names(filename: str):
    """Snapshot names must contain two ASCII decimal indices."""
    with pytest.raises(ValueError):
        ccf.ledger.snapshot_index_from_filename(filename)
