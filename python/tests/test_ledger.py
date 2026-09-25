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
