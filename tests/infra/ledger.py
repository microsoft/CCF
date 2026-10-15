# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compatibility helpers for ledger chunks downloaded by end-to-end tests."""

import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

import ccf.ledger

COMMITTED_PREFIX_FILE_SUFFIX = ".committed_prefix"


class _NodeCertificates(dict):
    """Allow ledger tombstones for certificates which were never present."""

    def pop(self, key, default=None):
        return super().pop(key, default)


class LedgerValidator(ccf.ledger.LedgerValidator):
    """Keep SDK verification with idempotent node-certificate removals."""

    def __init__(
        self,
        accept_deprecated_entry_types: bool = True,
        verification_level: ccf.ledger.VerificationLevel = ccf.ledger.VerificationLevel.FULL,
    ):
        super().__init__(
            accept_deprecated_entry_types=accept_deprecated_entry_types,
            verification_level=verification_level,
        )
        self.node_certificates = _NodeCertificates(self.node_certificates)


def range_from_filename(filename: str) -> tuple[int, int | None]:
    basename = os.path.basename(filename)
    if not basename.endswith(COMMITTED_PREFIX_FILE_SUFFIX):
        return ccf.ledger.range_from_filename(filename)

    name = basename.removesuffix(COMMITTED_PREFIX_FILE_SUFFIX)
    if re.fullmatch(r"ledger_[0-9]+-[0-9]+", name) is None:
        raise ValueError(f"Could not read seqno range from ledger file {filename}")

    start, end = ccf.ledger.range_from_filename(name)
    if start == 0 or end is None or end < start:
        raise ValueError(f"Could not read seqno range from ledger file {filename}")
    return start, end


def save_chunk(
    ledger_dir: str,
    ledger_paths: list[str],
    chunk_name: str,
    data: bytes,
    requested_seqno: int,
) -> int:
    chunk_name = os.path.basename(chunk_name)
    start_seqno, end_seqno = range_from_filename(chunk_name)
    assert (
        end_seqno is not None and start_seqno <= requested_seqno <= end_seqno
    ), f"Ledger chunk {chunk_name} does not cover seqno {requested_seqno}"

    chunk_path = os.path.join(ledger_dir, chunk_name)
    with open(chunk_path, "wb") as chunk_file:
        chunk_file.write(data)

    # A canonical chunk may replace prefixes downloaded before its promotion.
    while (
        ledger_paths
        and ledger_paths[-1].endswith(COMMITTED_PREFIX_FILE_SUFFIX)
        and range_from_filename(ledger_paths[-1])[0] >= start_seqno
    ):
        ledger_paths.pop()
    ledger_paths.append(chunk_path)
    return end_seqno


@contextmanager
def open_chunk(filename: str) -> Iterator[ccf.ledger.LedgerChunk]:
    """Decode prefix bytes without requiring prefix filename support in the SDK."""
    basename = os.path.basename(filename)
    if not basename.endswith(COMMITTED_PREFIX_FILE_SUFFIX):
        yield ccf.ledger.LedgerChunk(filename)
        return

    range_from_filename(filename)
    with tempfile.TemporaryDirectory() as ledger_dir:
        # Prefix bytes use the existing chunk format. A closed-range filename
        # without a suffix is understood by older SDKs and remains uncommitted.
        chunk_path = os.path.join(
            ledger_dir, basename.removesuffix(COMMITTED_PREFIX_FILE_SUFFIX)
        )
        shutil.copyfile(filename, chunk_path)
        yield ccf.ledger.LedgerChunk(chunk_path)
