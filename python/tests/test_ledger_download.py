# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Harness regression tests runnable with both released and development SDKs."""

import importlib.util
import json
import struct
from pathlib import Path
from unittest.mock import Mock, patch

import ccf.ledger
import ccf.signatures
import pytest

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "infra_ledger", ROOT / "tests" / "infra" / "ledger.py"
)
assert SPEC is not None
assert SPEC.loader is not None
LEDGER_INFRA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER_INFRA)

FIXTURE_DIR = ROOT / "tests" / "testdata" / "cose_upgraded_service" / "ledger"


def chunk_data(start: int, end: int) -> bytes:
    """Build a self-contained chunk from the requested real fixture transactions."""
    ledger = ccf.ledger.Ledger(
        [
            str(FIXTURE_DIR / "ledger_1-2.committed"),
            str(FIXTURE_DIR / "ledger_3-12.committed"),
        ]
    )
    transactions = [
        tx for tx in ledger.transactions() if start <= tx.get_txid().seqno <= end
    ]
    assert [tx.get_txid().seqno for tx in transactions] == list(range(start, end + 1))

    entries = bytearray()
    positions = []
    for tx in transactions:
        positions.append(ccf.ledger.LEDGER_HEADER_SIZE + len(entries))
        entries.extend(tx.get_raw_tx())
    return (
        struct.pack("<Q", ccf.ledger.LEDGER_HEADER_SIZE + len(entries))
        + entries
        + b"".join(struct.pack("<I", position) for position in positions)
    )


def transaction_with_tables(seqno: int, tables: dict) -> Mock:
    transaction = Mock(spec=ccf.ledger.Transaction)
    transaction.get_transaction_header.return_value = ccf.ledger.LedgerChunk(
        str(FIXTURE_DIR / "ledger_1-2.committed")
    )[0].get_transaction_header()
    public_domain = transaction.get_public_domain.return_value
    public_domain.get_tables.return_value = tables
    public_domain.get_seqno.return_value = seqno
    public_domain.is_deprecated.return_value = False
    transaction.get_tx_digest.return_value = bytes(ccf.ledger.SHA256_DIGEST_SIZE)
    return transaction


@pytest.mark.parametrize(
    "status, certificate",
    [("Pending", None), ("Trusted", b"test-only certificate")],
)
def test_validator_accepts_node_removal(status, certificate):
    validator = LEDGER_INFRA.LedgerValidator()
    assert validator.verification_level == ccf.ledger.VerificationLevel.FULL
    tables = {
        ccf.ledger.NODES_TABLE_NAME: {b"n1": json.dumps({"status": status}).encode()}
    }
    if certificate is not None:
        tables[ccf.ledger.ENDORSED_NODE_CERTIFICATES_TABLE_NAME] = {b"n1": certificate}
    validator.add_transaction(transaction_with_tables(1, tables))
    if status == "Pending":
        with pytest.raises(ccf.signatures.UntrustedNodeException, match="Pending"):
            validator._verify_signing_node_status("n1")
        with pytest.raises(KeyError):
            validator.node_certificates["n1"]

    validator.add_transaction(
        transaction_with_tables(
            2,
            {
                ccf.ledger.NODES_TABLE_NAME: {b"n1": None},
                ccf.ledger.ENDORSED_NODE_CERTIFICATES_TABLE_NAME: {b"n1": None},
            },
        )
    )
    assert validator.transaction_count == 2
    assert validator.node_certificates == {}
    assert validator.node_activity_status == {}
    with pytest.raises(KeyError):
        validator.node_certificates["n1"]
    with pytest.raises(ccf.signatures.UntrustedNodeException, match="not part"):
        validator._verify_signing_node_status("n1")


def test_validator_preserves_full_signature_verification():
    original = ccf.ledger.LedgerValidator()
    compatible = LEDGER_INFRA.LedgerValidator()
    ledger = ccf.ledger.Ledger(
        [
            str(FIXTURE_DIR / "ledger_1-2.committed"),
            str(FIXTURE_DIR / "ledger_3-12.committed"),
        ]
    )
    for tx in ledger.transactions():
        original.add_transaction(tx)
        compatible.add_transaction(tx)
    assert compatible.last_verified_txid() == original.last_verified_txid()
    assert compatible.last_verified_txid().seqno == 12
    assert compatible.signature_count == original.signature_count == 4
    assert compatible.node_certificates == original.node_certificates
    assert compatible.node_activity_status == original.node_activity_status


def test_validator_rejects_corrupted_signature_history():
    validator = LEDGER_INFRA.LedgerValidator()
    transactions = list(
        ccf.ledger.Ledger([str(FIXTURE_DIR / "ledger_1-2.committed")]).transactions()
    )
    with (
        patch.object(
            transactions[0],
            "get_tx_digest",
            return_value=bytes(ccf.ledger.SHA256_DIGEST_SIZE),
        ),
        pytest.raises(
            (
                ccf.signatures.InvalidRootException,
                ccf.signatures.InvalidRootSignatureException,
                ccf.signatures.InvalidRootCoseSignatureException,
            )
        ),
    ):
        for tx in transactions:
            validator.add_transaction(tx)


def test_nulled_entry_is_rejected(tmp_path):
    data = bytearray(chunk_data(1, 2))
    start = ccf.ledger.LEDGER_HEADER_SIZE
    nulled_size = (
        ccf.ledger.TransactionHeader.get_size()
        + ccf.ledger.GCM_SIZE_TAG
        + ccf.ledger.GCM_SIZE_IV
        + ccf.ledger.LEDGER_DOMAIN_SIZE
    )
    data[start : start + nulled_size] = bytes(nulled_size)
    path = tmp_path / "ledger_1-2.committed"
    path.write_bytes(data)
    expected_error = (
        "is smaller than the minimum entry size"
        if hasattr(ccf.ledger, "MIN_ENTRY_SIZE")
        else "index out of range"
    )
    with pytest.raises((IndexError, ValueError), match=expected_error):
        for tx in ccf.ledger.LedgerChunk(str(path)):
            tx.get_public_domain()


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("ledger_42", (42, None)),
        ("ledger_42-100", (42, 100)),
        ("ledger_42-100.committed", (42, 100)),
        ("ledger_42-100.committed.recovery", (42, 100)),
        ("ledger_42-100.committed_prefix", (42, 100)),
        ("ledger_01-002.committed_prefix", (1, 2)),
        ("ledger_42-42.committed_prefix", (42, 42)),
        ("download/ledger_42-100.committed_prefix", (42, 100)),
    ],
)
def test_filename_ranges(filename, expected):
    assert LEDGER_INFRA.range_from_filename(filename) == expected


@pytest.mark.parametrize(
    "filename",
    [
        "ledger_0-100.committed_prefix",
        "ledger_42-41.committed_prefix",
        "ledger_42.committed_prefix",
        "ledger_ledger_42-100.committed_prefix",
        "ledger_42x-100.committed_prefix",
        "ledger_42-100.committed_prefix.recovery",
        "ledger_-1-100.committed_prefix",
        "ledger_\u0661-100.committed_prefix",
    ],
)
def test_invalid_prefix_ranges(filename):
    with pytest.raises(ValueError):
        LEDGER_INFRA.range_from_filename(filename)


def test_save_multiple_canonical_chunks(tmp_path):
    paths = []
    for start, end in ((1, 2), (3, 12)):
        name = f"ledger_{start}-{end}.committed"
        data = chunk_data(start, end)
        assert LEDGER_INFRA.save_chunk(str(tmp_path), paths, name, data, start) == end
        assert (tmp_path / name).read_bytes() == data

    assert [Path(path).name for path in paths] == [
        "ledger_1-2.committed",
        "ledger_3-12.committed",
    ]
    assert [
        tx.get_txid().seqno for tx in ccf.ledger.Ledger(paths).transactions()
    ] == list(range(1, 13))


def test_save_adjacent_prefixes(tmp_path):
    paths = []
    for start, end in ((1, 2), (3, 12)):
        name = f"ledger_{start}-{end}.committed_prefix"
        data = chunk_data(start, end)
        assert LEDGER_INFRA.save_chunk(str(tmp_path), paths, name, data, start) == end
        assert (tmp_path / name).read_bytes() == data

    assert [Path(path).name for path in paths] == [
        "ledger_1-2.committed_prefix",
        "ledger_3-12.committed_prefix",
    ]
    seqnos = []
    for path in paths:
        with LEDGER_INFRA.open_chunk(path) as chunk:
            assert not chunk.is_committed()
            seqnos.extend(tx.get_txid().seqno for tx in chunk)
    assert seqnos == list(range(1, 13))


@pytest.mark.parametrize("suffix", [".committed", ".committed_prefix"])
def test_replacement_removes_only_superseded_prefixes(tmp_path, suffix):
    paths = []
    for start, end, original_suffix in (
        (1, 2, ".committed"),
        (3, 5, ".committed_prefix"),
        (6, 12, ".committed_prefix"),
    ):
        name = f"ledger_{start}-{end}{original_suffix}"
        LEDGER_INFRA.save_chunk(
            str(tmp_path), paths, name, chunk_data(start, end), start
        )

    replacement = f"ledger_3-12{suffix}"
    assert (
        LEDGER_INFRA.save_chunk(
            str(tmp_path), paths, replacement, chunk_data(3, 12), 12
        )
        == 12
    )
    assert [Path(path).name for path in paths] == [
        "ledger_1-2.committed",
        replacement,
    ]
    seqnos = []
    for path in paths:
        with LEDGER_INFRA.open_chunk(path) as chunk:
            seqnos.extend(tx.get_txid().seqno for tx in chunk)
    assert seqnos == list(range(1, 13))


@pytest.mark.parametrize(
    "name, requested_seqno",
    [
        ("ledger_1-2.committed", 0),
        ("ledger_1-2.committed", 3),
        ("ledger_1-2.committed_prefix", 0),
        ("ledger_1-2.committed_prefix", 3),
        ("ledger_1", 1),
    ],
)
def test_chunk_must_cover_requested_seqno(tmp_path, name, requested_seqno):
    paths = []
    with pytest.raises(AssertionError, match="does not cover seqno"):
        LEDGER_INFRA.save_chunk(str(tmp_path), paths, name, b"", requested_seqno)
    assert paths == []
    assert list(tmp_path.iterdir()) == []


def test_saved_chunk_uses_basename(tmp_path):
    paths = []
    name = "ledger_1-2.committed_prefix"
    data = chunk_data(1, 2)
    LEDGER_INFRA.save_chunk(str(tmp_path), paths, f"../{name}", data, 1)
    assert paths == [str(tmp_path / name)]
    assert (tmp_path / name).read_bytes() == data


@pytest.mark.parametrize("suffix", [".committed", ".committed_prefix", ""])
def test_open_chunk_preserves_bytes_and_commit_status(tmp_path, suffix):
    path = tmp_path / f"ledger_3-5{suffix}"
    data = chunk_data(3, 5)
    path.write_bytes(data)

    with LEDGER_INFRA.open_chunk(str(path)) as chunk:
        decoded_path = Path(chunk.filename())
        assert decoded_path.read_bytes() == data
        assert chunk.get_seqnos() == (3, 5)
        assert len(chunk) == 3
        assert chunk.is_complete()
        assert chunk.is_committed() == (suffix == ".committed")
        assert [tx.get_txid().seqno for tx in chunk] == [3, 4, 5]

    assert path.read_bytes() == data
    if suffix == ".committed_prefix":
        assert not decoded_path.exists()
    else:
        assert decoded_path == path


def test_open_chunk_cleans_up_on_error(tmp_path):
    path = tmp_path / "ledger_1-2.committed_prefix"
    data = chunk_data(1, 2)
    path.write_bytes(data)

    with (
        pytest.raises(RuntimeError, match="reader failed"),
        LEDGER_INFRA.open_chunk(str(path)) as chunk,
    ):
        decoded_path = Path(chunk.filename())
        raise RuntimeError("reader failed")
    assert not decoded_path.exists()
    assert path.read_bytes() == data
