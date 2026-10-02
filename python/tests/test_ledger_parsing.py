# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Regression tests for ledger and snapshot public domain parsing."""

import base64
import glob
import os
import struct

import ccf.ledger
import pytest

TABLE = "public:test"
TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "testdata")


def length_prefixed(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data


def public_domain_prefix(entry_type: ccf.ledger.EntryType) -> bytes:
    # entry type, version, max conflict version
    return bytes([entry_type.value]) + struct.pack("<qq", 1, 0)


def write_set_domain(
    writes: dict[bytes, bytes], removals: list[bytes], table: str = TABLE
) -> bytes:
    body = struct.pack("<qQQ", 0, 0, len(writes))  # read version, reads, writes
    for key, value in writes.items():
        body += length_prefixed(key) + length_prefixed(value)
    body += struct.pack("<Q", len(removals))
    for key in removals:
        body += length_prefixed(key)
    return (
        public_domain_prefix(ccf.ledger.EntryType.WRITE_SET)
        + length_prefixed(table.encode())
        + body
    )


def padded(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 8)


def snapshot_prefix() -> bytes:
    return (
        public_domain_prefix(ccf.ledger.EntryType.SNAPSHOT)
        + length_prefixed(b"\x00" * ccf.ledger.SHA256_DIGEST_SIZE)
        + length_prefixed(b"")  # view history
    )


def snapshot_domain(entries: dict[bytes, tuple[int, bytes]]) -> bytes:
    body = b""
    for key, (version, value) in entries.items():
        body += padded(length_prefixed(key))
        body += padded(length_prefixed(struct.pack("<q", version) + value))
    return (
        snapshot_prefix()
        + length_prefixed(TABLE.encode())
        + struct.pack("<qQ", 1, len(body))  # map version, map size
        + body
    )


def tables(domain: bytes) -> dict:
    return ccf.ledger.PublicDomain(domain).get_tables()


class TestTruncatedDomain:
    def test_complete_write_set_parses(self):
        domain = write_set_domain({b"k1": b"v1"}, [b"k2"])
        assert tables(domain) == {TABLE: {b"k1": b"v1", b"k2": None}}

    @pytest.mark.parametrize("missing", [1, 2, 3])
    def test_truncated_removal_key_rejected(self, missing: int):
        domain = write_set_domain({}, [b"key"])[:-missing]
        with pytest.raises(ValueError, match="Insufficient public domain data"):
            ccf.ledger.PublicDomain(domain)

    @pytest.mark.parametrize("missing", [1, 5])
    def test_truncated_write_value_rejected(self, missing: int):
        domain = write_set_domain({b"key": b"value"}, [])[:-missing]
        with pytest.raises(ValueError, match="Insufficient public domain data"):
            ccf.ledger.PublicDomain(domain)

    def test_oversized_declared_length_rejected(self):
        # One removal whose declared key length far exceeds the remaining bytes
        domain = write_set_domain({}, [])[:-8] + struct.pack("<QQ", 1, 2**40) + b"k"
        with pytest.raises(ValueError, match="Insufficient public domain data"):
            ccf.ledger.PublicDomain(domain)

    def test_truncated_snapshot_padding_rejected(self):
        domain = snapshot_domain({b"key": (1, b"v")})
        # Drop the trailing padding of the last value
        with pytest.raises(ValueError, match="Insufficient public domain data"):
            ccf.ledger.PublicDomain(domain[:-1])

    def test_truncated_table_name_rejected(self):
        domain = public_domain_prefix(ccf.ledger.EntryType.WRITE_SET)
        domain += struct.pack("<Q", 20) + b"public:short"
        with pytest.raises(ValueError, match="Insufficient public domain data"):
            ccf.ledger.PublicDomain(domain)


class TestSnapshotTombstone:
    def test_values_parse(self):
        domain = snapshot_domain({b"a": (1, b"x"), b"bb": (2**40, b"yyyyyyyyy")})
        assert tables(domain) == {TABLE: {b"a": b"x", b"bb": b"yyyyyyyyy"}}

    @pytest.mark.parametrize("version", [-1, -(2**40), -(2**63)])
    def test_negative_version_not_retained(self, version: int):
        domain = snapshot_domain({b"gone": (version, b""), b"kept": (3, b"v")})
        assert tables(domain) == {TABLE: {b"kept": b"v"}}

    def test_zero_version_is_a_value(self):
        assert tables(snapshot_domain({b"k": (0, b"")})) == {TABLE: {b"k": b""}}

    def test_negative_version_payload_skipped(self):
        # The node drops the entry without inspecting its payload
        domain = snapshot_domain({b"gone": (-1, b"stale"), b"kept": (3, b"v")})
        assert tables(domain) == {TABLE: {b"kept": b"v"}}


# Serialised KV snapshots from the "Old snapshots" test case in
# src/kv/test/kv_snapshot.cpp. "Tombstone deletions" records the deletion of
# "baz" as an entry with version -2; "True deletions" omits the key.
LEGACY_KV_SNAPSHOTS = {
    "tombstone_deletions": (
        "AQDYAAAAAADQAAAAAAAAAAECAAAAAAAAAAAAAAAAAAAADgAAAAAAAABwdWJsaWM6bnVtX21h"
        "cAIAAAAAAAAAKAAAAAAAAAACAAAAAAAAADQyAAAAAAAACwAAAAAAAAACAAAAAAAAADEyMwAA"
        "AAAAEQAAAAAAAABwdWJsaWM6c3RyaW5nX21hcAIAAAAAAAAASAAAAAAAAAAFAAAAAAAAACJi"
        "YXoiAAAACAAAAAAAAAD+/////////"
        "wUAAAAAAAAAImZvbyIAAAANAAAAAAAAAAEAAAAAAAAAImJhciIAAAA="
    ),
    "true_deletions": (
        "AQC4AAAAAACwAAAAAAAAAAECAAAAAAAAAAAAAAAAAAAADgAAAAAAAABwdWJsaWM6bnVtX21h"
        "cAIAAAAAAAAAKAAAAAAAAAACAAAAAAAAADQyAAAAAAAACwAAAAAAAAACAAAAAAAAADEyMwAA"
        "AAAAEQAAAAAAAABwdWJsaWM6c3RyaW5nX21hcAIAAAAAAAAAKAAAAAAAAAAFAAAAAAAAACJm"
        "b28iAAAADQAAAAAAAAABAAAAAAAAACJiYXIiAAAA"
    ),
}


def legacy_kv_snapshot_maps(raw_b64: str) -> bytes:
    # These were serialised without an encryptor or history, so hold no GCM
    # header, hash at snapshot, or view history. Keep only the serialised
    # maps, which follow the entry type, version and max conflict version.
    raw = base64.b64decode(raw_b64)
    header = ccf.ledger.TransactionHeader(
        raw[: ccf.ledger.TransactionHeader.get_size()]
    )
    assert len(raw) == ccf.ledger.TransactionHeader.get_size() + header.size
    (public_domain_size,) = struct.unpack_from("<Q", raw, 8)
    public_domain = raw[16 : 16 + public_domain_size]
    assert len(public_domain) == public_domain_size
    assert ccf.ledger.EntryType(public_domain[0]) == ccf.ledger.EntryType.SNAPSHOT
    return public_domain[1 + 8 + 8 :]


@pytest.mark.parametrize("name", sorted(LEGACY_KV_SNAPSHOTS))
def test_legacy_kv_snapshot_matches_node(name: str):
    maps = legacy_kv_snapshot_maps(LEGACY_KV_SNAPSHOTS[name])
    assert (struct.pack("<q", -2) in maps) == (name == "tombstone_deletions")
    # Same outcome as the C++ test: "foo" is present, "baz" is not
    assert tables(snapshot_prefix() + maps) == {
        "public:num_map": {b"42": b"123"},
        "public:string_map": {b'"foo"': b'"bar"'},
    }


class TestPeek:
    def test_peek_restores_cursor(self):
        buffer = ccf.ledger.SimpleBuffer("test", b"0123456789", at_loc=3)
        assert ccf.ledger._peek(buffer, 2, pos=7) == b"78"
        assert buffer.tell() == 3
        assert ccf.ledger._peek(buffer, 2) == b"34"
        assert buffer.tell() == 3

    @pytest.mark.parametrize(("pos", "size"), [(7, 4), (10, 1), (None, 8)])
    def test_failed_peek_restores_cursor(self, pos: int | None, size: int):
        buffer = ccf.ledger.SimpleBuffer("test", b"0123456789", at_loc=3)
        with pytest.raises(ValueError, match="Failed to read precise number"):
            ccf.ledger._peek(buffer, size, pos=pos)
        assert buffer.tell() == 3

    def test_peek_all_restores_cursor(self):
        buffer = ccf.ledger.SimpleBuffer("test", b"0123456789", at_loc=3)
        assert ccf.ledger._peek_all(buffer, pos=8) == b"89"
        assert buffer.tell() == 3
        assert ccf.ledger._peek_all(buffer) == b"3456789"
        assert buffer.tell() == 3


class InMemoryTransaction:
    def __init__(self, seqno: int, domain: bytes):
        self._seqno = seqno
        self._domain = ccf.ledger.PublicDomain(domain)
        self._domain._version = seqno

    def get_public_domain(self) -> ccf.ledger.PublicDomain:
        return self._domain


class InMemoryLedger(ccf.ledger.Ledger):
    def __init__(self, domains: list[bytes]):
        self._transactions = [
            InMemoryTransaction(seqno, domain)
            for seqno, domain in enumerate(domains, start=1)
        ]

    def __iter__(self):
        yield self._transactions


class TestLatestPublicState:
    def test_first_write_with_deletion(self):
        ledger = InMemoryLedger([write_set_domain({b"a": b"1"}, [b"b"])])
        assert ledger.get_latest_public_state() == ({TABLE: {b"a": b"1"}}, 1)

    def test_deletion_only_first_write(self):
        ledger = InMemoryLedger([write_set_domain({}, [b"b"])])
        assert ledger.get_latest_public_state() == ({TABLE: {}}, 1)

    def test_write_then_delete(self):
        ledger = InMemoryLedger(
            [
                write_set_domain({b"a": b"1", b"b": b"2"}, []),
                write_set_domain({b"c": b"3"}, [b"a"]),
            ]
        )
        assert ledger.get_latest_public_state() == (
            {TABLE: {b"b": b"2", b"c": b"3"}},
            2,
        )

    def test_delete_then_rewrite(self):
        ledger = InMemoryLedger(
            [
                write_set_domain({b"a": b"1"}, []),
                write_set_domain({}, [b"a"]),
                write_set_domain({b"a": b"2"}, []),
            ]
        )
        assert ledger.get_latest_public_state() == ({TABLE: {b"a": b"2"}}, 3)

    def test_transaction_tables_not_mutated(self):
        first = write_set_domain({b"a": b"1"}, [])
        ledger = InMemoryLedger([first, write_set_domain({b"b": b"2"}, [b"a"])])
        state, _ = ledger.get_latest_public_state()
        assert state == {TABLE: {b"b": b"2"}}
        assert ledger._transactions[0].get_public_domain().get_tables() == {
            TABLE: {b"a": b"1"}
        }


def fixture_services() -> list[str]:
    if not os.path.isdir(TESTDATA_DIR):
        return []
    return sorted(
        service
        for service in os.listdir(TESTDATA_DIR)
        if os.path.isdir(os.path.join(TESTDATA_DIR, service, "ledger"))
    )


@pytest.mark.parametrize("service", fixture_services())
def test_fixture_service_parses(service: str):
    ledger_dir = os.path.join(TESTDATA_DIR, service, "ledger")
    transactions = 0
    for chunk in ccf.ledger.Ledger(
        [ledger_dir],
        committed_only=False,
        verification_level=ccf.ledger.VerificationLevel.FULL,
    ):
        for transaction in chunk:
            transaction.get_public_domain().get_tables()
            transactions += 1
    assert transactions > 0

    state, seqno = ccf.ledger.Ledger(
        [ledger_dir], committed_only=False
    ).get_latest_public_state()
    assert seqno == transactions
    assert all(
        value is not None for table in state.values() for value in table.values()
    )

    for path in glob.glob(os.path.join(TESTDATA_DIR, service, "snapshots", "*")):
        with ccf.ledger.Snapshot(path) as snapshot:
            assert len(snapshot.get_public_domain().get_tables()) > 0
