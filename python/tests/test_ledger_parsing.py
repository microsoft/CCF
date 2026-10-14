# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Regression tests for ledger and snapshot public domain parsing."""

import base64
import glob
import json
import os
import struct

import ccf.ledger
import pytest

TABLE = "public:test"
TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "testdata")


def length_prefixed(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data


def public_domain_prefix(entry_type: ccf.ledger.EntryType, version: int = 1) -> bytes:
    # entry type, version, max conflict version
    return bytes([entry_type.value]) + struct.pack("<qq", version, 0)


def table_write_set(
    table: str, writes: dict[bytes, bytes], removals: list[bytes]
) -> bytes:
    body = struct.pack("<qQQ", 0, 0, len(writes))  # read version, reads, writes
    for key, value in writes.items():
        body += length_prefixed(key) + length_prefixed(value)
    body += struct.pack("<Q", len(removals))
    for key in removals:
        body += length_prefixed(key)
    return length_prefixed(table.encode()) + body


def write_set_domain(
    writes: dict[bytes, bytes],
    removals: list[bytes],
    table: str = TABLE,
    version: int = 1,
) -> bytes:
    return public_domain_prefix(
        ccf.ledger.EntryType.WRITE_SET, version
    ) + table_write_set(table, writes, removals)


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

    @pytest.mark.parametrize(
        ("version", "payload"),
        [(-1, b""), (-(2**40), b""), (-(2**63), b""), (-1, b"stale")],
    )
    def test_negative_version_not_retained(self, version: int, payload: bytes):
        # The node drops the entry without inspecting its payload
        domain = snapshot_domain({b"gone": (version, payload), b"kept": (3, b"v")})
        assert tables(domain) == {TABLE: {b"kept": b"v"}}

    def test_zero_version_is_a_value(self):
        assert tables(snapshot_domain({b"k": (0, b"")})) == {TABLE: {b"k": b""}}


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


def gcm_header(seqno: int, view: int = 2) -> bytes:
    return b"\x00" * ccf.ledger.GCM_SIZE_TAG + struct.pack("<QI", seqno, view)


def entry(
    seqno: int,
    writes: dict[bytes, bytes],
    private: bytes = b"",
    declared_size: int | None = None,
    declared_domain_size: int | None = None,
    version: int = ccf.ledger.ENTRY_FORMAT_V1,
    domain: bytes | None = None,
) -> bytes:
    if domain is None:
        domain = write_set_domain(writes, [], version=seqno)
    if declared_domain_size is None:
        declared_domain_size = len(domain)
    body = (
        gcm_header(seqno) + struct.pack("<Q", declared_domain_size) + domain + private
    )
    if declared_size is None:
        declared_size = len(body)
    return bytes([version, 0]) + declared_size.to_bytes(6, "little") + body


def transaction(data: bytes) -> ccf.ledger.Transaction:
    return ccf.ledger.Transaction(ccf.ledger.SimpleBuffer("test", data))


def header(
    size: int, version: int = ccf.ledger.ENTRY_FORMAT_V1, flags: int = 0
) -> ccf.ledger.TransactionHeader:
    return ccf.ledger.TransactionHeader(
        bytes([version, flags]) + size.to_bytes(6, "little")
    )


class TestEntryFraming:
    def test_well_formed_entry(self):
        tx = transaction(entry(1, {b"a": b"1"}, private=b"\x01" * 5))
        assert tx.get_public_domain().get_tables() == {TABLE: {b"a": b"1"}}
        assert tx.get_private_domain_size() == 5

    @pytest.mark.parametrize("size", [0, 1, ccf.ledger.MIN_ENTRY_SIZE - 1])
    def test_entry_smaller_than_fixed_fields_rejected(self, size: int):
        # Data for a full entry is present, only the declared size is too small
        data = entry(1, {b"a": b"1"}, declared_size=size)
        with pytest.raises(ValueError, match="smaller than the minimum entry size"):
            transaction(data)

    @pytest.mark.parametrize("short_by", [1, 8])
    def test_public_domain_exceeding_entry_rejected(self, short_by: int):
        domain_size = len(write_set_domain({b"a": b"1"}, []))
        data = entry(
            1,
            {b"a": b"1"},
            declared_size=ccf.ledger.MIN_ENTRY_SIZE + domain_size - short_by,
        )
        # Bytes from a following entry must not be read as the public domain
        data += entry(2, {b"b": b"2"})
        with pytest.raises(ValueError, match="exceeds remaining entry size"):
            transaction(data)

    @pytest.mark.parametrize("missing", [1, 8, 40])
    def test_entry_beyond_end_of_data_rejected(self, missing: int):
        data = entry(1, {b"a": b"1"}, private=b"\x01" * 40)
        with pytest.raises(ValueError, match="bytes are available"):
            transaction(data[:-missing])


class TestTransactionHeaderValidation:
    validate = staticmethod(ccf.ledger.LedgerValidator.validate_transaction_header)

    def test_valid_header(self):
        self.validate(header(ccf.ledger.MIN_ENTRY_SIZE))

    @pytest.mark.parametrize("version", [0, 2, 3, 4, 5, 255])
    def test_only_format_version_1_accepted(self, version: int):
        # The node only deserialises entry_format_v1 (src/kv/serialised_entry_format.h)
        with pytest.raises(ValueError, match="Invalid transaction version"):
            self.validate(header(ccf.ledger.MIN_ENTRY_SIZE, version=version))

    @pytest.mark.parametrize("size", [0, 1, ccf.ledger.MIN_ENTRY_SIZE - 1])
    def test_size_below_fixed_fields_rejected(self, size: int):
        with pytest.raises(ValueError, match="smaller than the minimum entry size"):
            self.validate(header(size))

    def test_unknown_flags_rejected(self):
        with pytest.raises(ValueError, match="Invalid transaction flags"):
            self.validate(header(ccf.ledger.MIN_ENTRY_SIZE, flags=0x80))


NODES_TABLE = ccf.ledger.NODES_TABLE_NAME
ENDORSED_CERTIFICATES_TABLE = ccf.ledger.ENDORSED_NODE_CERTIFICATES_TABLE_NAME


def node_info(status: str) -> bytes:
    return json.dumps({"status": status}).encode()


def governance_transaction(seqno: int, *write_sets: bytes) -> ccf.ledger.Transaction:
    domain = public_domain_prefix(ccf.ledger.EntryType.WRITE_SET, seqno) + b"".join(
        write_sets
    )
    return transaction(entry(seqno, {}, domain=domain))


def node_removal(seqno: int, node_id: bytes) -> ccf.ledger.Transaction:
    # InternalTablesAccess::remove_nodes (src/node/internal_tables_access.h)
    # removes the node's endorsed certificate alongside its node info
    return governance_transaction(
        seqno,
        table_write_set(NODES_TABLE, {}, [node_id]),
        table_write_set(ENDORSED_CERTIFICATES_TABLE, {}, [node_id]),
    )


class TestNodeRemoval:
    """
    Full verification must accept every node removal the service writes.
    """

    @staticmethod
    def full_validator() -> ccf.ledger.LedgerValidator:
        return ccf.ledger.LedgerValidator(
            verification_level=ccf.ledger.VerificationLevel.FULL
        )

    def test_trusted_node_removal(self):
        validator = self.full_validator()
        validator.add_transaction(
            governance_transaction(
                1,
                table_write_set(NODES_TABLE, {b"n1": node_info("Trusted")}, []),
                table_write_set(ENDORSED_CERTIFICATES_TABLE, {b"n1": b"cert"}, []),
            )
        )
        assert validator.node_certificates == {"n1": b"cert"}
        validator.add_transaction(node_removal(2, b"n1"))
        assert validator.node_certificates == {}
        assert "n1" not in validator.node_activity_status

    def test_pending_node_removal(self):
        # Pending nodes are removed when they expire (pending_node_timeout) and
        # by disaster recovery, but never had an endorsed certificate written.
        # The KV serialises the removal of the absent key regardless.
        validator = self.full_validator()
        validator.add_transaction(
            governance_transaction(
                1, table_write_set(NODES_TABLE, {b"n1": node_info("Pending")}, [])
            )
        )
        validator.add_transaction(node_removal(2, b"n1"))
        assert validator.node_certificates == {}
        assert "n1" not in validator.node_activity_status


def write_chunk(directory: str, name: str, entries: list[bytes], cut: int = 0) -> str:
    # An uncommitted chunk: zero positions-table offset, no positions table
    data = (0).to_bytes(ccf.ledger.LEDGER_HEADER_SIZE, "little") + b"".join(entries)
    if cut:
        data = data[:-cut]
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


class TestTornChunkTail:
    """
    An uncommitted chunk whose last entry was only partially written.

    The node drops such an entry when it opens the chunk (LedgerFile in
    src/host/ledger.h) and the public state must not include it.
    """

    first = entry(1, {b"a": b"1"}, private=b"\x01" * 16)
    second = entry(2, {b"b": b"2"}, private=b"\x02" * 32)

    def test_complete_chunk(self, tmp_path):
        write_chunk(tmp_path, "ledger_1", [self.first, self.second])
        ledger = ccf.ledger.Ledger([str(tmp_path)], committed_only=False)
        assert ledger.get_latest_public_state() == (
            {TABLE: {b"a": b"1", b"b": b"2"}},
            2,
        )

    @pytest.mark.parametrize("cut", [1, 16, 32])
    def test_torn_private_domain_rejected(self, tmp_path, cut: int):
        path = write_chunk(tmp_path, "ledger_1", [self.first, self.second], cut=cut)
        chunk = ccf.ledger.LedgerChunk(path)
        assert chunk[0].get_public_domain().get_tables() == {TABLE: {b"a": b"1"}}
        with pytest.raises(ValueError, match="bytes are available"):
            chunk[1]

    @pytest.mark.parametrize("cut", [1, 32, 33, 60, len(second) - 8])
    def test_torn_entry_excluded_from_public_state(self, tmp_path, cut: int):
        write_chunk(tmp_path, "ledger_1", [self.first, self.second], cut=cut)
        ledger = ccf.ledger.Ledger([str(tmp_path)], committed_only=False)
        assert ledger.get_latest_public_state() == ({TABLE: {b"a": b"1"}}, 1)


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
