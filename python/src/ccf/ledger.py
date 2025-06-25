# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import struct
import os
from enum import Enum

from typing import NamedTuple, Optional, Tuple, Dict, List

import json
import base64
from dataclasses import dataclass
import functools

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils, ec

from ccf.merkletree import MerkleTree
from ccf.tx_id import TxID
from ccf.cose import validate_cose_sign1
import ccf.receipt
from hashlib import sha256

GCM_SIZE_TAG = 16
GCM_SIZE_IV = 12
LEDGER_DOMAIN_SIZE = 8
LEDGER_HEADER_SIZE = 8

# Public table names as defined in CCF
SIGNATURE_TX_TABLE_NAME = "public:ccf.internal.signatures"
COSE_SIGNATURE_TX_TABLE_NAME = "public:ccf.internal.cose_signatures"
NODES_TABLE_NAME = "public:ccf.gov.nodes.info"
ENDORSED_NODE_CERTIFICATES_TABLE_NAME = "public:ccf.gov.nodes.endorsed_certificates"
SERVICE_INFO_TABLE_NAME = "public:ccf.gov.service.info"

COMMITTED_FILE_SUFFIX = ".committed"
RECOVERY_FILE_SUFFIX = ".recovery"
IGNORED_FILE_SUFFIX = ".ignored"

# Key used by CCF to record single-key tables
WELL_KNOWN_SINGLETON_TABLE_KEY = bytes(bytearray(8))

SHA256_DIGEST_SIZE = sha256().digest_size


class NodeStatus(Enum):
    PENDING = "Pending"
    TRUSTED = "Trusted"
    RETIRED = "Retired"


class EntryType(Enum):
    WRITE_SET = 0
    SNAPSHOT = 1
    WRITE_SET_WITH_CLAIMS = 2
    WRITE_SET_WITH_COMMIT_EVIDENCE = 3
    WRITE_SET_WITH_COMMIT_EVIDENCE_AND_CLAIMS = 4

    def has_claims(self):
        return self in (
            EntryType.WRITE_SET_WITH_CLAIMS,
            EntryType.WRITE_SET_WITH_COMMIT_EVIDENCE_AND_CLAIMS,
        )

    def has_commit_evidence(self):
        return self in (
            EntryType.WRITE_SET_WITH_COMMIT_EVIDENCE,
            EntryType.WRITE_SET_WITH_COMMIT_EVIDENCE_AND_CLAIMS,
        )

    def is_deprecated(self):
        return self in (
            EntryType.WRITE_SET,
            EntryType.WRITE_SET_WITH_CLAIMS,
            EntryType.WRITE_SET_WITH_COMMIT_EVIDENCE,
        )


def to_uint_64(buffer):
    return struct.unpack("@Q", buffer)[0]


def is_ledger_chunk_committed(file_name):
    return file_name.endswith(COMMITTED_FILE_SUFFIX)


def is_snapshot_file_committed(file_name):
    return file_name.endswith(COMMITTED_FILE_SUFFIX)


def digest(data):
    return sha256(data).digest()


def unpack(stream, fmt):
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    if not buf:
        raise EOFError  # Reached end of stream
    return struct.unpack(fmt, buf)[0]


def unpack_array(buf, fmt):
    unpack_iter = struct.iter_unpack(fmt, buf)
    ret = []
    while True:
        try:
            ret.append(next(unpack_iter)[0])
        except StopIteration:
            break
    return ret


@functools.lru_cache(maxsize=64)
def spki_from_cert(cert: bytes) -> bytes:
    cert_obj = load_pem_x509_certificate(cert, default_backend())
    return cert_obj.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def range_from_filename(filename: str) -> Tuple[int, Optional[int]]:
    elements = (
        os.path.basename(filename)
        .replace(COMMITTED_FILE_SUFFIX, "")
        .replace(RECOVERY_FILE_SUFFIX, "")
        .replace("ledger_", "")
        .split("-")
    )
    if len(elements) == 2:
        return (int(elements[0]), int(elements[1]))
    elif len(elements) == 1:
        return (int(elements[0]), None)
    else:
        raise ValueError(f"Could not read seqno range from ledger file {filename}")


def snapshot_index_from_filename(filename: str) -> Tuple[int, int]:
    elements = (
        os.path.basename(filename)
        .replace(COMMITTED_FILE_SUFFIX, "")
        .replace("snapshot_", "")
        .split("_")
    )
    if len(elements) == 2:
        return (int(elements[0]), int(elements[1]))
    else:
        raise ValueError(f"Could not read snapshot index from file name {filename}")


class GcmHeader:
    view: int
    seqno: int

    def __init__(self, buffer):
        if len(buffer) < GcmHeader.size():
            raise ValueError("Corrupt GCM header")

        # _gcm_tag = buffer[:GCM_SIZE_TAG] # Unused
        _gcm_iv = buffer[GCM_SIZE_TAG : GCM_SIZE_TAG + GCM_SIZE_IV]

        self.seqno = struct.unpack("@Q", _gcm_iv[:8])[0]
        self.view = struct.unpack("@I", _gcm_iv[8:])[0] & 0x7FFFFFFF

    @staticmethod
    def size():
        return GCM_SIZE_TAG + GCM_SIZE_IV


class PublicDomain:
    """
    All public tables within a :py:class:`ccf.ledger.Transaction`.
    """

    _buffer: bytes
    _cursor: int
    _entry_type: EntryType
    _claims_digest: bytes
    _version: int
    _max_conflict_version: int
    _tables: dict

    def __init__(self, buffer: bytes):
        self._entry_type = EntryType(buffer[0])

        # Already read a 1-byte entry-type, so start from 1 not 0
        self._cursor = 1
        self._buffer = buffer

        self._version = self._read_int64()

        if self._entry_type.has_claims():
            self._claims_digest = self._read_buffer(SHA256_DIGEST_SIZE)

        if self._entry_type.has_commit_evidence():
            self._commit_evidence_digest = self._read_buffer(SHA256_DIGEST_SIZE)

        self._max_conflict_version = self._read_int64()

        if self._entry_type == EntryType.SNAPSHOT:
            self._read_snapshot_header()

        self._tables = {}
        self._read()

    def _read_buffer(self, size):
        prev_cursor = self._cursor
        self._cursor += size
        return self._buffer[prev_cursor : self._cursor]

    def _read8(self):
        return self._read_buffer(8)

    def _read_int64(self):
        return struct.unpack("<q", self._read8())[0]

    def _read_uint64(self):
        return struct.unpack("<Q", self._read8())[0]

    def is_deprecated(self):
        return self._entry_type.is_deprecated()

    def get_version_size(self):
        return 8

    def _read_versioned_value(self, size):
        if size < self.get_version_size():
            raise ValueError(f"Invalid versioned value of size {size}")
        return (self._read_uint64(), self._read_buffer(size - self.get_version_size()))

    def _read_next_entry(self):
        size = self._read_uint64()
        return self._read_buffer(size)

    def _read_string(self):
        return self._read_next_entry().decode()

    def _read_snapshot_header(self):
        # read hash of entry at snapshot
        hash_size = self._read_uint64()
        buffer = self._read_buffer(hash_size)
        self._hash_at_snapshot = buffer.hex()

        # read view history
        view_history_size = self._read_uint64()
        self._view_history = unpack_array(self._read_buffer(view_history_size), "<Q")

    def _read_snapshot_entry_padding(self, size):
        padding = -size % 8  # Padded to 8 bytes
        self._cursor += padding

    def _read_snapshot_key(self):
        size = self._read_uint64()
        key = self._read_buffer(size)
        self._read_snapshot_entry_padding(size)
        return key

    def _read_snapshot_versioned_value(self):
        size = self._read_uint64()
        ver, value = self._read_versioned_value(size)
        if ver < 0:
            assert (
                len(value) == 0
            ), f"Expected empty value for tombstone deletion at {ver}"
            value = None
        self._read_snapshot_entry_padding(size)
        return value

    def _read(self):
        buffer_size = len(self._buffer)
        while self._cursor < buffer_size:
            map_name = self._read_string()

            records = {}
            self._tables[map_name] = records

            if self._entry_type == EntryType.SNAPSHOT:
                # map snapshot version
                self._read8()

                # size of map entry
                map_size = self._read_uint64()
                start_map_pos = self._cursor

                while self._cursor - start_map_pos < map_size:
                    k = self._read_snapshot_key()
                    val = self._read_snapshot_versioned_value()
                    records[k] = val
            else:
                # read_version
                self._read8()

                # read_count
                # Note: Read keys are not currently included in ledger transactions
                read_count = self._read_uint64()
                assert read_count == 0, f"Unexpected read count: {read_count}"

                write_count = self._read_uint64()
                if write_count:
                    for _ in range(write_count):
                        k = self._read_next_entry()
                        val = self._read_next_entry()
                        records[k] = val

                remove_count = self._read_uint64()
                if remove_count:
                    for _ in range(remove_count):
                        k = self._read_next_entry()
                        records[k] = None

    def get_tables(self) -> dict:
        """
        Return a dictionary of all public tables (with their content) in a :py:class:`ccf.ledger.Transaction`.

        :return: Dictionary of public tables with their content.
        """
        return self._tables

    def get_seqno(self) -> int:
        """
        Return the sequence number at which the transaction was recorded in the ledger.
        """
        return self._version

    def get_claims_digest(self) -> Optional[bytes]:
        """
        Return the claims digest when there is one
        """
        return self._claims_digest if self._entry_type.has_claims() else None

    def get_commit_evidence_digest(self) -> Optional[bytes]:
        """
        Return the commit evidence digest when there is one
        """
        return (
            self._commit_evidence_digest
            if self._entry_type.has_commit_evidence()
            else None
        )


class SimpleBuffer:
    def __init__(self, name: str, buffer: bytes, at_loc: int = 0):
        self.name = name
        self._buffer = buffer
        self._loc = at_loc
        self._len = len(self._buffer)

    def _safe_loc(self, loc):
        return min(loc, self._len)

    def tell(self):
        return self._loc

    def read(self, size: Optional[int] = None):
        start = self._loc
        end = self._len
        if size is not None:
            end = self._safe_loc(start + size)
        self._loc = end
        return self._buffer[start:end]

    def seek(self, loc):
        self._loc = self._safe_loc(loc)
        return self._loc

    def clone(self, at_loc: int = 0):
        sb = SimpleBuffer(self.name, self._buffer, at_loc)
        return sb

    @staticmethod
    def from_file(filename):
        return SimpleBuffer(filename, open(filename, "rb").read())


def _byte_read_safe(file: SimpleBuffer, num_of_bytes):
    offset = file.tell()
    ret = file.read(num_of_bytes)
    if len(ret) != num_of_bytes:
        raise ValueError(
            f"Failed to read precise number of bytes at offset {offset}: {len(ret)}/{num_of_bytes}"
        )
    return ret


def _peek(file: SimpleBuffer, num_bytes, pos=None):
    save_pos = file.tell()
    if pos is not None:
        file.seek(pos)
    buffer = _byte_read_safe(file, num_bytes)
    file.seek(save_pos)
    return buffer


def _peek_all(file: SimpleBuffer, pos=None):
    save_pos = file.tell()
    if pos is not None:
        file.seek(pos)
    buffer = file.read()
    file.seek(save_pos)
    return buffer


class TxBundleInfo(NamedTuple):
    """Bundle for transaction information required for validation"""

    merkle_tree: MerkleTree
    existing_root: bytes
    node_cert: bytes
    signature: bytes
    node_activity: dict
    signing_node: str


class BaseValidator:
    @staticmethod
    def _verify_tx_bundle(tx_info: TxBundleInfo):
        """
        Verify items 1, 2, and 3 for all the transactions up until a signature.
        """
        # 1) The merkle root is signed by a Trusted node in the given network, else throws
        BaseValidator._verify_node_status(tx_info)
        # 2) The merkle root and signature are verified with the node cert, else throws
        BaseValidator._verify_root_signature(
            tx_info.node_cert, tx_info.existing_root, tx_info.signature
        )
        # 3) The merkle root is correct for the set of transactions and matches with the one extracted from the ledger, else throws
        BaseValidator._verify_merkle_root(tx_info.merkle_tree, tx_info.existing_root)

    @staticmethod
    def _verify_node_status(tx_info: TxBundleInfo):
        """Verify item 1, The merkle root is signed by a valid node in the given network"""
        if tx_info.signing_node not in tx_info.node_activity:
            raise UntrustedNodeException(
                f"The signing node {tx_info.signing_node} is not part of the network"
            )
        node_info = tx_info.node_activity[tx_info.signing_node]
        node_status = NodeStatus(node_info[0])
        # Note: Even nodes that are Retired, and for which retired_committed is True
        # may be issuing signatures, to ensure the liveness of a reconfiguring
        # network. They will stop doing so once the transaction that sets retired_committed is itself committed,
        # but that is unfortunately not observable from the ledger alone.
        if node_status == NodeStatus.PENDING:
            raise UntrustedNodeException(
                f"The signing node {tx_info.signing_node} has unexpected status {node_status.value}"
            )

    @staticmethod
    def _verify_root_signature(node_cert: bytes, root: bytes, signature: bytes):
        """Verify item 2, that the Merkle root signature validates against the node certificate"""
        try:
            cert = load_pem_x509_certificate(node_cert, default_backend())
            pub_key = cert.public_key()

            assert isinstance(pub_key, ec.EllipticCurvePublicKey)
            pub_key.verify(
                signature,
                root,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )  # type: ignore[override]
        # This exception is thrown from x509, catch for logging and raise our own
        except InvalidSignature:
            raise InvalidRootSignatureException(
                "Signature verification failed:"
                + f"\nCertificate: {node_cert.decode()}"
                + f"\nSignature: {base64.b64encode(signature).decode()}"
                + f"\nRoot: {root.hex()}"
            ) from InvalidSignature

    @staticmethod
    def _verify_root_cose_signature(service_cert, root, cose_sign1):
        try:
            cert = load_pem_x509_certificate(
                service_cert.encode("ascii"), default_backend()
            )
            validate_cose_sign1(
                cose_sign1=cose_sign1, pubkey=cert.public_key(), payload=root
            )
        except Exception as exc:
            raise InvalidRootCoseSignatureException(
                "Signature verification failed:"
                + f"\nCertificate: {service_cert}"
                + f"\nRoot: {root}"
            ) from exc

    @staticmethod
    def _verify_merkle_root(merkletree: MerkleTree, existing_root: bytes):
        """Verify item 3, by comparing the roots from the merkle tree that's maintained by this class and from the one extracted from the ledger"""
        root = merkletree.get_merkle_root()
        if root != existing_root:
            raise InvalidRootException(
                f"\nComputed root: {root.hex()} \nExisting root from ledger: {existing_root.hex()}"
            )


class LedgerValidator(BaseValidator):
    """
    Ledger Validator contains the logic to verify that the ledger hasn't been tampered with.
    It has the ability to take transactions and it maintains a MerkleTree data structure similar to CCF.

    Ledger is valid and hasn't been tampered with if following conditions are met:
        1) The merkle proof is signed by a Trusted node in the given network
        2) The merkle root and signature are verified with the node cert
        3) The merkle proof is correct for each set of transactions
    """

    accept_deprecated_entry_types: bool = True
    node_certificates: Dict[str, str] = {}
    node_activity_status: Dict[str, Tuple[str, int, bool]] = {}
    signature_count: int = 0

    def __init__(self, accept_deprecated_entry_types: bool = True):
        self.accept_deprecated_entry_types = accept_deprecated_entry_types

        # Start with empty bytes array. CCF MerkleTree uses an empty array as the first leaf of its merkle tree.
        # Don't hash empty bytes array.
        self.merkle = MerkleTree()
        empty_bytes_array = bytearray(SHA256_DIGEST_SIZE)
        self.merkle.add_leaf(empty_bytes_array, do_hash=False)

        self.last_verified_seqno = 0
        self.last_verified_view = 0

        self.service_status = None
        self.service_cert = None

    def last_verified_txid(self) -> TxID:
        return TxID(self.last_verified_view, self.last_verified_seqno)

    def add_transaction(self, transaction):
        """
        To validate the ledger, ledger transactions need to be added via this method.
        Depending on the tables that were part of the transaction, it does different things.
        When transaction contains signature table, it starts the verification process and verifies that the root of merkle tree was signed by a node which was part of the network.
        It also matches the root of the merkle tree that this class maintains with the one extracted from the ledger.
        Further, it validates all service status transitions.
        If any of the above checks fail, this method throws.
        """
        transaction_public_domain = transaction.get_public_domain()
        if not self.accept_deprecated_entry_types:
            assert not transaction_public_domain.is_deprecated()
        tables = transaction_public_domain.get_tables()

        # Add contributing nodes certs and update nodes network trust status for verification
        node_certs = {}
        if NODES_TABLE_NAME in tables:
            node_table = tables[NODES_TABLE_NAME]
            for node_id, node_info in node_table.items():
                node_id = node_id.decode()
                if node_info is None:
                    # Node has been removed from the store
                    self.node_activity_status.pop(node_id)
                    continue

                node_info = json.loads(node_info)
                # Add the self-signed node certificate (only available in 1.x,
                # refer to node endorsed certificates table otherwise)
                if "cert" in node_info:
                    node_certs[node_id] = node_info["cert"].encode()
                    self.node_certificates[node_id] = node_certs[node_id]
                # Update node trust status
                # Also record the seqno at which the node status changed to
                # track when a primary node should stop issuing signatures
                self.node_activity_status[node_id] = (
                    node_info["status"],
                    transaction_public_domain.get_seqno(),
                    node_info.get("retired_committed", False),
                )

        if ENDORSED_NODE_CERTIFICATES_TABLE_NAME in tables:
            node_endorsed_certificates_tables = tables[
                ENDORSED_NODE_CERTIFICATES_TABLE_NAME
            ]
            for (
                node_id,
                endorsed_node_cert,
            ) in node_endorsed_certificates_tables.items():
                node_id = node_id.decode()
                assert (
                    node_id not in node_certs
                ), f"Only one of node self-signed certificate and endorsed certificate should be recorded for node {node_id}"

                if endorsed_node_cert is None:
                    # Node has been removed from the store
                    self.node_certificates.pop(node_id)
                else:
                    self.node_certificates[node_id] = endorsed_node_cert

        # This is a merkle root/signature tx if the table exists
        if SIGNATURE_TX_TABLE_NAME in tables:
            self.signature_count += 1
            signature_table = tables[SIGNATURE_TX_TABLE_NAME]

            for _, signature in signature_table.items():
                signature = json.loads(signature)
                current_seqno = signature["seqno"]
                current_view = signature["view"]
                signing_node = signature["node"]

                # Get binary representations for the cert, existing root, and signature
                cert = self.node_certificates[signing_node]
                existing_root = bytes.fromhex(signature["root"])
                sig = base64.b64decode(signature["sig"])

                # Check that key in cert matches that in node table
                # when present
                if "cert" in signature:
                    sig_cert = signature["cert"].encode("utf-8")
                    assert spki_from_cert(cert) == spki_from_cert(
                        sig_cert
                    ), f"Mismatch in public key for node {signing_node}"

                tx_info = TxBundleInfo(
                    self.merkle,
                    existing_root,
                    cert,
                    sig,
                    self.node_activity_status,
                    signing_node,
                )

                # validations for 1, 2 and 3
                # throws if ledger validation failed.
                self._verify_tx_bundle(tx_info)

                self.last_verified_seqno = current_seqno
                self.last_verified_view = current_view

        # Check service status transitions
        if SERVICE_INFO_TABLE_NAME in tables:
            service_table = tables[SERVICE_INFO_TABLE_NAME]
            updated_service = service_table.get(WELL_KNOWN_SINGLETON_TABLE_KEY)
            updated_service_json = json.loads(updated_service)
            updated_status = updated_service_json["status"]
            if updated_status == "Opening":
                # DR can happen at any point, so a transition to "Opening" is always valid
                pass
            elif self.service_status == updated_status:
                pass
            elif self.service_status == "Opening":
                assert updated_status in [
                    "Open",
                    "WaitingForRecoveryShares",
                ], updated_status
            elif self.service_status == "Recovering":
                assert updated_status in ["WaitingForRecoveryShares"], updated_status
            elif self.service_status == "WaitingForRecoveryShares":
                assert updated_status in ["Open"], updated_status
            elif self.service_status == "Open":
                assert updated_status in ["Recovering"], updated_status
            else:
                assert self.service_status is None, self.service_status
            self.service_status = updated_status
            self.service_cert = updated_service_json["cert"]

        if COSE_SIGNATURE_TX_TABLE_NAME in tables:
            cose_signature_table = tables[COSE_SIGNATURE_TX_TABLE_NAME]
            cose_signature = cose_signature_table.get(WELL_KNOWN_SINGLETON_TABLE_KEY)
            signature = json.loads(cose_signature)
            cose_sign1 = base64.b64decode(signature)
            self._verify_root_cose_signature(
                self.service_cert, self.merkle.get_merkle_root(), cose_sign1
            )

        # Checks complete, add this transaction to tree
        self.merkle.add_leaf(transaction.get_tx_digest(), False)


@dataclass
class TransactionHeader:
    VERSION_LENGTH = 1
    FLAGS_LENGTH = 1
    SIZE_LENGTH = 6

    # 1-byte entry version
    version: int

    # 1-byte flags
    flags: int

    # 6-byte transaction size
    size: int

    def __init__(self, buffer):
        if len(buffer) != TransactionHeader.get_size():
            raise ValueError("Incomplete transaction header")

        self.version = int.from_bytes(
            buffer[: TransactionHeader.VERSION_LENGTH], byteorder="little"
        )

        end_of_flags = TransactionHeader.VERSION_LENGTH + TransactionHeader.FLAGS_LENGTH
        self.flags = int.from_bytes(
            buffer[TransactionHeader.VERSION_LENGTH : end_of_flags],
            byteorder="little",
        )
        end_of_size = end_of_flags + TransactionHeader.SIZE_LENGTH
        self.size = int.from_bytes(buffer[end_of_flags:end_of_size], byteorder="little")

    @staticmethod
    def get_size():
        return (
            TransactionHeader.VERSION_LENGTH
            + TransactionHeader.FLAGS_LENGTH
            + TransactionHeader.SIZE_LENGTH
        )


class Entry:
    _file: SimpleBuffer
    _header: TransactionHeader
    _public_domain_size: int = 0
    _public_domain: Optional[PublicDomain] = None
    _file_size: int = 0
    gcm_header: Optional[GcmHeader] = None

    def __init__(self, file: SimpleBuffer):
        if type(self) is Entry:
            raise TypeError("Entry is not instantiable")

        self._file = file

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def _read_header(self):
        # read the transaction header
        buffer = _byte_read_safe(self._file, TransactionHeader.get_size())
        self._header = TransactionHeader(buffer)
        entry_start_pos = self._file.tell()

        # read the AES GCM header
        buffer = _byte_read_safe(self._file, GcmHeader.size())
        self.gcm_header = GcmHeader(buffer)

        # read the size of the public domain
        buffer = _byte_read_safe(self._file, LEDGER_DOMAIN_SIZE)
        self._public_domain_size = to_uint_64(buffer)

        return entry_start_pos

    def get_txid(self) -> str:
        assert self.gcm_header is not None
        return f"{self.gcm_header.view}.{self.gcm_header.seqno}"

    def get_public_domain(self) -> PublicDomain:
        """
        Retrieve the public (i.e. non-encrypted) domain for that entry.

        Note: Even if the entry is private-only, an empty :py:class:`ccf.ledger.PublicDomain` object is returned.

        :return: :py:class:`ccf.ledger.PublicDomain`
        """
        if self._public_domain is None:
            buffer = _byte_read_safe(self._file, self._public_domain_size)
            self._public_domain = PublicDomain(buffer)
        return self._public_domain

    def get_private_domain_size(self) -> int:
        """
        Retrieve the size of the private (i.e. encrypted) domain for that transaction.
        """
        return self._header.size - (
            GcmHeader.size() + LEDGER_DOMAIN_SIZE + self._public_domain_size
        )

    def get_transaction_header(self) -> TransactionHeader:
        return self._header


class Transaction(Entry):
    """
    A transaction represents one entry in the CCF ledger.
    """

    _tx_offset: int = 0

    def __init__(self, file: SimpleBuffer):
        super().__init__(file)
        self._tx_offset = self._file.tell()
        super()._read_header()

    def get_raw_tx(self) -> bytes:
        """
        Return raw transaction bytes.

        :return: Raw transaction bytes.
        """
        assert self._file is not None

        return _peek(
            self._file,
            TransactionHeader.get_size() + self._header.size,
            pos=self._tx_offset,
        )

    def get_len(self) -> int:
        return len(self.get_raw_tx())

    def get_offsets(self) -> Tuple[int, int]:
        return (self._tx_offset, TransactionHeader.get_size() + self._header.size)

    def get_write_set_digest(self) -> bytes:
        return digest(self.get_raw_tx())

    def get_tx_digest(self) -> bytes:
        claims_digest = self.get_public_domain().get_claims_digest()
        commit_evidence_digest = self.get_public_domain().get_commit_evidence_digest()
        write_set_digest = self.get_write_set_digest()
        if claims_digest is None:
            if commit_evidence_digest is None:
                return write_set_digest
            else:
                return digest(write_set_digest + commit_evidence_digest)
        else:
            assert (
                commit_evidence_digest
            ), "Invalid transaction: commit_evidence_digest not set"
            return digest(write_set_digest + commit_evidence_digest + claims_digest)


class Snapshot(Entry):
    """
    Utility used to parse the content of a snapshot file.
    """

    _filename: str

    def __init__(self, filename: str):
        super().__init__(SimpleBuffer.from_file(filename))
        self._filename = filename
        self._file_size = os.path.getsize(filename)

        if self._file_size == 0:
            raise InvalidSnapshotException(f"{filename} is currently empty")

        entry_start_pos = super()._read_header()

        # 1.x snapshots do not include evidence
        if self.is_committed() and not self.is_snapshot_file_1_x():
            receipt_pos = entry_start_pos + self._header.size
            receipt_bytes = _peek_all(self._file, pos=receipt_pos)

            try:
                receipt = json.loads(receipt_bytes.decode("utf-8"))
            except json.decoder.JSONDecodeError as e:
                raise InvalidSnapshotException(
                    f"Cannot read receipt from snapshot {os.path.basename(self._filename)}: Receipt starts at {receipt_pos} (file is {self._file_size} bytes), and contains {receipt_bytes}"
                ) from e

            # Receipts included in snapshots always contain leaf components,
            # including a claims digest and commit evidence, from 2.0.0-rc0 onwards.
            # This verification code deliberately does not support snapshots
            # produced by 2.0.0-dev* releases.
            assert "leaf_components" in receipt
            write_set_digest = bytes.fromhex(
                receipt["leaf_components"]["write_set_digest"]
            )
            claims_digest = bytes.fromhex(receipt["leaf_components"]["claims_digest"])
            commit_evidence_digest = sha256(
                receipt["leaf_components"]["commit_evidence"].encode()
            ).digest()
            leaf = (
                sha256(write_set_digest + commit_evidence_digest + claims_digest)
                .digest()
                .hex()
            )
            root = ccf.receipt.root(leaf, receipt["proof"])
            node_cert = load_pem_x509_certificate(
                receipt["cert"].encode(), default_backend()
            )
            ccf.receipt.verify(root, receipt["signature"], node_cert)

    def is_committed(self):
        return COMMITTED_FILE_SUFFIX in self._filename

    def is_snapshot_file_1_x(self):
        # Kept here for compatibility
        if not self.is_committed():
            raise ValueError(f"Snapshot file {self._filename} is not yet committed")
        return len(self._filename.split(COMMITTED_FILE_SUFFIX)[1]) != 0

    def get_len(self) -> int:
        return self._file_size


class TransactionIterator:
    _positions: List[int]
    _buffer: SimpleBuffer
    _idx: int = -1

    def __init__(
        self,
        positions: List[int],
        buffer: SimpleBuffer,
    ):
        self._positions = positions
        self._buffer = buffer

    def __next__(self):
        self._idx += 1
        if len(self._positions) > self._idx:
            pos = self._positions[self._idx]
            return Transaction(self._buffer.clone(at_loc=pos))
        else:
            raise StopIteration


def find_tx_positions(file: SimpleBuffer, file_size: int) -> List[int]:
    pos = LEDGER_HEADER_SIZE
    ps = []
    while pos < file_size:
        ps.append(pos)
        file.seek(pos)
        buffer = _byte_read_safe(file, TransactionHeader.get_size())
        header = TransactionHeader(buffer)
        pos += header.size + TransactionHeader.get_size()
    return ps


def latest_snapshot(snapshots_dir):
    best_name, best_seqno = None, None
    for s in os.listdir(snapshots_dir):
        with ccf.ledger.Snapshot(os.path.join(snapshots_dir, s)) as snapshot:
            snapshot_seqno = snapshot.get_public_domain().get_seqno()
            if best_seqno is None or snapshot_seqno > best_seqno:
                best_name = s
                best_seqno = snapshot_seqno
    return best_name


class LedgerChunk:
    """
    Class used to parse and iterate over :py:class:`ccf.ledger.Transaction` in a CCF ledger chunk.

    :param str name: Name for a single ledger chunk.
    """

    _filename: str
    _file: SimpleBuffer

    def __init__(self, name: str):
        self._filename = name
        self._file = SimpleBuffer.from_file(name)

        self._pos_offset = int.from_bytes(
            _byte_read_safe(self._file, LEDGER_HEADER_SIZE), byteorder="little"
        )

        # If the ledger chunk is not yet committed, the ledger header will be empty.
        # Default to reading the file size instead.
        if self._pos_offset > 0:
            self._file_size = self._pos_offset

            positions_buffer = _peek_all(self._file, self._pos_offset)
            buf_len = len(positions_buffer)
            assert (
                buf_len % 4 == 0
            ), f"Expected positions to contain uint32s, but contains {buf_len} bytes"
            positions_count = buf_len // 4
            self._positions = [
                int.from_bytes(
                    positions_buffer[i * 4 : (i + 1) * 4],
                    byteorder="little",
                )
                for i in range(positions_count)
            ]
        else:
            self._file_size = os.path.getsize(name)
            self._positions = find_tx_positions(self._file, self._file_size)

        self.start_seqno, self.end_seqno = range_from_filename(name)

    def __getitem__(self, key):
        if isinstance(key, int):
            position = self._positions[key]
            return Transaction(self._file.clone(at_loc=position))
        elif isinstance(key, slice):
            positions = self._positions[key]
            transactions = []
            for p in positions:
                transactions.append(Transaction(self._file.clone(at_loc=p)))
            return transactions
        else:
            raise KeyError(f"Unsupported type ({type(key)}) passed to LedgerChunk[]")

    def __iter__(self):
        return TransactionIterator(
            self._positions,
            self._file,
        )

    def __len__(self):
        return len(self._positions)

    def filename(self):
        return self._filename

    def is_committed(self):
        return is_ledger_chunk_committed(self._filename)

    def is_complete(self):
        return self._pos_offset > 0

    def get_seqnos(self):
        return self.start_seqno, self.end_seqno


class ChunkIterator:
    _filenames: list
    _fileindex: int = -1
    _current_chunk: LedgerChunk

    def __init__(self, filenames: list, validator: Optional[LedgerValidator] = None):
        self._filenames = filenames

    def __next__(self) -> LedgerChunk:
        self._fileindex += 1
        if len(self._filenames) > self._fileindex:
            self._current_chunk = LedgerChunk(self._filenames[self._fileindex])
            return self._current_chunk
        else:
            raise StopIteration


class Ledger:
    """
    Class used to iterate over all :py:class:`ccf.ledger.LedgerChunk` stored in a CCF ledger folder.

    :param str name: Ledger directory for a single CCF node.
    """

    _filenames: list

    def __init__(
        self,
        paths: List[str],
        committed_only: bool = True,
        read_recovery_files: bool = False,
    ):
        self._filenames = []

        ledger_files: List[str] = []

        def try_add_chunk(path):
            sanitised_path = path
            if path.endswith(RECOVERY_FILE_SUFFIX):
                sanitised_path = path[: -len(RECOVERY_FILE_SUFFIX)]
                if not read_recovery_files:
                    return

            if path.endswith(IGNORED_FILE_SUFFIX):
                return

            if committed_only and not sanitised_path.endswith(COMMITTED_FILE_SUFFIX):
                return

            # The same ledger file may appear multiple times in different directories
            # so ignore duplicates
            if os.path.isfile(path) and not any(
                os.path.basename(path) in f for f in ledger_files
            ):
                ledger_files.append(path)

        for p in paths:
            if os.path.isdir(p):
                for path in os.listdir(p):
                    chunk = os.path.join(p, path)
                    try_add_chunk(chunk)
            elif os.path.isfile(p):
                try_add_chunk(p)
            else:
                raise ValueError(f"{p} is not a ledger directory or ledger chunk")

        # Sorts the list based off the first number after ledger_ so that
        # the ledger is verified in sequence
        self._filenames = sorted(
            ledger_files,
            key=lambda x: range_from_filename(x)[0],
        )

        # If we do not have a single contiguous range, report an error
        for file_a, file_b in zip(self._filenames[:-1], self._filenames[1:]):
            range_a = range_from_filename(file_a)
            range_b = range_from_filename(file_b)
            if range_a[1] is None and range_b[1] is not None:
                raise ValueError(
                    f"Ledger cannot parse committed chunk {file_b} following uncommitted chunk {file_a}"
                )
            if range_a[1] is not None and range_a[1] + 1 != range_b[0]:
                raise ValueError(
                    f"Ledger cannot parse non-contiguous chunks {file_a} and {file_b}"
                )

    @property
    def last_committed_chunk_range(self) -> Tuple[int, Optional[int]]:
        last_chunk_name = self._filenames[-1]
        return range_from_filename(last_chunk_name)

    def __len__(self):
        return len(self._filenames)

    def __getitem__(self, key):
        if isinstance(key, int):
            return LedgerChunk(self._filenames[key])
        elif isinstance(key, slice):
            files = self._filenames[key]
            return [LedgerChunk(file) for file in files]
        else:
            raise KeyError(f"Unsupported type ({type(key)}) passed to Ledger[]")

    def __iter__(self):
        return ChunkIterator(self._filenames)

    def transactions(self):
        for chunk in self:
            for transaction in chunk:
                yield transaction

    def get_transaction(self, seqno: int) -> Transaction:
        """
        Return the :py:class:`ccf.ledger.Transaction` recorded in the ledger at the given sequence number.

        Note that the transaction returned may not yet be verified by a
        signature transaction nor committed by the service.

        :param int seqno: Sequence number of the transaction to fetch.

        :return: :py:class:`ccf.ledger.Transaction`
        """
        if seqno < 1:
            raise ValueError(f"Ledger first seqno is 1, cannot get {seqno}")

        for filename in self._filenames:
            start, end = range_from_filename(filename)
            if seqno >= start and (end is None or seqno <= end):
                chunk = LedgerChunk(filename)
                return chunk[seqno - start]

        raise UnknownTransaction(
            f"Transaction at seqno {seqno} does not exist in ledger"
        )

    def get_latest_public_state(self) -> Tuple[dict, int]:
        """
        Return the current public state of the service.

        Note that the public state returned may not yet be verified by a
        signature transaction nor committed by the service.

        :return: Tuple[Dict, int]: Tuple containing a dictionary of public tables and their values and the seqno of the state read from the ledger.
        """

        public_tables: Dict[str, Dict] = {}
        latest_seqno = 0
        # If a transaction cannot be read (e.g. because it was only partially written to disk
        # before a crash), return public state so far. This is consistent with CCF's behaviour
        # which discards the incomplete transaction on recovery.

        try:
            for chunk in self:
                for tx in chunk:
                    public_domain = tx.get_public_domain()
                    latest_seqno = public_domain.get_seqno()
                    for table_name, records in public_domain.get_tables().items():
                        if table_name in public_tables:
                            public_tables[table_name].update(records)
                            # Remove deleted keys
                            public_tables[table_name] = {
                                k: v
                                for k, v in public_tables[table_name].items()
                                if v is not None
                            }
                        else:
                            public_tables[table_name] = records
        except Exception as e:
            print(f"Error reading ledger entry. Latest read seqno: {latest_seqno}")
            print(f"Error: {e}")
        return public_tables, latest_seqno


class InvalidRootException(Exception):
    """MerkleTree root doesn't match with the root reported in the signature's table"""


class InvalidRootSignatureException(Exception):
    """Signature of the MerkleRoot doesn't match with the signature that's reported in the signature's table"""


class InvalidRootCoseSignatureException(Exception):
    """COSE signature of the MerkleRoot doesn't pass COSE verification"""


class CommitIdRangeException(Exception):
    """Missing ledger chunk in the ledger directory"""


class UntrustedNodeException(Exception):
    """The signing node wasn't part of the network"""


class UnknownTransaction(Exception):
    """The transaction at seqno does not exist in ledger"""


class InvalidSnapshotException(Exception):
    """The given snapshot file is invalid and cannot be parsed"""
