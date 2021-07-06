# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import io
import struct
import os
from enum import Enum

from typing import BinaryIO, NamedTuple, Optional, Tuple, Dict, List

import json
import base64
from dataclasses import dataclass

from loguru import logger as LOG  # type: ignore
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils, ec

from ccf.merkletree import MerkleTree
from ccf.tx_id import TxID

GCM_SIZE_TAG = 16
GCM_SIZE_IV = 12
LEDGER_DOMAIN_SIZE = 8
LEDGER_HEADER_SIZE = 8

# Public table names as defined in CCF
# https://github.com/microsoft/CCF/blob/main/src/node/entities.h
SIGNATURE_TX_TABLE_NAME = "public:ccf.internal.signatures"
NODES_TABLE_NAME = "public:ccf.gov.nodes.info"

# Key used by CCF to record single-key tables
WELL_KNOWN_SINGLETON_TABLE_KEY = bytes(bytearray(8))


class NodeStatus(Enum):
    PENDING = "Pending"
    TRUSTED = "Trusted"
    RETIRED = "Retired"
    LEARNER = "Learner"


def to_uint_64(buffer):
    return struct.unpack("@Q", buffer)[0]


def is_ledger_chunk_committed(file_name):
    return file_name.endswith(".committed")


def unpack(stream, fmt):
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    if not buf:
        raise EOFError  # Reached end of stream
    return struct.unpack(fmt, buf)[0]


def unpack_array(stream, fmt, length):
    buf = stream.read(length)
    if not buf:
        raise EOFError  # Reached end of stream
    unpack_iter = struct.iter_unpack(fmt, buf)
    ret = []
    while True:
        try:
            ret.append(next(unpack_iter)[0])
        except StopIteration:
            break
    return ret


class GcmHeader:
    _gcm_tag = ["\0"] * GCM_SIZE_TAG
    _gcm_iv = ["\0"] * GCM_SIZE_IV

    def __init__(self, buffer):
        if len(buffer) < GcmHeader.size():
            raise ValueError("Corrupt GCM header")
        self._gcm_tag = struct.unpack(f"@{GCM_SIZE_TAG}B", buffer[:GCM_SIZE_TAG])
        self._gcm_iv = struct.unpack(f"@{GCM_SIZE_IV}B", buffer[GCM_SIZE_TAG:])

    @staticmethod
    def size():
        return GCM_SIZE_TAG + GCM_SIZE_IV


class PublicDomain:
    """
    All public tables within a :py:class:`ccf.ledger.Transaction`.
    """

    _buffer: io.BytesIO
    _buffer_size: int
    _is_snapshot: bool
    _version: int
    _max_conflict_version: int
    _tables: dict

    def __init__(self, buffer: io.BytesIO):
        self._buffer = buffer
        self._buffer_size = self._buffer.getbuffer().nbytes
        self._is_snapshot = self._read_is_snapshot()
        self._version = self._read_version()
        self._max_conflict_version = self._read_version()

        if self._is_snapshot:
            self._read_snapshot_header()

        self._tables = {}
        self._read()

    def _read_is_snapshot(self):
        return unpack(self._buffer, "<?")

    def _read_version(self):
        return unpack(self._buffer, "<q")

    def get_version_size(self):
        return struct.calcsize("<q")

    def _read_versioned_value(self, size):
        return (self._read_version(), self._buffer.read(size - self.get_version_size()))

    def _read_size(self):
        return unpack(self._buffer, "<Q")

    def _read_string(self):
        size = self._read_size()
        return self._buffer.read(size).decode()

    def _read_next_entry(self):
        size = self._read_size()
        return self._buffer.read(size)

    def _read_snapshot_header(self):
        # read hash of entry at snapshot
        hash_size = self._read_size()
        buffer = unpack(self._buffer, f"<{hash_size}s")
        self._hash_at_snapshot = buffer.hex()

        # read view history
        view_history_size = self._read_size()
        self._view_history = unpack_array(self._buffer, "<Q", view_history_size)

    def _read_snapshot_entry_padding(self, size):
        padding = -size % 8  # Padded to 8 bytes
        self._buffer.read(padding)

    def _read_snapshot_key(self):
        size = self._read_size()
        key = self._buffer.read(size)
        self._read_snapshot_entry_padding(size)
        return key

    def _read_snapshot_versioned_value(self):
        size = self._read_size()
        _, value = self._read_versioned_value(size)
        self._read_snapshot_entry_padding(size)
        return value

    def _read(self):
        while True:
            try:
                map_name = self._read_string()
            except EOFError:
                break

            records = {}
            self._tables[map_name] = records

            if self._is_snapshot:
                # map snapshot version
                self._read_version()

                # size of map entry
                map_size = self._read_size()
                start_map_pos = self._buffer.tell()

                while self._buffer.tell() - start_map_pos < map_size:
                    k = self._read_snapshot_key()
                    val = self._read_snapshot_versioned_value()
                    records[k] = val
            else:
                # read_version
                self._read_version()

                # read_count
                # Note: Read keys are not currently included in ledger transactions
                read_count = self._read_size()
                assert read_count == 0, f"Unexpected read count: {read_count}"

                write_count = self._read_size()
                if write_count:
                    for _ in range(write_count):
                        k = self._read_next_entry()
                        val = self._read_next_entry()
                        records[k] = val

                remove_count = self._read_size()
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


def _byte_read_safe(file, num_of_bytes):
    offset = file.tell()
    ret = file.read(num_of_bytes)
    if len(ret) != num_of_bytes:
        raise ValueError(
            f"Failed to read precise number of bytes in {file.name} at offset {offset}: {len(ret)}/{num_of_bytes}"
        )
    return ret


class TxBundleInfo(NamedTuple):
    """Bundle for transaction information required for validation"""

    merkle_tree: MerkleTree
    existing_root: bytes
    node_cert: bytes
    signature: bytes
    node_activity: dict
    signing_node: str


class LedgerValidator:
    """
    Ledger Validator contains the logic to verify that the ledger hasn't been tampered with.
    It has the ability to take transactions and it maintains a MerkleTree data structure similar to CCF.

    Ledger is valid and hasn't been tampered with if following conditions are met:
        1) The merkle proof is signed by a Trusted node in the given network
        2) The merkle root and signature are verified with the node cert
        3) The merkle proof is correct for each set of transactions
    """

    # Constant for the size of a hashed transaction
    SHA_256_HASH_SIZE = 32

    def __init__(self):
        self.node_certificates = {}
        self.node_activity_status = {}
        self.signature_count = 0
        self.chosen_hash = ec.ECDSA(utils.Prehashed(hashes.SHA256()))

        # Start with empty bytes array. CCF MerkleTree uses an empty array as the first leaf of it's merkle tree.
        # Don't hash empty bytes array.
        self.merkle = MerkleTree()
        empty_bytes_array = bytearray(self.SHA_256_HASH_SIZE)
        self.merkle.add_leaf(empty_bytes_array, do_hash=False)

        self.last_verified_seqno = 0
        self.last_verified_view = 0

    def add_transaction(self, transaction):
        """
        To validate the ledger, ledger transactions need to be added via this method.
        Depending on the tables that were part of the transaction, it does different things.
        When transaction contains signature table, it starts the verification process and verifies that the root of merkle tree was signed by a node which was part of the network.
        It also matches the root of the merkle tree that this class maintains with the one extracted from the ledger.
        If any of the above checks fail, this method throws.
        """
        transaction_public_domain = transaction.get_public_domain()
        tables = transaction_public_domain.get_tables()

        # Add contributing nodes certs and update nodes network trust status for verification
        if NODES_TABLE_NAME in tables:
            node_table = tables[NODES_TABLE_NAME]
            for node_id, node_info in node_table.items():
                node_id = node_id.decode()
                node_info = json.loads(node_info)
                # Add the node certificate
                self.node_certificates[node_id] = node_info["cert"].encode()
                # Update node trust status
                # Also record the seqno at which the node status changed to
                # track when a primary node should stop issuing signatures
                self.node_activity_status[node_id] = (
                    node_info["status"],
                    transaction_public_domain.get_seqno(),
                )

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
                self._verify_tx_set(tx_info)

                # Forget about nodes whose retirement has been committed
                for node_id, (status, seqno) in list(self.node_activity_status.items()):
                    if (
                        status == NodeStatus.RETIRED.value
                        and signature["commit_seqno"] >= seqno
                    ):
                        self.node_activity_status.pop(node_id)

                self.last_verified_seqno = current_seqno
                self.last_verified_view = current_view

        # Checks complete, add this transaction to tree
        self.merkle.add_leaf(transaction.get_raw_tx())

    def _verify_tx_set(self, tx_info: TxBundleInfo):
        """
        Verify items 1, 2, and 3 for all the transactions up until a signature.
        """
        # 1) The merkle root is signed by a Trusted node in the given network, else throws
        self._verify_node_status(tx_info)
        # 2) The merkle root and signature are verified with the node cert, else throws
        self._verify_root_signature(tx_info)
        # 3) The merkle root is correct for the set of transactions and matches with the one extracted from the ledger, else throws
        self._verify_merkle_root(tx_info.merkle_tree, tx_info.existing_root)

    @staticmethod
    def _verify_node_status(tx_info: TxBundleInfo):
        """Verify item 1, The merkle root is signed by a valid node in the given network"""
        # Note: A retired primary will still issue signature transactions until
        # its retirement is committed
        if tx_info.node_activity[tx_info.signing_node][0] not in (
            NodeStatus.TRUSTED.value,
            NodeStatus.RETIRED.value,
        ):
            LOG.error(
                f"The signing node {tx_info.signing_node!r} is not trusted by the network"
            )
            raise UntrustedNodeException

    def _verify_root_signature(self, tx_info: TxBundleInfo):
        """Verify item 2, that the Merkle root signature validates against the node certificate"""
        try:
            cert = load_pem_x509_certificate(tx_info.node_cert, default_backend())
            pub_key = cert.public_key()

            assert isinstance(pub_key, ec.EllipticCurvePublicKey)
            pub_key.verify(
                tx_info.signature, tx_info.existing_root, self.chosen_hash
            )  # type: ignore[override]
        # This exception is thrown from x509, catch for logging and raise our own
        except InvalidSignature:
            LOG.error(
                "Signature verification failed:"
                + f"\nCertificate: {tx_info.node_cert!r}"
                + f"\nSignature: {tx_info.signature!r}"
                + f"\nRoot: {tx_info.existing_root!r}"
            )
            raise InvalidRootSignatureException from InvalidSignature

    def _verify_merkle_root(self, merkletree: MerkleTree, existing_root: bytes):
        """Verify item 3, by comparing the roots from the merkle tree that's maintained by this class and from the one extracted from the ledger"""
        root = merkletree.get_merkle_root()
        if root != existing_root:
            LOG.error(
                f"\nRoot: {root.hex()} \nExisting root from ledger: {existing_root.hex()}"
            )
            raise InvalidRootException


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
        if len(buffer) < TransactionHeader.get_size():
            raise ValueError("Incomplete transaction header")

        self.version = int.from_bytes(
            buffer[: TransactionHeader.VERSION_LENGTH], byteorder="little"
        )

        self.flags = int.from_bytes(
            buffer[
                TransactionHeader.VERSION_LENGTH : TransactionHeader.VERSION_LENGTH
                + TransactionHeader.FLAGS_LENGTH
            ],
            byteorder="little",
        )
        self.size = int.from_bytes(
            buffer[-TransactionHeader.SIZE_LENGTH :], byteorder="little"
        )

    @staticmethod
    def get_size():
        return (
            TransactionHeader.VERSION_LENGTH
            + TransactionHeader.FLAGS_LENGTH
            + TransactionHeader.SIZE_LENGTH
        )


class Entry:
    _file: Optional[BinaryIO] = None
    _header: TransactionHeader
    _public_domain_size: int = 0
    _public_domain: Optional[PublicDomain] = None
    _file_size: int = 0
    gcm_header: Optional[GcmHeader] = None

    def __init__(self, filename: str):
        if type(self) == Entry:
            raise TypeError("Entry is not instantiable")

        self._file = open(filename, mode="rb")
        if self._file is None:
            raise RuntimeError(f"File {filename} could not be opened")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        self._file.close()

    def _read_header(self):
        # read the transaction header
        buffer = _byte_read_safe(self._file, TransactionHeader.get_size())
        self._header = TransactionHeader(buffer)

        # read the AES GCM header
        buffer = _byte_read_safe(self._file, GcmHeader.size())
        self.gcm_header = GcmHeader(buffer)

        # read the size of the public domain
        buffer = _byte_read_safe(self._file, LEDGER_DOMAIN_SIZE)
        self._public_domain_size = to_uint_64(buffer)

    def get_public_domain(self) -> Optional[PublicDomain]:
        """
        Retrieve the public (i.e. non-encrypted) domain for that entry.

        Note: If the entry is private-only, nothing is returned.

        :return: :py:class:`ccf.ledger.PublicDomain`
        """
        if self._public_domain == None:
            buffer = io.BytesIO(_byte_read_safe(self._file, self._public_domain_size))
            self._public_domain = PublicDomain(buffer)
        return self._public_domain

    def get_private_domain_size(self) -> int:
        """
        Retrieve the size of the private (i.e. encrypted) domain for that transaction.
        """
        return self._header.size - (
            GcmHeader.size() + LEDGER_DOMAIN_SIZE + self._public_domain_size
        )


class Transaction(Entry):
    """
    A transaction represents one entry in the CCF ledger.
    """

    _next_offset: int = LEDGER_HEADER_SIZE
    _tx_offset: int = 0
    _ledger_validator: Optional[LedgerValidator] = None

    def __init__(
        self, filename: str, ledger_validator: Optional[LedgerValidator] = None
    ):
        super().__init__(filename)
        self._ledger_validator = ledger_validator

        try:
            self._file_size = int.from_bytes(
                _byte_read_safe(self._file, LEDGER_HEADER_SIZE), byteorder="little"
            )
            # If the ledger chunk is not yet committed, the ledger header will be empty.
            # Default to reading the file size instead.
            if self._file_size == 0:
                self._file_size = os.path.getsize(filename)
        except ValueError:
            if is_ledger_chunk_committed(filename):
                raise
            else:
                LOG.warning(
                    f"Could not read ledger header size in uncommitted ledger file '{filename}'"
                )

    def _read_header(self):
        self._tx_offset = self._file.tell()
        super()._read_header()
        self._next_offset += self._header.size
        self._next_offset += TransactionHeader.get_size()

    def get_raw_tx(self) -> bytes:
        """
        Return raw transaction bytes.

        :return: Raw transaction bytes.
        """
        assert self._file is not None

        # remember where the pointer is in the file before we go back for the transaction bytes
        save_pos = self._file.tell()
        self._file.seek(self._tx_offset)
        buffer = _byte_read_safe(
            self._file, TransactionHeader.get_size() + self._header.size
        )
        # return to original filepointer and return the transaction bytes
        self._file.seek(save_pos)
        return buffer

    def _complete_read(self):
        self._file.seek(self._next_offset, 0)
        self._public_domain = None

    def __iter__(self):
        return self

    def __next__(self):
        if self._next_offset == self._file_size:
            super().close()
            raise StopIteration()

        self._complete_read()
        self._read_header()

        # Adds every transaction to the ledger validator
        # LedgerValidator does verification for every added transaction
        # and throws when it finds any anomaly.
        self._ledger_validator.add_transaction(self)

        return self


class Snapshot(Entry):
    """
    Utility used to parse the content of a snapshot file.
    """

    _filename: str

    def __init__(self, filename: str):
        super().__init__(filename)
        self._filename = filename
        self._file_size = os.path.getsize(filename)
        super()._read_header()

    def commit_seqno(self):
        try:
            return int(self._filename.split("committed_")[1])
        except IndexError:
            # Snapshot is not yet committed
            return None


class LedgerChunk:
    """
    Class used to parse and iterate over :py:class:`ccf.ledger.Transaction` in a CCF ledger chunk.

    :param str name: Name for a single ledger chunk.
    :param LedgerValidator ledger_validator: :py:class:`LedgerValidator` instance used to verify ledger integrity.
    """

    _current_tx: Transaction
    _filename: str
    _ledger_validator: LedgerValidator

    def __init__(self, name: str, ledger_validator: LedgerValidator):
        self._ledger_validator = ledger_validator
        self._current_tx = Transaction(name, ledger_validator)
        self._filename = name

    def __next__(self) -> Transaction:
        return next(self._current_tx)

    def __iter__(self):
        return self

    def filename(self):
        return self._filename

    def is_committed(self):
        return is_ledger_chunk_committed(self._filename)


class Ledger:
    """
    Class used to iterate over all :py:class:`ccf.ledger.LedgerChunk` stored in a CCF ledger folder.

    :param str name: Ledger directory for a single CCF node.
    """

    _filenames: list
    _fileindex: int
    _current_chunk: LedgerChunk
    _ledger_validator: LedgerValidator

    def _reset_iterators(self):
        self._fileindex = -1
        # Initialize LedgerValidator instance which will be passed to LedgerChunks.
        self._ledger_validator = LedgerValidator()

    @classmethod
    def _range_from_filename(cls, filename: str) -> Tuple[int, Optional[int]]:
        elements = (
            os.path.basename(filename)
            .replace(".committed", "")
            .replace("ledger_", "")
            .split("-")
        )
        if len(elements) == 2:
            return (int(elements[0]), int(elements[1]))
        elif len(elements) == 1:
            return (int(elements[0]), None)
        else:
            assert False, elements

    def __init__(self, directories: List[str], committed_only: bool = True):

        self._filenames = []

        ledger_files = []
        for directory in directories:
            for path in os.listdir(directory):
                if committed_only and not path.endswith(".committed"):
                    continue
                chunk = os.path.join(directory, path)
                if os.path.isfile(chunk):
                    ledger_files.append(chunk)

        # Sorts the list based off the first number after ledger_ so that
        # the ledger is verified in sequence
        self._filenames = sorted(
            ledger_files,
            key=lambda x: Ledger._range_from_filename(x)[0],
        )

        self._reset_iterators()

    @property
    def last_committed_chunk_range(self) -> Tuple[int, Optional[int]]:
        last_chunk_name = self._filenames[-1]
        return Ledger._range_from_filename(last_chunk_name)

    def __next__(self) -> LedgerChunk:
        self._fileindex += 1
        if len(self._filenames) > self._fileindex:
            self._current_chunk = LedgerChunk(
                self._filenames[self._fileindex], self._ledger_validator
            )
            return self._current_chunk
        else:
            raise StopIteration

    def __len__(self):
        return len(self._filenames)

    def __iter__(self):
        return self

    def get_transaction(self, seqno: int) -> Transaction:
        """
        Return the :py:class:`ccf.ledger.Transaction` recorded in the ledger at the given sequence number.

        Note that the transaction returned may not yet be verified by a
        signature transaction nor committed by the service.

        :param int seqno: Sequence number of the transaction to fetch.

        :return: :py:class:`ccf.ledger.Transaction`
        """
        if seqno < 1:
            raise ValueError("Ledger first seqno is 1")

        self._reset_iterators()

        transaction = None
        try:
            # Note: This is slower than it really needs to as this will walk through
            # all transactions from the start of the ledger.
            for chunk in self:
                for tx in chunk:
                    public_transaction = tx.get_public_domain()
                    if public_transaction.get_seqno() == seqno:
                        return tx
        finally:
            self._reset_iterators()

        if transaction is None:
            raise UnknownTransaction(
                f"Transaction at seqno {seqno} does not exist in ledger"
            )
        return transaction

    def get_latest_public_state(self) -> Tuple[dict, int]:
        """
        Return the current public state of the service.

        Note that the public state returned may not yet be verified by a
        signature transaction nor committed by the service.

        :return: Tuple[Dict, int]: Tuple containing a dictionary of public tables and their values and the seqno of the state read from the ledger.
        """
        self._reset_iterators()

        public_tables: Dict[str, Dict] = {}
        latest_seqno = 0
        for chunk in self:
            for tx in chunk:
                latest_seqno = tx.get_public_domain().get_seqno()
                for table_name, records in tx.get_public_domain().get_tables().items():
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

        return public_tables, latest_seqno

    def signature_count(self) -> int:
        """
        Return the number of verified signature transactions in the *parsed* ledger.

        Note: The ledger should first be parsed before calling this function.

        :return int: Number of verified signature transactions.
        """
        return self._ledger_validator.signature_count

    def last_verified_txid(self) -> TxID:
        """
        Return the :py:class:`ccf.tx_id.TxID` of the last verified signature transaction in the *parsed* ledger.

        Note: The ledger should first be parsed before calling this function.

        :return: :py:class:`ccf.tx_id.TxID`
        """
        return TxID(
            self._ledger_validator.last_verified_view,
            self._ledger_validator.last_verified_seqno,
        )


class InvalidRootException(Exception):
    """MerkleTree root doesn't match with the root reported in the signature's table"""


class InvalidRootSignatureException(Exception):
    """Signature of the MerkleRoot doesn't match with the signature that's reported in the signature's table"""


class CommitIdRangeException(Exception):
    """Missing ledger chunk in the ledger directory"""


class UntrustedNodeException(Exception):
    """The signing node wasn't part of the network"""


class UnknownTransaction(Exception):
    """The transaction at seqno does not exist in ledger"""
