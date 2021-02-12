# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import io
import struct
import os
import re
import hashlib

from typing import BinaryIO, NamedTuple, Optional, Set
from enum import IntEnum

# Default implementation has buggy interaction between read_bytes and tell, so use fallback
import msgpack.fallback as msgpack  # type: ignore

from loguru import logger as LOG  # type: ignore
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils, ec

from merkletree import MerkleTree

GCM_SIZE_TAG = 16
GCM_SIZE_IV = 12
LEDGER_TRANSACTION_SIZE = 4
LEDGER_DOMAIN_SIZE = 8
LEDGER_HEADER_SIZE = 8

UNPACK_ARGS = {"raw": True, "strict_map_key": False}

# Public table names as defined in CCF
# https://github.com/microsoft/CCF/blob/master/src/node/entities.h#L96
SIGNATURE_TX_TABLE_NAME = "public:ccf.internal.signatures"
# https://github.com/microsoft/CCF/blob/master/src/node/entities.h#L71
NODES_TABLE_NAME = "public:ccf.gov.nodes.info"


def to_uint_32(buffer):
    return struct.unpack("@I", buffer)[0]


def to_uint_64(buffer):
    return struct.unpack("@Q", buffer)[0]


def is_ledger_chunk_committed(file_name):
    return file_name.endswith(".committed")


class GcmHeader:
    _gcm_tag = ["\0"] * GCM_SIZE_TAG
    _gcm_iv = ["\0"] * GCM_SIZE_IV

    def __init__(self, buffer):
        if len(buffer) < GcmHeader.size():
            raise ValueError("Corrupt GCM header")
        self._gcm_tag = struct.unpack(
            f"@{GCM_SIZE_TAG}B", buffer[:GCM_SIZE_TAG])
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
    _unpacker: msgpack.Unpacker
    _is_snapshot: bool
    _version: int
    _max_conflict_version: int
    _tables: dict
    _msgpacked_tables: Set[str]

    def __init__(self, buffer: io.BytesIO):
        self._buffer = buffer
        self._buffer_size = buffer.getbuffer().nbytes
        self._unpacker = msgpack.Unpacker(self._buffer, **UNPACK_ARGS)
        self._is_snapshot = self._read_next()
        self._version = self._read_next()
        self._max_conflict_version = self._read_next()
        self._tables = {}
        # Keys and Values may have custom serialisers.
        # Store most as raw bytes, only decode a few which we know are msgpack.
        self._msgpacked_tables = {
            "public:ccf.internal.members.certs_der",
            "public:ccf.gov.history",
            SIGNATURE_TX_TABLE_NAME,
            NODES_TABLE_NAME
        }
        self._read()

    def _read_next(self):
        return self._unpacker.unpack()

    def _read_next_string(self):
        return self._unpacker.unpack().decode()

    def _read_next_entry(self):
        size_bytes = self._unpacker.read_bytes(8)
        (size,) = struct.unpack("<Q", size_bytes)
        entry_bytes = bytes(self._unpacker.read_bytes(size))
        return entry_bytes

    def _read(self):
        while self._buffer_size > self._unpacker.tell():
            # map_start_indicator
            self._read_next()
            map_name = self._read_next_string()
            LOG.debug(f"Reading map {map_name}")
            records = {}
            self._tables[map_name] = records

            # read_version
            self._read_next()

            # read_count
            read_count = self._read_next()
            assert read_count == 0, f"Unexpected read count: {read_count}"

            write_count = self._read_next()
            if write_count:
                for _ in range(write_count):
                    k = self._read_next_entry()
                    val = self._read_next_entry()
                    if map_name in self._msgpacked_tables:
                        k = msgpack.unpackb(k, **UNPACK_ARGS)
                        val = msgpack.unpackb(val, **UNPACK_ARGS)
                    records[k] = val

            remove_count = self._read_next()
            if remove_count:
                for _ in range(remove_count):
                    k = self._read_next_entry()
                    if map_name in self._msgpacked_tables:
                        k = msgpack.unpackb(k, **UNPACK_ARGS)
                    records[k] = None

            LOG.debug(
                f"Found {read_count} reads, {write_count} writes, and {remove_count} removes"
            )

    def get_tables(self) -> dict:
        """
        Returns a dictionary of all public tables (with their content) in a :py:class:`ccf.ledger.Transaction`.

        :return: Dictionary of public tables with their content.
        """
        return self._tables


def _byte_read_safe(file, num_of_bytes):
    ret = file.read(num_of_bytes)
    if len(ret) != num_of_bytes:
        raise ValueError(
            "Failed to read precise number of bytes: %u, actual = %u"
            % (num_of_bytes, len(ret))
        )
    return ret


class LedgerValidator:
    """
    Ledger Validator contains the logic to verify that the ledger hasn't been tampered with.
    It has the ability to take transactions and it maintains a MerkleTree data structure similar to CCF.

    Ledger is valid and hasn't been tampered with if:
        1) The merkle proof is signed by a TRUSTED node in the given network
        2) The merkle root and signature are verified with the node cert
        3) The merkle proof is correct for each set of transactions
    """

    # The node that is expected to sign the signature transaction
    # The certificate used to sign the signature transaction
    # https://github.com/microsoft/CCF/blob/master/src/node/nodes.h#L42
    EXPECTED_NODE_CERT_INDEX = 1
    # The current network trust status of the Node at the time of the current transaction
    EXPECTED_NODE_STATUS_INDEX = 4

    # Signature table contains PrimarySignature which extends NodeSignature. NodeId should be at index 1 in the serialized Node
    # https://github.com/microsoft/CCF/blob/master/src/node/signatures.h#L23
    EXPECTED_NODE_SIGNATURE_INDEX = 0
    EXPECTED_NODE_VIEW_INDEX = 2
    EXPECTED_ROOT_INDEX = 5
    # https://github.com/microsoft/CCF/blob/master/src/node/node_signature.h#L76
    EXPECTED_SIGNING_NODE_ID_INDEX = 1
    EXPECTED_SIGNATURE_INDEX = 0
    # Constant for the size of a hashed transaction
    SHA_256_HASH_SIZE = 32

    def __init__(self):
        self.node_certificates = {}
        self.node_activity_status = {}
        self.signature_count = 0
        self.signature_ending = False
        self.chosen_hash = ec.ECDSA(utils.Prehashed(hashes.SHA256()))

        # Initialize the Merkle tree with an empty transaction.
        self.merkle = MerkleTree()
        empty_bytes_array = bytearray(32)
        self.merkle.add_leaf(empty_bytes_array, do_hash=False)

    def add_transaction(self, transaction):
        """
        To validate the ledger, ledger transactions need to be added via this method.
        Depending on the tables that were part of the transaction, it does different things.
        When transaction contains signature table, it starts the verification process and verifies that the root of merkle tree was signed by a node which was part of the network.
        It also matches the root of the merkle tree that this class maintains with the one extracted from the ledger.
        If any of the above checks fail, this method throws.
        """
        # Start with empty bytes array. CCF MerkleTree uses an empty array as the first leaf of it's merkle tree.
        # Don't hash empty bytes array.
        self.signature_ending = False
        transaction_public_domain = transaction.get_public_domain()
        tables = transaction_public_domain.get_tables()

        # Add contributing nodes certs and update nodes network trust status for verification
        if NODES_TABLE_NAME in tables:
            node_table = tables[NODES_TABLE_NAME]
            for nodeid, values in node_table.items():
                # Add the nodes certificate
                self.node_certificates[nodeid] = values[
                    self.EXPECTED_NODE_CERT_INDEX
                ]
                # Update node trust status
                self.node_activity_status[nodeid] = NodeStatus(
                    values[self.EXPECTED_NODE_STATUS_INDEX]
                )

        # This is a merkle root/signature tx if the table exists
        if SIGNATURE_TX_TABLE_NAME in tables:
            self.signature_ending = True
            self.signature_count += 1
            signature_table = tables[SIGNATURE_TX_TABLE_NAME]

            for nodeid, values in signature_table.items():
                signing_node = int(
                    values[self.EXPECTED_NODE_SIGNATURE_INDEX][self.EXPECTED_SIGNING_NODE_ID_INDEX])
                # Get binary representations for the cert, existing root, and signature
                cert = b"".join(self.node_certificates[signing_node])
                existing_root = b"".join(
                    values[self.EXPECTED_ROOT_INDEX])
                signature = values[self.EXPECTED_NODE_SIGNATURE_INDEX][self.EXPECTED_SIGNATURE_INDEX]

                tx_info = TxBundleInfo(
                    self.merkle,
                    existing_root,
                    cert,
                    signature,
                    self.node_activity_status,
                    signing_node,
                )

                # validations for 1, 2 and 3
                # throws if ledger validation failed.
                if self._verify_tx_set(tx_info):
                    continue
                else:
                    raise ValueError("Ledger validation failed")

        # Checks complete, add this transaction to tree
        self.merkle.add_leaf(transaction.get_public_tx())

    def verify_ending(self) -> bool:
        if self.signature_count == 0:
            LOG.error(
                "Found 0 signatures. This usually means that the ledger is invalid")
            raise SignatureCountException
        if not self.signature_ending:
            LOG.error(
                "The last transaction in the ledger chunk wasn't a signature transaction which is unexpected.")
            raise SignatureEndingException

    def _verify_tx_set(self, tx_info: tuple) -> bool:
        """Verify items 2, 3, and 4 for a the transactions up until a signature"""
        # 2) The merkle proof is signed by a TRUSTED node in the given network
        if self._verify_node_status(tx_info):
            # 3) The merkle root and signature are verified with the node cert
            if self._verify_root_signature(tx_info):
                # 4) The merkle proof is correct for the set of transactions
                if self._verify_merkle_root(tx_info.merkle_tree, tx_info.existing_root):
                    return True
        return False

    @staticmethod
    def _verify_node_status(tx_info: NamedTuple) -> bool:
        """Verify item 2, The merkle proof is signed by a TRUSTED node in the given network"""
        if tx_info.node_activity[tx_info.signing_node] is NodeStatus.trusted:
            return True
        LOG.error(
            f"The signing node {tx_info.signing_node} is not trusted by the network"
        )
        raise UntrustedNodeException

    def _verify_root_signature(self, tx_info: NamedTuple) -> bool:
        """Verify item 3, that the Merkle root signature validates against the node certificate"""
        try:
            cert = load_pem_x509_certificate(
                tx_info.node_cert, default_backend())
            pub_key = cert.public_key()
            pub_key.verify(tx_info.signature,
                           tx_info.existing_root, self.chosen_hash)
            return True
        # This exception is thrown from x509, catch for logging and raise our own
        except InvalidSignature:
            LOG.error(
                "Signature verification failed:"
                + f"\nCertificate: {tx_info.node_cert}"
                + f"\nSignature: {tx_info.signature}"
                + f"\nRoot: {tx_info.existing_root}"
            )
            raise InvalidRootSignatureException

    def _verify_merkle_root(
        self, merkletree: MerkleTree, existing_root: bytes
    ) -> bool:
        """Verify item 4, by comparing the roots from the ledger and tree"""
        root = bytearray(self.SHA_256_HASH_SIZE)
        root = merkletree.get_merkle_root()
        if root == existing_root:
            return True
        LOG.error(
            f"\nRoot: {root.hex()} \nExisting root from ledger: {existing_root.hex()}"
        )
        raise InvalidRootException

    @staticmethod
    def _hash_tx(transaction: bytes) -> bytes:
        """Hashing function for ledger transactions"""
        hashed = hashlib.sha256(transaction)
        return hashed.digest()


class Transaction:
    """
    A transaction represents one entry in the CCF ledger.
    """

    _file: Optional[BinaryIO] = None
    _total_size: int = 0
    _public_domain_size: int = 0
    _next_offset: int = LEDGER_HEADER_SIZE
    _public_domain: Optional[PublicDomain] = None
    _file_size: int = 0
    gcm_header: Optional[GcmHeader] = None
    _tx_offset: int = 0
    _ledger_validator: LedgerValidator

    def __init__(self, filename: str, ledger_validator: LedgerValidator):
        self._ledger_validator = ledger_validator
        self._file = open(filename, mode="rb")
        if self._file is None:
            raise RuntimeError(f"Ledger file {filename} could not be opened")

        try:
            self._file_size = int.from_bytes(
                _byte_read_safe(self._file, LEDGER_HEADER_SIZE), byteorder="little"
            )
        except ValueError:
            if is_ledger_chunk_committed(filename):
                raise
            else:
                LOG.warning(
                    f"Could not read ledger header size in uncommitted ledger file '{filename}'"
                )

    def __del__(self):
        self._file.close()

    def _read_header(self):
        # read the size of the transaction
        buffer = _byte_read_safe(self._file, LEDGER_TRANSACTION_SIZE)
        self._tx_offset = self._file.tell()
        self._total_size = to_uint_32(buffer)
        self._next_offset += self._total_size
        self._next_offset += LEDGER_TRANSACTION_SIZE

        # read the AES GCM header
        buffer = _byte_read_safe(self._file, GcmHeader.size())
        self.gcm_header = GcmHeader(buffer)

        # read the size of the public domain
        buffer = _byte_read_safe(self._file, LEDGER_DOMAIN_SIZE)
        self._public_domain_size = to_uint_64(buffer)

    def get_public_domain(self) -> Optional[PublicDomain]:
        """
        Retrieve the public (i.e. non-encrypted) domain for that transaction.

        Note: If the transaction is private-only, nothing is returned.

        :return: :py:class:`ccf.ledger.PublicDomain`
        """
        if self._public_domain == None:
            buffer = io.BytesIO(_byte_read_safe(
                self._file, self._public_domain_size))
            self._public_domain = PublicDomain(buffer)
        return self._public_domain

    def get_public_tx(self) -> bytes:
        """
        Returns raw transaction bytes.

        :return: Raw transaction bytes.
        """
        assert self._file is not None

        # remember where the pointer is in the file before we go back for the transaction bytes
        header = self._file.tell()
        self._file.seek(self._tx_offset)
        buffer = _byte_read_safe(self._file, self._total_size)
        # return to original filepointer and return the transaction bytes
        self._file.seek(header)
        return buffer

    def _complete_read(self):
        self._file.seek(self._next_offset, 0)
        self._public_domain = None

    def __iter__(self):
        return self

    def __next__(self):
        if self._next_offset == self._file_size:
            raise StopIteration()
        try:
            self._complete_read()
            self._read_header()

            # Adds every transaction to the ledger validator
            # LedgerValidator does verification for every added transaction and throws when it finds any anamoly.
            self._ledger_validator.add_transaction(self)

            return self
        except Exception as exception:
            LOG.exception(f"Encountered exception: {exception}")
            raise


class LedgerChunk:
    """
    Class used to parse and iterate over :py:class:`ccf.ledger.Transaction` in a CCF ledger chunk.

    :param str name: Name for a single ledger chunk.
    """

    _current_tx: Transaction
    _filename: str
    _ledger_validator: LedgerValidator

    def __init__(self, name: str, ledger_validator: LedgerValidator):
        self._ledger_validator = ledger_validator
        self._current_tx = Transaction(name, ledger_validator)
        self._filename = name

    def __next__(self) -> Transaction:
        try:
            return next(self._current_tx)
        except StopIteration:
            self._ledger_validator.verify_ending()
            LOG.debug(f"Completed verifying Txns in {self._filename}.")
            raise

    def __iter__(self):
        return self


class Ledger:
    """
    Class used to iterate over all :py:class:`ccf.ledger.LedgerChunk` stored in a CCF ledger folder.

    :param str name: Ledger directory for a single CCF node.
    """

    LEDGER_COMMITTED_FILE_NAME_REGEX = r"ledger_([0-9]*)-([0-9]*)\.committed"

    _filenames: list
    _fileindex: int
    _current_chunk: LedgerChunk
    _ledger_validator: LedgerValidator

    def __init__(self, directory: str):

        self._filenames = []
        self._fileindex = -1

        ledgers = os.listdir(directory)
        # Sorts the list based off the first number after ledger_ so that
        # the ledger is verified in sequence
        sorted_ledgers = sorted(
            ledgers,
            key=lambda x: int(
                x.replace(".committed", "").replace(
                    "ledger_", "").split("-")[0]
            ),
        )

        # Verifies there are no missing ledger chunks
        self._verify_commited_files(sorted_ledgers)

        for chunk in sorted_ledgers:
            if os.path.isfile(os.path.join(directory, chunk)):
                if not is_ledger_chunk_committed(chunk):
                    LOG.warning(f"The file {chunk} has not been committed")
                self._filenames.append(os.path.join(directory, chunk))

        # Initialize LedgerValidator isntance which will be passed to LedgerChunks.
        self._ledger_validator = LedgerValidator()

    def __next__(self) -> LedgerChunk:
        self._fileindex += 1
        if len(self._filenames) > self._fileindex:
            self._current_chunk = LedgerChunk(
                self._filenames[self._fileindex], self._ledger_validator)
            return self._current_chunk
        else:
            raise StopIteration

    def __iter__(self):
        return self

    def _verify_commited_files(self, sorted_ledgers: list):
        """
        Verify that there are no missing ledger chunks.
        Throws if there are missing files.
        """

        # First commit should always be 1
        expected_commit = 1

        # initialize end commit id to 1
        end_commit_id = -1

        for filename in sorted_ledgers:
            match = re.search(self.LEDGER_COMMITTED_FILE_NAME_REGEX, filename)
            if match:
                start_commit_id = match.group(1)
                if(len(match.group(2))) > 0:
                    end_commit_id = match.group(2)
            if expected_commit == int(start_commit_id):
                expected_commit = int(end_commit_id) + 1
            else:
                LOG.error(
                    f"Expected next commit to be {expected_commit}, but was {start_commit_id}"
                )
                raise ValueError("Ledger chunks are missing.")


def extract_msgpacked_data(data: bytes):
    return msgpack.unpackb(data, **UNPACK_ARGS)


class NodeStatus(IntEnum):
    """These are the corresponding status meanings from the ccf.nodes table"""

    pending = 0
    trusted = 1
    retired = 2


class TxBundleInfo(NamedTuple):
    """Bundle for transaction information required for validation """

    merkle_tree: MerkleTree
    existing_root: bytes
    node_cert: bytes
    signature: bytes
    node_activity: dict
    signing_node: int


class InvalidRootException(Exception):
    """When the transactions don't add up to the ledger signature root"""


class SignatureCountException(Exception):
    """When a ledger has no signature transactions"""


class SignatureEndingException(Exception):
    """When a signature transaction is not the last transaction of a ledger"""


class InvalidRootSignatureException(Exception):
    """When a signature transactions certificate cannot be validated against the node signature"""


class CommitIdRangeException(Exception):
    """There was a missing chunk in the ledger directory"""


class UntrustedNodeException(Exception):
    """The signing node was not verified by the network"""
