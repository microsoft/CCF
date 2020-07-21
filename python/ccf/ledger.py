# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import io
import msgpack.fallback as msgpack  # Default implementation has buggy interaction between read_bytes and tell, so use fallback
import struct
import os

from loguru import logger as LOG

GCM_SIZE_TAG = 16
GCM_SIZE_IV = 12
LEDGER_TRANSACTION_SIZE = 4
LEDGER_DOMAIN_SIZE = 8
LEDGER_HEADER_SIZE = 8

UNPACK_ARGS = {"raw": True, "strict_map_key": False}


def to_uint_32(buffer):
    return struct.unpack("@I", buffer)[0]


def to_uint_64(buffer):
    return struct.unpack("@Q", buffer)[0]


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


class LedgerDomain:
    def __init__(self, buffer):
        self._buffer = buffer
        self._buffer_size = buffer.getbuffer().nbytes
        self._unpacker = msgpack.Unpacker(self._buffer, **UNPACK_ARGS)
        self._is_snapshot = self._read_next()
        self._version = self._read_next()
        self._tables = {}
        # Keys and Values may have custom serialisers.
        # Store most as raw bytes, only decode a few which we know are msgpack.
        self._msgpacked_tables = {
            "ccf.member_certs",
            "ccf.governance.history",
            "ccf.signatures",
            "ccf.nodes",
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

    def get_tables(self):
        return self._tables


def _byte_read_safe(file, num_of_bytes):
    ret = file.read(num_of_bytes)
    if len(ret) != num_of_bytes:
        raise ValueError(
            "Failed to read precise number of bytes: %u, actual = %u"
            % (num_of_bytes, len(ret))
        )
    return ret


class Transaction:

    _file = None
    _total_size = 0
    _public_domain_size = 0
    _next_offset = LEDGER_HEADER_SIZE
    _public_domain = None
    _file_size = 0
    gcm_header = None
    _tx_offset = 0

    def __init__(self, filename):
        self._file = open(filename, mode="rb")
        self._file_size = int.from_bytes(
            _byte_read_safe(self._file, LEDGER_HEADER_SIZE), byteorder="little"
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

    def get_public_domain(self):
        if self._public_domain == None:
            buffer = io.BytesIO(_byte_read_safe(self._file, self._public_domain_size))
            self._public_domain = LedgerDomain(buffer)
        return self._public_domain

    def get_public_tx(self) -> bytes:
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
            return self
        except:
            raise StopIteration()


class Ledger:

    _filenames = []
    _fileindex = 0

    def __init__(self, name: str):

        contents = os.listdir(name)
        # Sorts the list based off the first number after ledger_ so that the ledger is verified in sequence
        sort = sorted(
            contents,
            key=lambda x: int(
                x.replace(".committed", "").replace("ledger_", "").split("-")[0]
            ),
        )

        for chunk in sort:
            # Add only the .committed ledgers to be verified
            if os.path.isfile(os.path.join(name, chunk)):
                if chunk.endswith(".committed"):
                    self._filenames.append(os.path.join(name, chunk))
                else:
                    LOG.warning(f"The file {chunk} has not been committed")
                    self._filenames.append(os.path.join(name, chunk))

        self._fileindex = 0
        self._current_tx = Transaction(self._filenames[0])

    def __next__(self):
        try:
            return next(self._current_tx)
        except StopIteration:
            self._fileindex += 1
            if len(self._filenames) > self._fileindex:
                self._current_tx = Transaction(self._filenames[self._fileindex])
                return next(self._current_tx)
            else:
                raise StopIteration()

    def __iter__(self):
        return self

    def get_ledger_files(self) -> list:
        return self._filenames
