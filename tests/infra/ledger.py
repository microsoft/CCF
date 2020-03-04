# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import io
import msgpack
import struct

GCM_SIZE_TAG = 16
GCM_SIZE_IV = 12
LEDGER_TRANSACTION_SIZE = 4
LEDGER_DOMAIN_SIZE = 8


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

    def size():
        return GCM_SIZE_TAG + GCM_SIZE_IV


class LedgerDomain:
    def __init__(self, buffer):
        self._buffer = buffer
        self._buffer_size = buffer.getbuffer().nbytes
        self._unpacker = msgpack.Unpacker(self._buffer, raw=True, strict_map_key=False)
        self._version = self._read_next()
        self._tables = {}
        self._read()

    def _read_next(self):
        return self._unpacker.unpack()

    def _read_next_string(self):
        return self._unpacker.unpack().decode()

    def _read(self):
        while self._buffer_size > self._unpacker.tell():
            map_start_indicator = self._read_next()
            map_name = self._read_next_string()
            records = {}
            self._tables[map_name] = records
            read_version = self._read_next()

            read_count = self._read_next()

            write_count = self._read_next()
            if write_count:
                for i in range(write_count):
                    k = self._read_next()
                    val = self._read_next()
                    records[k] = val

            remove_count = self._read_next()
            if remove_count:
                for i in range(remove_count):
                    k = self._read_next()
                    records[k] = None

    def get_tables(self):
        return self._tables


def _byte_read_safe(file, num_of_bytes):
    ret = file.read(num_of_bytes)
    if len(ret) != num_of_bytes:
        raise ValueError("Failed to read precise number of bytes: %u" % num_of_bytes)
    return ret


class Transaction:

    _file = None
    _total_size = 0
    _public_domain_size = 0
    _next_offset = 0
    _public_domain = None
    _file_size = 0
    gcm_header = None

    def __init__(self, filename):
        self._file = open(filename, mode="rb")
        self._file.seek(0, 2)
        self._file_size = self._file.tell()
        self._file.seek(0, 0)

    def __del__(self):
        self._file.close()

    def _read_header(self):
        # read the size of the transaction
        buffer = _byte_read_safe(self._file, LEDGER_TRANSACTION_SIZE)
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

    _filename = None

    def __init__(self, filename):
        self._filename = filename

    def __iter__(self):
        return Transaction(self._filename)
