// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/ccf_assert.h"
#include "ds/serialized.h"
#include "kv/ledger_format.h"

namespace consensus
{
  class LedgerEnclave
  {
  public:
    static constexpr size_t FRAME_SIZE = sizeof(uint32_t);

  private:
    ringbuffer::WriterPtr to_host;

  public:
    LedgerEnclave(ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside())
    {}

    /**
     * Put a single entry to be written the ledger, when primary.
     *
     * @param entry Serialised entry
     * @param globally_committable True is entry is signature transaction
     * @param force_chunk Force new ledger chunk to be created after this entry
     * (only if globally_committable)
     */
    void put_entry(
      const std::vector<uint8_t>& entry,
      bool globally_committable,
      bool force_chunk = false)
    {
      put_entry(entry.data(), entry.size(), globally_committable, force_chunk);
    }

    /**
     * Put a single entry to be written the ledger, when primary.
     *
     * @param data Serialised entry start
     * @param size Serialised entry size
     * @param globally_committable True is entry is signature transaction
     * @param force_chunk Force new ledger chunk to be created after this entry
     * (only if globally_committable)
     */
    void put_entry(
      const uint8_t* data,
      size_t size,
      bool globally_committable,
      bool force_chunk = false)
    {
      CCF_ASSERT_FMT(
        globally_committable || !force_chunk,
        "Only globally committable entries can force new ledger chunk");

      serializer::ByteRange byte_range = {data, size};
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_append,
        to_host,
        globally_committable,
        force_chunk,
        byte_range);
    }

    /**
     * Skip a single entry, when backup.
     *
     * Does not write any entry to the legder.
     *
     * @param data Serialised entries
     * @param size Size of overall serialised entries
     */
    void skip_entry(const uint8_t*& data, size_t& size)
    {
      auto header = serialized::read<kv::SerialisedEntryHeader>(data, size);
      serialized::skip(data, size, header.size);
    }

    /**
     * Retrieve a single entry, advancing offset to the next entry.
     *
     * @param data Serialised entries
     * @param size Size of overall serialised entries
     *
     * @return Raw entry as a vector
     */
    std::vector<uint8_t> get_entry(const uint8_t*& data, size_t& size)
    {
      auto header = serialized::peek<kv::SerialisedEntryHeader>(data, size);
      size_t entry_size = kv::serialised_entry_header_size + header.size;
      std::vector<uint8_t> entry(data, data + entry_size);
      serialized::skip(data, size, entry_size);
      return entry;
    }

    /**
     * Truncate the ledger at a given index.
     *
     * @param idx Index to truncate from
     */
    void truncate(Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_truncate, to_host, idx);
    }

    /**
     * Commit the ledger at a given index.
     *
     * @param idx Index to commit at
     */
    void commit(Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_commit, to_host, idx);
    }

    /**
     * Initialise ledger at a given index (e.g. after a snapshot)
     *
     * @param idx Index to start ledger from
     */
    void init(Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_init, to_host, idx);
    }
  };
}