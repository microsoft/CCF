// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/ccf_assert.h"
#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"

namespace consensus
{
  class LedgerEnclave
  {
  public:
    static constexpr size_t FRAME_SIZE = sizeof(uint32_t);

    /**
     * Retrieve a single entry, advancing offset to the next entry.
     *
     * @param data Serialised entries
     * @param size Size of overall serialised entries
     *
     * @return Raw entry as a vector
     */
    static std::vector<uint8_t> get_entry(const uint8_t*& data, size_t& size)
    {
      auto header =
        serialized::peek<ccf::kv::SerialisedEntryHeader>(data, size);
      size_t entry_size = ccf::kv::serialised_entry_header_size + header.size;
      std::vector<uint8_t> entry(data, data + entry_size);
      serialized::skip(data, size, entry_size);
      return entry;
    }

  private:
    ringbuffer::WriterPtr to_host;

  public:
    LedgerEnclave(ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside())
    {}

    /**
     * Put a single entry to be written to the ledger, when primary.
     *
     * @param entry Serialised entry
     * @param globally_committable True if entry is signature transaction
     * @param term Consensus term of entry
     * @param index Index (seqno) of entry
     */
    void put_entry(
      const std::vector<uint8_t>& entry,
      bool globally_committable,
      ccf::kv::Term term,
      ccf::kv::Version index)
    {
      put_entry(entry.data(), entry.size(), globally_committable, term, index);
    }

    /**
     * Put a single entry to be written the ledger, when primary.
     *
     * @param data Serialised entry start
     * @param size Serialised entry size
     * @param globally_committable True if entry is signature transaction
     * @param term Consensus term of entry
     * @param index Index (seqno) of entry
     *
     * Note: The entry should already contain its own header.
     */
    void put_entry(
      const uint8_t* data,
      size_t size,
      bool globally_committable,
      ccf::kv::Term /*term*/,
      ccf::kv::Version /*index*/)
    {
      serializer::ByteRange byte_range = {data, size};
      RINGBUFFER_WRITE_MESSAGE(
        ::consensus::ledger_append, to_host, globally_committable, byte_range);
    }

    /**
     * Skip a single entry, when backup.
     *
     * Does not write any entry to the legder.
     *
     * @param data Serialised entries
     * @param size Size of overall serialised entries
     */
    static void skip_entry(const uint8_t*& data, size_t& size)
    {
      auto header =
        serialized::read<ccf::kv::SerialisedEntryHeader>(data, size);
      serialized::skip(data, size, header.size);
    }

    /**
     * Truncate the ledger at a given index.
     *
     * @param idx Index to truncate from
     */
    void truncate(Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(
        ::consensus::ledger_truncate, to_host, idx, false /* no recovery */);
    }

    /**
     * Commit the ledger at a given index.
     *
     * @param idx Index to commit at
     */
    void commit(Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(::consensus::ledger_commit, to_host, idx);
    }

    /**
     * Initialise ledger at a given index (e.g. after a snapshot)
     *
     * @param idx Index to start ledger from
     * @param recovery_start_idx Index at which the recovery starts
     */
    void init(Index idx = 0, Index recovery_start_idx = 0)
    {
      RINGBUFFER_WRITE_MESSAGE(
        ::consensus::ledger_init, to_host, idx, recovery_start_idx);
    }
  };
}