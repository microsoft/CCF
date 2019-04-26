// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"
#include "rafttypes.h"

#include <algorithm>
#include <cassert>
#include <sstream>

namespace raft
{
  class LedgerEnclave
  {
  private:
    std::unique_ptr<ringbuffer::AbstractWriter> to_host;

  public:
    LedgerEnclave(ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside())
    {}

    /**
     * Put a single entry to be written the ledger, when leader.
     *
     * @param entry Serialised entry
     */
    void put_entry(const std::vector<uint8_t>& entry)
    {
      // write the message
      RINGBUFFER_WRITE_MESSAGE(raft::log_append, to_host, entry);
    }

    /**
     * Record a single entry to the ledger, when follower.
     *
     * @param data Serialised entries
     * @param size Size of overall serialised entries
     *
     * @return Pair of boolean status (false if rejected), raw data as a vector
     */
    std::pair<std::vector<uint8_t>, bool> record_entry(
      const uint8_t*& data, size_t& size)
    {
      auto entry_len = serialized::read<uint32_t>(data, size);
      std::vector<uint8_t> entry(data, data + entry_len);

      RINGBUFFER_WRITE_MESSAGE(raft::log_append, to_host, entry);

      serialized::skip(data, size, entry_len);

      return std::make_pair(std::move(entry), true);
    }

    /**
     * Skip a single entry, when follower.
     *
     * Does not write any entry to the legder.
     *
     * @param data Serialised entries
     * @param size Size of overall serialised entries
     */
    void skip_entry(const uint8_t*& data, size_t& size)
    {
      auto entry_len = serialized::read<uint32_t>(data, size);
      serialized::skip(data, size, entry_len);
    }

    /**
     * Truncate the ledger at a given index.
     *
     * @param idx Index to truncate from
     */
    void truncate(Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(raft::log_truncate, to_host, idx);
    }
  };
}
