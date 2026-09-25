// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/ccf_assert.h"
#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"

#include <fmt/format.h>

namespace consensus
{
  class LedgerEnclave
  {
  private:
    static size_t get_entry_size(const uint8_t* data, size_t size)
    {
      if (size < ccf::kv::serialised_entry_header_size)
      {
        throw std::logic_error(fmt::format(
          "Cannot read transaction header: buffer contains {} bytes, but the "
          "fixed ledger entry header requires {} bytes",
          size,
          ccf::kv::serialised_entry_header_size));
      }

      const auto header =
        serialized::peek<ccf::kv::SerialisedEntryHeader>(data, size);
      const size_t body_size = header.size;
      const auto available_body_size =
        size - ccf::kv::serialised_entry_header_size;

      // The size in the entry header is not trusted: check it against the
      // buffer we were given before allocating. This is distinct from the
      // configured max_transaction_size, which applies only when serialising
      // new transactions, so that entries written under a larger or unset
      // limit can always be read back.
      if (body_size > available_body_size)
      {
        throw std::logic_error(fmt::format(
          "Cannot read transaction with serialised body size {} bytes from "
          "buffer containing {} bytes after the fixed {}-byte ledger entry "
          "header",
          body_size,
          available_body_size,
          ccf::kv::serialised_entry_header_size));
      }

      return ccf::kv::serialised_entry_header_size + body_size;
    }

  public:
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
      const auto entry_size = get_entry_size(data, size);
      std::vector<uint8_t> entry(data, data + entry_size);
      serialized::skip(data, size, entry_size);
      return entry;
    }

  private:
    std::shared_ptr<AbstractLedgerWriter> ledger;

  public:
    LedgerEnclave(std::shared_ptr<AbstractLedgerWriter> ledger_) :
      ledger(std::move(ledger_))
    {
      if (ledger == nullptr)
      {
        throw std::logic_error("A ledger writer must be provided");
      }
    }

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
      [[maybe_unused]] ccf::kv::Term term,
      [[maybe_unused]] ccf::kv::Version index)
    {
      std::vector<uint8_t> entry(data, data + size);
      if (!ledger->append(std::move(entry), globally_committable))
      {
        throw std::logic_error("Ledger rejected append");
      }
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
      serialized::skip(data, size, get_entry_size(data, size));
    }

    /**
     * Truncate the ledger at a given index.
     *
     * @param idx Index to truncate from
     */
    void truncate(Index idx)
    {
      if (!ledger->truncate(idx, false /* no recovery */))
      {
        throw std::logic_error("Ledger rejected truncation");
      }
    }

    /**
     * Commit the ledger at a given index.
     *
     * @param idx Index to commit at
     */
    void commit(Index idx)
    {
      if (!ledger->commit(idx))
      {
        throw std::logic_error("Ledger rejected commit");
      }
    }

    /**
     * Initialise ledger at a given index (e.g. after a snapshot)
     *
     * @param idx Index to start ledger from
     * @param recovery_start_idx Index at which the recovery starts
     */
    void init(Index idx = 0, Index recovery_start_idx = 0)
    {
      if (!ledger->init(idx, recovery_start_idx))
      {
        throw std::logic_error("Ledger rejected initialisation");
      }
    }
  };
}