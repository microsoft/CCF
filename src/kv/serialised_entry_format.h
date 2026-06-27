// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"

#include <climits>
#include <fmt/format.h>
#include <stdint.h>
#include <string>

namespace ccf::kv
{
  static constexpr auto entry_format_v1 = 1;
  using SerialisedEntryFlags = uint8_t;

  enum EntryFlags : SerialisedEntryFlags
  {
    FORCE_LEDGER_CHUNK_AFTER = 0x01,
    FORCE_LEDGER_CHUNK_BEFORE = 0x02
  };

  struct SerialisedEntryHeader
  {
    uint8_t version = entry_format_v1;
    SerialisedEntryFlags flags = 0;

    static constexpr auto BITS_FOR_SIZE =
      (sizeof(uint64_t) - sizeof(uint8_t) - sizeof(SerialisedEntryFlags)) *
      CHAR_BIT;
    static constexpr uint64_t max_serialised_entry_body_size =
      (uint64_t{1} << BITS_FOR_SIZE) - 1;
    uint64_t size : BITS_FOR_SIZE = 0;

    void set_size(uint64_t size_)
    {
      CCF_ASSERT_FMT(
        size_ <= max_serialised_entry_body_size,
        "Cannot serialise entry of size {} (max allowed size is {})",
        size_,
        max_serialised_entry_body_size);
      size = size_;
    }
  };
  static_assert(sizeof(SerialisedEntryHeader) == sizeof(uint64_t));

  static constexpr size_t serialised_entry_header_size =
    sizeof(SerialisedEntryHeader);

  static inline std::string describe_serialized_entry_size_error(
    size_t body_size, size_t max_body_size, const char* operation)
  {
    return fmt::format(
      "Cannot {} transaction with serialised body size {} bytes. The "
      "configured maximum is {} bytes. The transaction size compared to this "
      "limit is the size stored in the ledger entry header: the serialised "
      "transaction body after the fixed {}-byte ledger entry header, "
      "including any ledger encryption header, public domain size field, "
      "public domain and encrypted private domain.",
      operation,
      body_size,
      max_body_size,
      serialised_entry_header_size);
  }
}