// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"

#include <stdint.h>

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
    uint64_t size : BITS_FOR_SIZE = 0;

    void set_size(uint64_t size_)
    {
      [[maybe_unused]] static constexpr size_t max_entry_size = 1UL
        << BITS_FOR_SIZE;
      CCF_ASSERT_FMT(
        size_ < max_entry_size,
        "Cannot serialise entry of size {} (max allowed size is {})",
        size_,
        max_entry_size);
      size = size_;
    }
  };
  static_assert(sizeof(SerialisedEntryHeader) == sizeof(uint64_t));

  static constexpr size_t serialised_entry_header_size =
    sizeof(SerialisedEntryHeader);
}