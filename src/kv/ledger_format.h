// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdint.h>

namespace kv
{
  static constexpr auto entry_format_v1 = 1;

  struct SerialisedEntryHeader
  {
    uint8_t version = entry_format_v1;
    uint8_t flags = 0;

    uint64_t size : (sizeof(uint64_t) - sizeof(uint8_t) - sizeof(uint8_t)) *
                    CHAR_BIT;

    void set_size(uint64_t size_)
    {
      // TODO: Maximum size
      // CCF_ASSERT_FMT(size_ <= max_entry_size, "");

      size = size_;
    }
  };
  static_assert(sizeof(SerialisedEntryHeader) == sizeof(uint64_t));

  static constexpr size_t serialised_entry_header_size =
    sizeof(SerialisedEntryHeader);
}