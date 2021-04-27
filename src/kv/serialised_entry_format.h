// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"

#include <stdint.h>

namespace kv
{
  static constexpr auto entry_format_v1 = 1;

  // 6 bytes are used for the size of the serialised entry
  static const size_t max_entry_size = 1UL << 48;

  struct SerialisedEntryHeader
  {
    uint8_t version = entry_format_v1;
    uint8_t flags = 0;

    uint64_t size : (sizeof(uint64_t) - sizeof(uint8_t) - sizeof(uint8_t)) *
                    CHAR_BIT;

    void set_size(uint64_t size_)
    {
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