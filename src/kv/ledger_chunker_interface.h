// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/version.h"

#include <map>
#include <numeric>

namespace ccf::kv
{
  struct ILedgerChunker
  {
    virtual ~ILedgerChunker() = default;

    virtual void append_entry_size(size_t) = 0;
    virtual void force_end_of_chunk(Version v) = 0;

    virtual bool is_chunk_end_requested(Version) = 0;

    virtual void rolled_back_to(Version) = 0;
    virtual void compacted_to(Version) = 0;

    virtual void produced_chunk_at(Version) = 0;
  };
}
