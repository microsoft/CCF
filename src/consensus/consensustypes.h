// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <stdint.h>

namespace ccf
{
  using ObjectId = uint64_t;
  using NodeId = ObjectId;
  using Index = int64_t;
}

namespace consensus
{
#pragma pack(push, 1)
  struct AppendEntriesIndex
  {
    ccf::Index idx;
    ccf::Index prev_idx;
  };

#pragma pack(pop)
}