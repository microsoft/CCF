// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Common typedefs for use by indexing system

#include "ccf/tx_id.h"
#include "ds/contiguous_set.h"

#include <memory>

namespace kv
{
  class Store;
}

namespace ccf::indexing
{
  using StorePtr = std::shared_ptr<kv::Store>;
  using SeqNoCollection = ds::ContiguousSet<ccf::SeqNo>;
}
