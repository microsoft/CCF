// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <nlohmann/json.hpp>
#include <small_vector/SmallVector.h>

namespace kv::serialisers
{
  using SerialisedEntry = llvm_vecsmall::SmallVector<uint8_t, 8>;
}
