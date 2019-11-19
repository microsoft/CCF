// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv/kvtypes.h"

#include <unordered_set>

namespace pbft
{
  static constexpr auto replicate_type_pbft = kv::ReplicateType::NONE;
  static const std::unordered_set<std::string> replicated_tables_pbft = {};
}
