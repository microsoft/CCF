// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

#include <unordered_set>

namespace raft
{
  static constexpr auto replicate_type_raft = kv::ReplicateType::ALL;
  static const std::unordered_set<std::string> replicated_tables_raft = {};
}