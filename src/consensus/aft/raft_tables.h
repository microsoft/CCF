// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "node/entities.h"

#include <unordered_set>

namespace aft
{
  // The KV provides an option to select which tables are replicated and which
  // are not.
  static constexpr auto replicate_type = kv::ReplicateType::ALL;
  static const std::unordered_set<std::string> replicated_tables = {};
}