// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

#include <unordered_set>

namespace pbft
{
  struct Tables
  {
    static constexpr auto PBFT_REQUESTS = "ccf.pbft.requests";
    static constexpr auto PBFT_PRE_PREPARES = "ccf.pbft.preprepares";
  };

  static constexpr auto replicate_type_pbft = kv::ReplicateType::SOME;
  static const std::unordered_set<std::string> replicated_tables_pbft = {
    Tables::PBFT_REQUESTS, Tables::PBFT_PRE_PREPARES};
}
