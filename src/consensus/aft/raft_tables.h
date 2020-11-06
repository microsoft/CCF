// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "node/entities.h"

#include <unordered_set>

namespace aft
{
  static constexpr auto replicate_type_raft = kv::ReplicateType::ALL;
  static const std::unordered_set<std::string> replicated_tables_raft = {};

  static constexpr auto replicate_type_bft = kv::ReplicateType::SOME;
  static const std::unordered_set<std::string> replicated_tables_bft = {
    ccf::Tables::AFT_REQUESTS,
    ccf::Tables::SIGNATURES,
    ccf::Tables::BACKUP_SIGNATURES,
    ccf::Tables::NONCES,
    ccf::Tables::NEW_VIEWS};
}