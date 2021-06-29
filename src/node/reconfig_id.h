// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "network_state.h"

namespace ccf
{
  inline size_t get_next_reconfiguration_id(
    ccf::NetworkState& network, kv::ReadOnlyTx& tx)
  {
    auto nodes = tx.ro(network.nodes);

    size_t max_id = 0;
    nodes->foreach([&max_id](const auto& node_id, const auto& node_info) {
      max_id = std::max(max_id, node_info.reconfiguration_id);
      return true;
    });

    return max_id + 1;
  }
}
