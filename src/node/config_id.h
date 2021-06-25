// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "node/network_configurations.h"
#include "node/network_state.h"

namespace ccf
{
  size_t get_fresh_config_id(const NetworkState& network, kv::Tx& tx)
  {
    size_t r = 0;
    auto cfgs = tx.ro(network.network_configurations);
    cfgs->foreach([&r](size_t id, auto) {
      r = std::max(r, id);
      return true;
    });
    return r;
  }
}
