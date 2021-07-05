// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "network_tables.h"

#include <algorithm>

namespace ccf
{
  kv::ReconfigurationId CONFIG_COUNT_KEY = 0;

  inline kv::ReconfigurationId get_next_reconfiguration_id(
    ccf::NetworkTables& tables, kv::ReadOnlyTx& tx)
  {
    auto nconfigs = tx.ro(tables.network_configurations);
    auto e = nconfigs->get(CONFIG_COUNT_KEY);
    if (!e.has_value())
    {
      return 1;
    }
    else
    {
      return e.value().rid + 1;
    }
  }

  inline kv::NetworkConfiguration get_latest_network_configuration(
    ccf::NetworkTables& tables, kv::Tx& tx)
  {
    auto nconfigs = tx.ro(tables.network_configurations);
    auto e = nconfigs->get(CONFIG_COUNT_KEY);
    if (e.has_value())
    {
      return nconfigs->get(e.value().rid).value();
    }
    return {};
  }

  inline void add_new_network_reconfiguration(
    ccf::NetworkTables& tables, kv::Tx& tx, kv::NetworkConfiguration& config)
  {
    config.rid = get_next_reconfiguration_id(tables, tx);
    LOG_DEBUG_FMT(
      "Configurations: adding new entry to network_configurations table: {}",
      config);
    auto nconfigs = tx.rw(tables.network_configurations);
    nconfigs->put(config.rid, config);
    nconfigs->put(CONFIG_COUNT_KEY, {config.rid, {}});
  }
}
