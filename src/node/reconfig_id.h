// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "network_tables.h"

#include <algorithm>

namespace ccf
{
  inline kv::ReconfigurationId get_next_reconfiguration_id(
    ccf::NetworkTables& tables, kv::ReadOnlyTx& tx)
  {
    auto nconfigs = tx.ro(tables.network_configuration);
    auto e = nconfigs->get();
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
    auto nconfigs = tx.ro(tables.network_configuration);
    return nconfigs->get().value_or(kv::NetworkConfiguration{});
  }

  inline void add_new_network_reconfiguration(
    ccf::NetworkTables& tables, kv::Tx& tx, kv::NetworkConfiguration& config)
  {
    config.rid = get_next_reconfiguration_id(tables, tx);
    auto nconfigs = tx.rw(tables.network_configuration);
    nconfigs->put(config);
  }
}
