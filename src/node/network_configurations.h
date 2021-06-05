// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "entities.h"
#include "kv/map.h"
#include "node_info_network.h"
#include "service_map.h"

#include <set>

namespace ccf
{
  struct NetworkConfiguration
  {
    std::set<NodeId> nodes;
  };
  DECLARE_JSON_TYPE(NetworkConfiguration);
  DECLARE_JSON_REQUIRED_FIELDS(NetworkConfiguration, nodes);

  using NetworkConfigurations = ServiceMap<size_t, NetworkConfiguration>;
}