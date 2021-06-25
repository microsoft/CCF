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
  using NetworkConfigurations = ServiceMap<size_t, std::unordered_set<NodeId>>;
}
