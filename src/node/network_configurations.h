// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "entities.h"
#include "kv/map.h"
#include "network_tables.h"
#include "node_info_network.h"
#include "quote_info.h"
#include "service_map.h"

#include <string>
#include <vector>

namespace ccf
{
  using NetworkConfigurations =
    ServiceMap<kv::ReconfigurationId, kv::NetworkConfiguration>;
}
