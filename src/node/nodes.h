// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "entities.h"
#include "kv/map.h"
#include "node/node_info.h"
#include "service_map.h"

#include <string>
#include <vector>

namespace ccf
{
  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(NodeInfo, NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfo, cert, quote_info, encryption_pub_key, status);
  DECLARE_JSON_OPTIONAL_FIELDS(NodeInfo, ledger_secret_seqno);

  using Nodes = ServiceMap<NodeId, NodeInfo>;
}
