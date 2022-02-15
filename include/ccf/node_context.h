// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "ccf/host_processes_interface.h"
#include "ccf/indexing/indexer_interface.h"
#include "ccf/indexing/lfs_interface.h"

namespace ccfapp
{
  struct AbstractNodeContext
  {
    virtual ~AbstractNodeContext() = default;

    virtual ccf::NodeId get_node_id() const = 0;
    virtual ccf::historical::AbstractStateCache& get_historical_state() = 0;
    virtual ccf::indexing::IndexingStrategies& get_indexing_strategies() = 0;
    virtual ccf::indexing::AbstractLFSAccess& get_lfs_access() = 0;

    virtual ccf::AbstractHostProcesses* get_host_processes() = 0;
  };
}
