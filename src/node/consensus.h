// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/nodetonode.h"
#include "consensus/raft/ledgerenclave.h"
#include "consensus/raft/raft.h"

namespace ccf
{
  using ConsensusRaft = raft::Raft<raft::LedgerEnclave, NodeToNode>;
}