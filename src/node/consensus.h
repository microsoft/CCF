// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/raft/consensus_raft.h"
#include "consensus/raft/ledgerenclave.h"
#include "node/nodetonode.h"

namespace ccf
{
  using RaftConsensusType = raft::ConsensusRaft<raft::LedgerEnclave, NodeToNode>;
  using RaftType = raft::Raft<raft::LedgerEnclave, NodeToNode>;
}