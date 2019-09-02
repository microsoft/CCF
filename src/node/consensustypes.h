// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef PBFT
#  include "consensus/pbft/pbft.h"
#endif

#include "consensus/ledgerenclave.h"
#include "consensus/raft/raftconsensus.h"
#include "node/nodetonode.h"

namespace ccf
{
#ifdef PBFT
  using PbftConsensusType = pbft::Pbft<consensus::LedgerEnclave, NodeToNode>;
#endif
  using RaftConsensusType =
    raft::RaftConsensus<consensus::LedgerEnclave, NodeToNode>;
  using RaftType = raft::Raft<consensus::LedgerEnclave, NodeToNode>;
}