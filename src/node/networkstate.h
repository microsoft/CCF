// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "identity.h"
#include "ledgersecrets.h"
#include "networktables.h"

namespace ccf
{
  struct NetworkState : public NetworkTables
  {
    std::unique_ptr<NetworkIdentity> identity;
    std::shared_ptr<LedgerSecrets> ledger_secrets;
    std::vector<uint8_t> encryption_priv_key;
    // default set to Raft
    ConsensusType consensus_type = ConsensusType::RAFT;

    NetworkState(const ConsensusType& consensus_type_) :
      consensus_type(consensus_type_),
      NetworkTables(consensus_type_)
    {}
    NetworkState() = default;
  };
}