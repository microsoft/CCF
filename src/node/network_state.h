// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "identity.h"
#include "network_tables.h"
#include "new_ledger_secrets.h"

namespace ccf
{
  struct NetworkState : public NetworkTables
  {
    std::unique_ptr<NetworkIdentity> identity;
    std::shared_ptr<NewLedgerSecrets> ledger_secrets;
    // default set to Raft
    ConsensusType consensus_type = ConsensusType::CFT;

    NetworkState(const ConsensusType& consensus_type_) :
      NetworkTables(consensus_type_),
      consensus_type(consensus_type_)
    {}
    NetworkState() = default;
  };
}