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
    std::unique_ptr<LedgerSecrets> ledger_secrets;

    NetworkState(const ConsensusType& consensus_type) :
      NetworkTables(consensus_type)
    {}
    NetworkState() = default;
  };
}