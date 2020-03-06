// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "identity.h"
#include "ledgersecrets.h"
#include "networkencryption.h"
#include "networktables.h"

namespace ccf
{
  struct NetworkState : public NetworkTables
  {
    std::unique_ptr<NetworkIdentity> identity;
    std::shared_ptr<LedgerSecrets> ledger_secrets;
    std::unique_ptr<NetworkEncryptionKey> encryption_key;

    NetworkState(const ConsensusType& consensus_type) :
      NetworkTables(consensus_type)
    {}
    NetworkState() = default;
  };
}