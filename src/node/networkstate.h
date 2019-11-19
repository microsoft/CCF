// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "networksecrets.h"
#include "networktables.h"

#include <memory>

namespace ccf
{
  struct NetworkState : public NetworkTables
  {
    std::unique_ptr<NetworkSecrets> secrets;
    NetworkState(const ConsensusType& consensus_type) :
      NetworkTables(consensus_type)
    {}
    NetworkState() = default;
  };
}