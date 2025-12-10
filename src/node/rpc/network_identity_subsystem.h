// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/network_identity_interface.h"
#include "node/identity.h"
#include "node/rpc/node_interface.h"

namespace ccf
{
  class NetworkIdentitySubsystem : public NetworkIdentitySubsystemInterface
  {
  protected:
    AbstractNodeState& node_state;
    const std::unique_ptr<NetworkIdentity>& network_identity;

  public:
    NetworkIdentitySubsystem(
      AbstractNodeState& node_state_,
      const std::unique_ptr<NetworkIdentity>& network_identity_) :
      node_state(node_state_),
      network_identity(network_identity_)
    {}

    const std::unique_ptr<NetworkIdentity>& get() override
    {
      return network_identity;
    }
  };
}
