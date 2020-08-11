// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "impl/state_machine.h"

namespace aft
{
  std::unique_ptr<IStateMachine> create_state_machine(
    kv::NodeId my_node_id, const std::vector<uint8_t>& cert)
  {
    return std::make_unique<StateMachine>(
      my_node_id, cert, std::make_unique<StartupStateMachine>());
  }
}