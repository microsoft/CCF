// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "aft_state.h"
#include "global_commit_handler.h"
#include "request_message.h"
#include "state_machine.h"

namespace aft
{
  std::unique_ptr<StateMachine> create_bft_state_machine(
    std::shared_ptr<ServiceState> shared_state,
    std::shared_ptr<ccf::NodeToNode> channels,
    pbft::RequestsMap& requests_map,
    Store<kv::DeserialiseSuccess>& store,
    std::shared_ptr<enclave::RPCMap> rpc_map,
    const std::vector<uint8_t>& cert)
  {
    auto startup_state_machine =
      create_startup_state_machine(shared_state, channels, requests_map);
    auto global_commit_handler = create_global_commit_handler(store);
    auto catchup_state_machine = create_catchup_state_machine(
      shared_state, channels, rpc_map, store, requests_map);
    return std::make_unique<BftStateMachine>(
      shared_state,
      cert,
      std::move(startup_state_machine),
      std::move(global_commit_handler),
      std::move(catchup_state_machine),
      channels);
  }
}