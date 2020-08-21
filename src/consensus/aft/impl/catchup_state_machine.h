// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

//#include "consensus/aft/raft.h"
#include "aft_state.h"
#include "consensus/aft/raft_types.h"
#include "consensus/pbft/pbft_requests.h"
#include "enclave/rpc_map.h"
#include "kv/kv_types.h"
#include "node/node_to_node.h"

namespace aft
{
  class ICatchupStateMachine
  {
  public:
    ICatchupStateMachine() = default;
    virtual ~ICatchupStateMachine() = default;

    virtual void start() = 0;
    virtual bool is_message_type_supported(OArray& oa) = 0;
    virtual void receive_message(OArray oa, kv::NodeId from) = 0;
    virtual void add_node(kv::NodeId node_id) = 0;
  };

  std::unique_ptr<ICatchupStateMachine> create_catchup_state_machine(
    std::shared_ptr<ServiceState> state,
    std::shared_ptr<ccf::NodeToNode> channels,
    std::shared_ptr<enclave::RPCMap> rpc_map,
    Store<kv::DeserialiseSuccess>& store,
    pbft::RequestsMap& pbft_requests_map);
} 