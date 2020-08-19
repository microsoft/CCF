// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "aft_state.h"
#include "consensus/aft/aft_types.h"
#include "kv/kv_types.h"

namespace aft
{
  class RequestMessage;

  class IStartupStateMachine
  {
  public:
    IStartupStateMachine() = default;
    virtual ~IStartupStateMachine() = default;

    virtual kv::Version receive_request(
      std::unique_ptr<RequestMessage> request) = 0;
    virtual bool receive_message(OArray& oa, kv::NodeId from) = 0;
    virtual bool is_message_type_supported(OArray& oa) = 0;
  };

  std::unique_ptr<IStartupStateMachine> create_startup_state_machine(
    std::shared_ptr<ServiceState> state,
    std::shared_ptr<EnclaveNetwork> network_,
    pbft::RequestsMap& pbft_requests_map_);
}