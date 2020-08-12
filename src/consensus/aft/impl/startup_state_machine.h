// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "consensus/aft/aft_types.h"
#include "request_message.h"
#include "ds/ccf_exception.h"

#include <vector>

namespace aft
{
  class IStartupStateMachine
  {
  public:
    IStartupStateMachine() = default;
    virtual ~IStartupStateMachine() = default;

    virtual kv::Version receive_request(std::unique_ptr<RequestMessage> request) = 0;
  };

  class StartupStateMachine : public IStartupStateMachine
  {
  public:
    StartupStateMachine() : is_first_message(true) {}
    virtual ~StartupStateMachine() = default;

    kv::Version receive_request(std::unique_ptr<RequestMessage> request) override
    {
      LOG_INFO_FMT("CCCCCCCCCCCCCCCC");
      // TODO: the network is not open so we will execute everything inline
      // TODO: check that we are running on thread 0 - we do not want
      // multi-threading before the network is open

      std::shared_ptr<enclave::RpcContext>& ctx = request->get_request_ctx().ctx;
      std::shared_ptr<enclave::RpcHandler>& frontend = request->get_request_ctx().frontend;

      ctx->is_create_request = is_first_message;
      ctx->set_apply_writes(true);

      enclave::RpcHandler::ProcessPbftResp rep = frontend->process_pbft(ctx);

      frontend->update_merkle_tree();

      LOG_INFO_FMT("CCCCCCCCCCCCCCCC, version:{}, resp.size:{}", rep.version, rep.result.size());
      

      is_first_message = false;
      //throw ccf::ccf_logic_error("we should be here");
      request->callback(rep.result);

      return rep.version;
    }

  private:
    bool is_first_message;
  };
}