// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/aft_types.h"
#include "ds/ccf_exception.h"
#include "kv/kv_types.h"
#include "request_message.h"
#include "status_message.h"

#include <vector>

namespace aft
{
  class IStartupStateMachine
  {
  public:
    IStartupStateMachine() = default;
    virtual ~IStartupStateMachine() = default;

    virtual kv::Version receive_request(std::unique_ptr<RequestMessage> request) = 0;
    virtual void receive_message(OArray&& oa, kv::NodeId from) = 0;
  };

  class StartupStateMachine : public IStartupStateMachine
  {
  public:
    StartupStateMachine() : is_first_message(true), have_requested_data(false) {}
    virtual ~StartupStateMachine() = default;

    kv::Version receive_request(std::unique_ptr<RequestMessage> request) override
    {
      // TODO: the network is not open so we will execute everything inline
      // TODO: check that we are running on thread 0 - we do not want
      // multi-threading before the network is open

      std::shared_ptr<enclave::RpcContext>& ctx = request->get_request_ctx().ctx;
      std::shared_ptr<enclave::RpcHandler>& frontend = request->get_request_ctx().frontend;

      ctx->pbft_raw.resize(request->size());
      request->serialize_message(ctx->pbft_raw.data(), ctx->pbft_raw.size());

      ctx->is_create_request = is_first_message;
      ctx->set_apply_writes(true);

      enclave::RpcHandler::ProcessPbftResp rep = frontend->process_pbft(ctx);

      frontend->update_merkle_tree();


      is_first_message = false;
      request->callback(rep.result);

      return rep.version;
    }

    void receive_message(OArray&& oa, kv::NodeId from) override
    {
      LOG_INFO_FMT("Received message from:{}, tag:{}", from, get_message_type(oa.data()));

      switch (get_message_type(oa.data()))
      {
        case MessageTag::Status:
          handle_status_message(std::move(oa), from);
          break;
        default:
          CCF_ASSERT_FMT_FAIL("Unknown or unsupported message type - {}", get_message_type(oa.data()));
      }
    }

  private:
    bool is_first_message;
    bool have_requested_data;

    void handle_status_message(OArray&& oa, kv::NodeId from)
    {
      if (have_requested_data)
      {
        // We have already requested data so need to do that again
        return;
      }

      StatusMessageRecv status(std::move(oa), from);

    }

  };
}