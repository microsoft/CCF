// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "startup_state_machine.h"

#include "consensus/aft/aft_network.h"
#include "consensus/aft/request.h"
#include "consensus/ledger_enclave.h"
#include "consensus/pbft/pbft_requests.h"
#include "ds/ccf_exception.h"
#include "http/http_rpc_context.h"
#include "kv/tx.h"
#include "request_data_message.h"
#include "request_message.h"
#include "status_message.h"

#include <vector>

namespace aft
{
  class StartupStateMachine : public IStartupStateMachine
  {
  public:
    StartupStateMachine(
      std::shared_ptr<EnclaveNetwork> network_,
      pbft::RequestsMap& pbft_requests_map_) :
      network(network_),
      pbft_requests_map(pbft_requests_map_),
      is_first_message(true),
      last_version(kv::NoVersion)
    {}
    virtual ~StartupStateMachine() = default;

    kv::Version receive_request(std::unique_ptr<RequestMessage> request) override
    {
      CCF_ASSERT(
        threading::get_current_thread_id() ==
          threading::ThreadMessaging::main_thread,
        "Should be executed on the main thread");

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

      last_version = rep.version;
      return rep.version;
    }

    bool receive_message(OArray& oa, kv::NodeId from) override
    {
      CCF_ASSERT(
        threading::get_current_thread_id() ==
          threading::ThreadMessaging::main_thread,
        "Should be executed on the main thread");

      switch (get_message_type(oa.data()))
      {
        case MessageTag::Status:
          handle_status_message(std::move(oa), from);
          break;
        case MessageTag::RequestData:
          handle_request_data_message(std::move(oa), from);
          break;
        default:
          CCF_ASSERT_FMT_FAIL("Unsupported msg type {}", get_message_type(oa.data()));
          return false;
      }
      return true;
    }

    bool is_message_type_supported(OArray& oa) override
    {
      switch (get_message_type(oa.data()))
      {
        case MessageTag::Status:
        case MessageTag::RequestData:
          return true;
        default:
          return false;
      }
    }

  private:
    std::shared_ptr<EnclaveNetwork> network;
    bool is_first_message;
    pbft::RequestsMap& pbft_requests_map;
    kv::Version last_version = kv::NoVersion;

    void handle_status_message(OArray&& oa, kv::NodeId from)
    {
      StatusMessageRecv status(std::move(oa), from);
      LOG_INFO_FMT("****** last {}, status {}", last_version, status.get_version());
      if (last_version > status.get_version())
      {
        // We have already requested data so need to do that again
        return;
      }

      RequestDataMessage request(
        std::max(last_version, (int64_t)0), status.get_version());
      network->Send(request, from);
    }

    void handle_request_data_message(OArray && oa, kv::NodeId from)
    {
      RequestDataMessageRecv request(std::move(oa), from);

      kv::Version index_from = request.get_from();
      kv::Version index_to = request.get_to();

      LOG_INFO_FMT("Sending entries {} to {}, to node {}", index_from, index_to, from);

      AppendEntries ae = {
        aft_append_entries, network->get_my_node_id(), index_to, index_from};
      network->Send(ae, from);
    }
  };

  std::unique_ptr<IStartupStateMachine> create_startup_state_machine(
    std::shared_ptr<EnclaveNetwork> network,
    pbft::RequestsMap& pbft_requests_map)
  {
    return std::make_unique<StartupStateMachine>(
      network, pbft_requests_map);
  }
}