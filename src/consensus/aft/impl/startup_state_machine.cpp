// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "startup_state_machine.h"

#include "consensus/aft/aft_network.h"
#include "consensus/aft/request.h"
#include "consensus/ledger_enclave.h"
#include "consensus/pbft/pbft_requests.h"
#include "ds/ccf_exception.h"
#include "execution_utilities.h"
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
      std::shared_ptr<ServiceState> state_,
      std::shared_ptr<EnclaveNetwork> network_,
      pbft::RequestsMap& pbft_requests_map_) :
      state(state_),
      network(network_),
      pbft_requests_map(pbft_requests_map_)
    {}

    virtual ~StartupStateMachine() = default;

    kv::Version receive_request(
      std::unique_ptr<RequestMessage> request) override
    {
      CCF_ASSERT(
        threading::get_current_thread_id() ==
          threading::ThreadMessaging::main_thread,
        "Should be executed on the main thread");
      return ExecutionUtilities::execute_request(
        std::move(request), state->last_committed_version == 0);
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
          CCF_ASSERT_FMT_FAIL(
            "Unsupported msg type {}", get_message_type(oa.data()));
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
    std::shared_ptr<ServiceState> state;
    std::shared_ptr<EnclaveNetwork> network;
    pbft::RequestsMap& pbft_requests_map;

    void handle_status_message(OArray&& oa, kv::NodeId from)
    {
      StatusMessageRecv status(std::move(oa), from);
      LOG_TRACE_FMT(
        "last {}, status {}",
        state->last_committed_version,
        status.get_version());
      if (state->last_committed_version > status.get_version())
      {
        // We have already requested data so need to do that again
        return;
      }

      RequestDataMessage request(
        std::max(state->last_committed_version, (int64_t)0),
        status.get_version());
      network->Send(request, from);
    }

    void handle_request_data_message(OArray&& oa, kv::NodeId from)
    {
      RequestDataMessageRecv request(std::move(oa), from);

      kv::Version index_from = request.get_from();
      kv::Version index_to = request.get_to();

      LOG_TRACE_FMT(
        "Sending entries {} to {}, to node {}", index_from, index_to, from);

      AppendEntries ae = {
        aft_append_entries, network->get_my_node_id(), index_to, index_from};
      network->Send(ae, from);
    }
  };

  std::unique_ptr<IStartupStateMachine> create_startup_state_machine(
    std::shared_ptr<ServiceState> state,
    std::shared_ptr<EnclaveNetwork> network,
    pbft::RequestsMap& pbft_requests_map)
  {
    return std::make_unique<StartupStateMachine>(
      state, network, pbft_requests_map);
  }
}