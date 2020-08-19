// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "aft_state.h"
#include "catchup_state_machine.h"
#include "consensus/aft/aft_network.h"
#include "consensus/aft/aft_types.h"
#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "ds/thread_messaging.h"
#include "global_commit_handler.h"
#include "open_network_message.h"
#include "replica.h"
#include "request_message.h"
#include "startup_state_machine.h"

namespace aft
{
  class StateMachine : public IStateMachine
  {
  public:
    StateMachine(
      std::shared_ptr<ServiceState> state_,
      const std::vector<uint8_t>& cert,
      std::unique_ptr<IStartupStateMachine> startup_state_machine_,
      std::unique_ptr<IGlobalCommitHandler> global_commit_handler_,
      std::unique_ptr<ICatchupStateMachine> catchup_state_machine_,
      std::shared_ptr<EnclaveNetwork> network_) :
      state(state_),
      startup_state_machine(std::move(startup_state_machine_)),
      global_commit_handler(std::move(global_commit_handler_)),
      catchup_state_machine(std::move(catchup_state_machine_)),
      network(network_)
    {
      LOG_INFO_FMT("Starting AFT - my node id {}", state_->my_node_id);
      add_node(state_->my_node_id, cert);
    }

    void receive_request(std::unique_ptr<RequestMessage> request) override
    {
      if (state->network_state == ServiceState::NetworkState::not_open)
      {
        kv::Version version =
          startup_state_machine->receive_request(std::move(request));

        // Before the network is open we say that every version has been
        // globally committed because we do not want to roll anything back.
        global_commit_handler->perform_global_commit(
          version, state->current_view);
        state->last_committed_version = version;
        return;
      }
    }

    void receive_message(OArray oa, kv::NodeId from) override
    {
      if (
        state->network_state == ServiceState::NetworkState::not_open &&
        get_message_type(oa.data()) != MessageTag::OpenNetwork)
      {
        startup_state_machine->receive_message(oa, from);
        return;
      }

      switch (get_message_type(oa.data()))
      {
        case MessageTag::Status:
        case MessageTag::RequestData:
          break;
        case MessageTag::OpenNetwork:
          handle_open_network_message(std::move(oa), from);
          break;
        default:
          CCF_ASSERT_FMT_FAIL(
            "Unknown or unsupported message type - {}",
            get_message_type(oa.data()));
      }
    }

    void receive_message(OArray oa, AppendEntries ae, kv::NodeId from) override
    {
      catchup_state_machine->receive_message(std::move(oa), ae, from);

      // We obviously show not be committing here
      global_commit_handler->perform_global_commit(
        state->last_committed_version, state->current_view);
    }

    void add_node(kv::NodeId node_id, const std::vector<uint8_t>& cert) override
    {
      std::lock_guard<std::mutex> lock(state->configuration_lock);
      LOG_INFO_FMT("Adding node {}", node_id);
      state->configuration.emplace(
        node_id, std::make_unique<Replica>(node_id, cert));
      catchup_state_machine->add_node(node_id);
    }

    void attempt_to_open_network() override
    {
      LOG_INFO_FMT("Opening network");
      CCF_ASSERT_FMT(
        state->network_state == ServiceState::NetworkState::not_open,
        "Cannot open a network current state is {}",
        state->network_state);

      if (state->my_node_id == 0)
      {
        state->received_open_network_messages.insert(state->my_node_id);
        return;
      }
      LOG_INFO_FMT(
        "****** Network is now open and ready to accept requests ******");
      state->network_state = ServiceState::NetworkState::open;

      OpenNetworkMessage open_network_msg;
      network->Send(open_network_msg, 0);
    }

    void handle_open_network_message(OArray oa, kv::NodeId from)
    {
      if (state->network_state != ServiceState::NetworkState::not_open)
      {
        return;
      }

      state->received_open_network_messages.insert(from);
      {
        std::lock_guard<std::mutex> lock(state->configuration_lock);
        if (
          state->received_open_network_messages.size() ==
          state->configuration.size())
        {
          LOG_INFO_FMT(
            "****** Network is now open and ready to accept requests ******");
          state->network_state = ServiceState::NetworkState::open;
        }
      }
    }

    bool is_primary() override
    {
      return state->my_node_id == primary();
    }

    kv::NodeId primary() override
    {
      std::lock_guard<std::mutex> lock(state->configuration_lock);
      return state->current_view % state->configuration.size();
    }

    kv::Consensus::View view() override
    {
      return state->current_view;
    }

    kv::Consensus::View get_view_for_version(kv::Version version) override
    {
      return global_commit_handler->get_view_for_version(version);
    }

    kv::Version get_last_committed_version() override
    {
      return state->last_committed_version;
    }

  private:
    std::shared_ptr<ServiceState> state;
    std::unique_ptr<IStartupStateMachine> startup_state_machine;
    std::unique_ptr<IGlobalCommitHandler> global_commit_handler;
    std::unique_ptr<ICatchupStateMachine> catchup_state_machine;
    std::shared_ptr<EnclaveNetwork> network;
  };
}