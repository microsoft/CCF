// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "aft_state.h"
#include "catchup_state_machine.h"
#include "consensus/aft/raft.h"
//#include "consensus/aft/aft_network.h"
//#include "consensus/aft/aft_types.h"
#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "ds/thread_messaging.h"
#include "global_commit_handler.h"
#include "open_network_message.h"
//#include "replica.h"
#include "ds/spin_lock.h"
#include "request_message.h"
#include "startup_state_machine.h"

namespace aft
{
  class BftStateMachine : public StateMachine
  {
  public:
    BftStateMachine(
      std::shared_ptr<ServiceState> state_,
      const std::vector<uint8_t>& cert,
      std::unique_ptr<IStartupStateMachine> startup_state_machine_,
      std::unique_ptr<IGlobalCommitHandler> global_commit_handler_,
      std::unique_ptr<ICatchupStateMachine> catchup_state_machine_,
      std::shared_ptr<ccf::NodeToNode> channels_) :
      state(state_),
      startup_state_machine(std::move(startup_state_machine_)),
      global_commit_handler(std::move(global_commit_handler_)),
      catchup_state_machine(std::move(catchup_state_machine_)),
      channels(channels_)
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
        state->commit_idx = version;
        return;
      }
    }

    void receive_message(OArray&& oa, kv::NodeId from) override
    {
      if (
        state->network_state == ServiceState::NetworkState::not_open &&
        serialized::peek<RaftMsgType>(oa.data(), oa.size()) != bft_OpenNetwork)
      {
        startup_state_machine->receive_message(oa, from);
        return;
      }

      switch (serialized::peek<RaftMsgType>(oa.data(), oa.size()))
      {
        case bft_Status:
        case bft_RequestData:
          break;
        case bft_OpenNetwork:
          handle_open_network_message(std::move(oa), from);
          break;
        default:
          CCF_ASSERT_FMT_FAIL(
            "Unknown or unsupported message type - {}",
            serialized::peek<RaftMsgType>(oa.data(), oa.size()));
      }
    }

    void receive_message(OArray oa, AppendEntries, kv::NodeId from) override
    {
      //catchup_state_machine->receive_message(std::move(oa), ae, from);
      catchup_state_machine->receive_message(std::move(oa), from);

      // We obviously show not be committing here
      global_commit_handler->perform_global_commit(
        state->commit_idx, state->current_view);
    }

    void add_node(kv::NodeId node_id, const std::vector<uint8_t>& cert) override
    {
      std::lock_guard<SpinLock> lock(state->lock);
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
      std::vector<uint8_t> data(open_network_msg.size());
      open_network_msg.serialize_message(state->my_node_id, data.data(), data.size());
      channels->send_authenticated(ccf::NodeMsgType::consensus_msg, 0, data);
    }

    bool is_primary() override
    {
      return state->my_node_id == primary();
    }

    kv::NodeId primary() override
    {
      std::lock_guard<SpinLock> lock(state->lock);
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
      return state->commit_idx;
    }

  private:
    std::shared_ptr<ServiceState> state;
    std::unique_ptr<IStartupStateMachine> startup_state_machine;
    std::unique_ptr<IGlobalCommitHandler> global_commit_handler;
    std::unique_ptr<ICatchupStateMachine> catchup_state_machine;
    std::shared_ptr<ccf::NodeToNode> channels;

    void handle_open_network_message(OArray, kv::NodeId from)
    {
      if (state->network_state != ServiceState::NetworkState::not_open)
      {
        return;
      }

      state->received_open_network_messages.insert(from);
      {
        std::lock_guard<SpinLock> lock(state->lock);
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
  };
}
