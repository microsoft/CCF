// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/aft_types.h"
#include "consensus/aft/aft_network.h"
#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "ds/thread_messaging.h"
#include "global_commit_handler.h"
#include "replica.h"
#include "startup_state_machine.h"
#include "status_message.h"

namespace aft
{
  class StateMachine : public IStateMachine
  {
  public:
    StateMachine(
      kv::NodeId my_node_id_,
      const std::vector<uint8_t>& cert,
      std::unique_ptr<IStartupStateMachine> startup_state_machine_,
      std::unique_ptr<IGlobalCommitHandler> global_commit_handler_,
      std::shared_ptr<EnclaveNetwork> network_) :
      my_node_id(my_node_id_),
      current_view(0),
      last_good_version(0),
      is_network_open(false),
      startup_state_machine(std::move(startup_state_machine_)),
      global_commit_handler(std::move(global_commit_handler_)),
      network(network_)
    {
      LOG_INFO_FMT("Starting AFT - my node id {}", my_node_id);
      add_node(my_node_id, cert);
    }

    // TODO: move this to thread 0
    void receive_request(std::unique_ptr<RequestMessage> request) override
    {
      if (!is_network_open)
      {
        kv::Version version = startup_state_machine->receive_request(std::move(request));

        // Before the network is open we say that every version has been
        // globally committed because we do not want to roll anything back.
        global_commit_handler->perform_global_commit(version, current_view);
        last_good_version = version;
        return;
      }

      ccf::ccf_logic_error("Not Implemented");
      // TODO: fill this in when we open the network
    }

    // TODO: move this to thread 0
    void receive_message(OArray&& oa, kv::NodeId from) override
    {
      if (!is_network_open)
      {
        startup_state_machine->receive_message(std::move(oa), from);
        return;
      }

      ccf::ccf_logic_error("Not Implemented");
      // TODO: fill this in when we open the network
    }

    void receive_message(OArray&& oa, AppendEntries ae, kv::NodeId from) override
    {
      if (!is_network_open)
      {
        kv::Version version = startup_state_machine->receive_message(std::move(oa), ae, from);
        global_commit_handler->perform_global_commit(version, current_view);
        return;
      }

      ccf::ccf_logic_error("Not Implemented");
      // TODO: fill this in when we open the network
    }


    void add_node(kv::NodeId node_id, const std::vector<uint8_t>& cert) override
    {
      std::lock_guard<std::mutex> lock(configuration_lock);
      LOG_INFO_FMT("Adding node {}", node_id);
      configuration.emplace(node_id, std::make_unique<Replica>(node_id, cert));
    }

    struct SendStatusMsg
    {
      SendStatusMsg(
        std::shared_ptr<Replica>& replica_,
        StateMachine* self_) :
        replica(replica_), self(self_)
      {}

      std::shared_ptr<Replica> replica;
      StateMachine* self;
    };

    static void send_status_cb(std::unique_ptr<threading::Tmsg<SendStatusMsg>> msg)
    {
      StatusMessage status(msg->data.self->current_view, msg->data.self->last_good_version);
      msg->data.self->network->Send(status, *msg->data.replica);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg),
        std::chrono::milliseconds(100)); // TODO: this should be configurable
    }

    // TODO: move this to thread 0
    void attempt_to_open_network() override
    {
      CCF_ASSERT(!is_network_open, "Cannot open a network that has already been opened");
      // TODO: send the network open messages
      // TODO: start sending the status messages

      std::lock_guard<std::mutex> lock(configuration_lock);
      for (auto& it : configuration)
      {
        if (it.first == my_node_id)
        {
          continue;
        }
        auto msg = std::make_unique<threading::Tmsg<SendStatusMsg>>(&send_status_cb, it.second, this);
        send_status_cb(std::move(msg)); 
      }
    }

    bool is_primary() override
    {
      return my_node_id == primary();
    }

    kv::NodeId primary() override
    {
      std::lock_guard<std::mutex> lock(configuration_lock);
      return current_view % configuration.size();
    }

    kv::Consensus::View view() override
    {
      return current_view;
    }

    kv::Consensus::View get_view_for_version(kv::Version version) override
    {
      return global_commit_handler->get_view_for_version(version);
    }

    kv::Version get_last_committed_version() override
    {
      return last_good_version;
    }


  private:
    kv::NodeId my_node_id;
    kv::Consensus::View current_view;
    kv::Version last_good_version;
    bool is_network_open;
    std::unique_ptr<IStartupStateMachine> startup_state_machine;
    std::unique_ptr<IGlobalCommitHandler> global_commit_handler;
    std::shared_ptr<EnclaveNetwork> network;
    kv::Version last_global_commit;

    std::map<kv::NodeId, std::shared_ptr<Replica>> configuration;
    SpinLock configuration_lock;
  };
}