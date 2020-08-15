// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "catchup_state_machine.h"

#include "aft_state.h"
#include "consensus/aft/aft_network.h"
#include "ds/thread_messaging.h"
#include "status_message.h"

namespace aft
{
  class CatchupStateMachine : public ICatchupStateMachine
  {
  public:
    CatchupStateMachine(
      std::shared_ptr<ServiceState> state_,
      std::shared_ptr<EnclaveNetwork> network_) :
      state(state_), network(network_)
    {}

    void start() override
    {
      {
        std::lock_guard<std::mutex> lock(state->configuration_lock);
        for (auto& it : state->configuration)
        {
          if (it.first == state->my_node_id)
          {
            continue;
          }

          add_node(it.first);
        }
      }

    }
    
    void receive_message() override
    {

    }


    void add_node(kv::NodeId node_id) override
    {
      auto it = known_nodes.find(node_id);
      if (
        //state->network_state == ServiceState::NetworkState::not_open ||
        node_id == state->my_node_id ||
        it != known_nodes.end())
      {
        return;
      }
      known_nodes.emplace(node_id);

      auto msg = std::make_unique<threading::Tmsg<SendStatusMsg>>(
        &send_status_cb, node_id, this);
      send_status_cb(std::move(msg));
    }

  private:
    std::shared_ptr<ServiceState> state;
    std::shared_ptr<EnclaveNetwork> network;
    std::set<kv::NodeId> known_nodes;

    struct SendStatusMsg
    {
      SendStatusMsg(
        kv::NodeId node_id_,
        CatchupStateMachine* self_) :
        node_id(node_id_), self(self_)
      {}

      kv::NodeId node_id;
      CatchupStateMachine* self;
    };


    static void send_status_cb(std::unique_ptr<threading::Tmsg<SendStatusMsg>> msg)
    {
      StatusMessage status(msg->data.self->state->current_view, msg->data.self->state->last_committed_version);
      msg->data.self->network->Send(status, msg->data.node_id);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg),
        std::chrono::milliseconds(100)); // TODO: this should be configurable
    }

  };

  std::unique_ptr<ICatchupStateMachine> create_catchup_state_machine(
    std::shared_ptr<ServiceState> state,
    std::shared_ptr<EnclaveNetwork> network)
  {
    return std::make_unique<CatchupStateMachine>(state, network);
  }
}