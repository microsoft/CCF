// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "ccf/node_startup_state.h"
#include "ds/internal_logger.h"
#include "ds/state_machine.h"
#include "node/node_transport.h"
#include "node/node_types.h"
#include "tasks/basic_task.h"
#include "tasks/ordered_tasks.h"

#include <atomic>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ccf
{
  inline bool can_process_node_inbound_message(
    ::ds::StateMachine<NodeStartupState>& sm)
  {
    static const std::set<NodeStartupState> active_states{
      NodeStartupState::partOfNetwork,
      NodeStartupState::partOfPublicNetwork,
      NodeStartupState::readingPrivateLedger};

    return sm.check_one_of(active_states);
  }

  // Dispatches an inbound node message to the appropriate handler. Callers
  // must check can_process_node_inbound_message() before calling this.
  template <typename TForwarder, typename TChannels, typename TConsensus>
  void recv_node_inbound_message(
    NodeMsgType msg_type,
    const NodeId& from,
    const uint8_t* payload_data,
    size_t payload_size,
    TForwarder* cmd_forwarder,
    TChannels* n2n_channels,
    TConsensus* consensus)
  {
    switch (msg_type)
    {
      case forwarded_msg:
      {
        if (cmd_forwarder == nullptr)
        {
          LOG_FAIL_FMT(
            "Ignoring forwarded node message: command forwarder not "
            "initialised");
          return;
        }
        cmd_forwarder->recv_message(from, payload_data, payload_size);
        return;
      }
      case channel_msg:
      {
        if (n2n_channels == nullptr)
        {
          LOG_FAIL_FMT(
            "Ignoring channel node message: node-to-node channels not "
            "initialised");
          return;
        }
        n2n_channels->recv_channel_message(from, payload_data, payload_size);
        return;
      }
      case consensus_msg:
      {
        if (consensus == nullptr)
        {
          LOG_FAIL_FMT(
            "Ignoring consensus node message: consensus not initialised");
          return;
        }
        consensus->recv_message(from, payload_data, payload_size);
        return;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unknown node message type: {}", std::to_underlying(msg_type)));
      }
    }
  }

  // Serial execution domain for node ingress. Inbound peer frames, node ticks
  // and stop notices are executed in submission order on one critical
  // OrderedTasks lane, so they are mutually exclusive regardless of which
  // worker runs them. Must outlive the execution of its lane.
  class NodeIngress : public NodeInboundHandler
  {
  public:
    using Receiver =
      std::function<void(NodeMsgType, const NodeId&, const uint8_t*, size_t)>;

  private:
    std::shared_ptr<ccf::tasks::OrderedTasks> lane;
    Receiver receiver;
    std::atomic<bool> stopped = false;

  public:
    NodeIngress(ccf::tasks::JobBoard& job_board, Receiver receiver_) :
      lane(ccf::tasks::OrderedTasks::create(
        job_board, "Node ingress", ccf::tasks::TaskClass::Critical)),
      receiver(std::move(receiver_))
    {}

    // Thread-safe. The payload is owned by the queued action. Peer input is
    // untrusted: an exception while processing it drops that message only.
    void recv_node_inbound(
      NodeMsgType type,
      const NodeId& from,
      std::vector<uint8_t>&& payload) override
    {
      if (stopped.load())
      {
        LOG_DEBUG_FMT(
          "Ignoring node message from {} received during shutdown", from);
        return;
      }

      lane->add_action(ccf::tasks::make_basic_action(
        [this, type, from, payload = std::move(payload)]() {
          try
          {
            receiver(type, from, payload.data(), payload.size());
          }
          catch (const std::exception& e)
          {
            LOG_DEBUG_FMT(
              "Ignoring node_inbound message due to exception: {}", e.what());
          }
        },
        "Node inbound"));
    }

    // Thread-safe. Runs fn in order with inbound messages. Exceptions are not
    // caught, so failures in node-internal work remain fail-fast.
    void submit(std::string name, std::function<void()> fn)
    {
      if (stopped.load())
      {
        return;
      }

      lane->add_action(
        ccf::tasks::make_basic_action(std::move(fn), std::move(name)));
    }

    // Rejects further submissions. Queued work is discarded when the job board
    // shuts down.
    void stop()
    {
      stopped.store(true);
    }
  };
}
