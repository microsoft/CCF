// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "ccf/node_startup_state.h"
#include "ds/internal_logger.h"
#include "ds/state_machine.h"
#include "node/node_types.h"

namespace ccf
{
  // Reads a serialised node_inbound message and dispatches it to the
  // appropriate handler, but only once the node is part of the network. This
  // includes forwarded commands, which must not be executed until the node is
  // part of the network, as some commands may otherwise exhibit undefined
  // behaviour.
  template <typename TForwarder, typename TChannels, typename TConsensus>
  void recv_node_inbound_message(
    const uint8_t* data,
    size_t size,
    ::ds::StateMachine<NodeStartupState>& sm,
    TForwarder* cmd_forwarder,
    TChannels* n2n_channels,
    TConsensus* consensus)
  {
    auto [msg_type, from, payload] =
      ringbuffer::read_message<node_inbound>(data, size);

    const auto* payload_data = payload.data;
    auto payload_size = payload.size;

    static const std::set<NodeStartupState> active_states{
      NodeStartupState::partOfNetwork,
      NodeStartupState::partOfPublicNetwork,
      NodeStartupState::readingPrivateLedger};

    if (!sm.check_one_of(active_states))
    {
      LOG_DEBUG_FMT(
        "Ignoring node msg received too early - current state is {}",
        sm.value());
      return;
    }

    switch (msg_type)
    {
      case forwarded_msg:
      {
        cmd_forwarder->recv_message(from, payload_data, payload_size);
        return;
      }
      case channel_msg:
      {
        n2n_channels->recv_channel_message(from, payload_data, payload_size);
        return;
      }
      case consensus_msg:
      {
        consensus->recv_message(from, payload_data, payload_size);
        return;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unknown node message type: {}", static_cast<uint32_t>(msg_type)));
      }
    }
  }
}
