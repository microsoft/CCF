// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"

#include <cstdint>
#include <string>

namespace aft
{
  // The authenticated node-to-node channels, as used by consensus. Implemented
  // by the node's channel manager (ccf::NodeToNode), which sends these as
  // consensus messages.
  class ConsensusChannels
  {
  public:
    virtual ~ConsensusChannels() = default;

    virtual void associate_node_address(
      const ccf::NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service) = 0;

    // Returns false if the message could not be sent
    virtual bool send_consensus_message(
      const ccf::NodeId& to, const uint8_t* data, size_t size) = 0;

    template <class T>
    bool send_consensus_message(const ccf::NodeId& to, const T& msg)
    {
      return send_consensus_message(
        to, reinterpret_cast<const uint8_t*>(&msg), sizeof(T));
    }
  };
}
