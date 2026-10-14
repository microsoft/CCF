// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "node/node_types.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ccf
{
  // Receives frames from peers. Peer-controlled input: implementations must
  // tolerate malformed payloads. Called by the transport on its own thread, so
  // implementations must be thread-safe and must not block.
  class NodeInboundHandler
  {
  public:
    virtual ~NodeInboundHandler() = default;

    virtual void recv_node_inbound(
      NodeMsgType type, const NodeId& from, std::vector<uint8_t>&& payload) = 0;
  };

  // Node-to-node transport, implemented by the host. All methods are
  // thread-safe and never block on the network. Operations are applied in a
  // single total order consistent with each caller's call order, so a caller
  // holding a lock across its calls gets FIFO delivery per peer.
  //
  // An AppendEntries sent after the corresponding ledger entries were passed
  // to the ledger subsystem is framed with those entries: the host reads
  // (prev_idx, idx] from the ledger after all earlier ledger mutations.
  class AbstractNodeTransport
  {
  public:
    virtual ~AbstractNodeTransport() = default;

    virtual void associate_node_address(
      const NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service) = 0;

    // payload is everything after the message type and sender ID on the wire.
    virtual void send(
      const NodeId& to,
      NodeMsgType type,
      const NodeId& from,
      std::vector<uint8_t>&& payload) = 0;

    virtual void close(const NodeId& peer_id) = 0;

    // Frames received before a handler is set are dropped.
    virtual void set_inbound_handler(
      std::shared_ptr<NodeInboundHandler> handler) = 0;
  };
}
