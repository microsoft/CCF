// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "ledger.h"
#include "node/node_types.h"
#include "tcp.h"
#include "timer.h"

#include <unordered_map>

namespace asynchost
{
  static const auto UnassociatedNode = ccf::NodeId("Unknown");

  class NodeConnections
  {
  private:
    class ConnectionBehaviour : public TCPBehaviour
    {
    private:
    public:
      NodeConnections& parent;
      std::optional<ccf::NodeId> node;
      std::optional<size_t> msg_size = std::nullopt;
      std::vector<uint8_t> pending;

      ConnectionBehaviour(
        NodeConnections& parent,
        std::optional<ccf::NodeId> node = std::nullopt) :
        parent(parent),
        node(node)
      {}

      void on_read(size_t len, uint8_t*& incoming)
      {
        LOG_DEBUG_FMT(
          "from node {} received {} bytes",
          node.value_or(UnassociatedNode).trim(),
          len);

        pending.insert(pending.end(), incoming, incoming + len);

        const uint8_t* data = pending.data();
        size_t size = pending.size();
        const auto size_before = size;

        while (true)
        {
          if (!msg_size.has_value())
          {
            if (size < sizeof(uint32_t))
            {
              break;
            }

            msg_size = serialized::read<uint32_t>(data, size);
          }

          if (size < msg_size.value())
          {
            LOG_DEBUG_FMT(
              "from node {} have {}/{} bytes",
              node.value_or(UnassociatedNode).trim(),
              size,
              msg_size.value());
            break;
          }

          const auto size_pre_headers = size;
          auto msg_type = serialized::read<ccf::NodeMsgType>(data, size);
          ccf::NodeId from = serialized::read<ccf::NodeId::Value>(data, size);
          const auto size_post_headers = size;
          const size_t payload_size =
            msg_size.value() - (size_pre_headers - size_post_headers);

          associate(from);

          LOG_DEBUG_FMT(
            "node in: from node {}, size {}, type {}",
            node->trim(),
            msg_size.value(),
            msg_type);

          RINGBUFFER_WRITE_MESSAGE(
            ccf::node_inbound,
            parent.to_enclave,
            msg_type,
            from.value(),
            serializer::ByteRange{data, payload_size});

          data += payload_size;
          size -= payload_size;
          msg_size.reset();
        }

        const auto size_after = size;
        const auto used = size_before - size_after;
        if (used > 0)
        {
          pending.erase(pending.begin(), pending.begin() + used);
        }
      }

      virtual void associate(const ccf::NodeId&) {}
    };

    class IncomingBehaviour : public ConnectionBehaviour
    {
    public:
      size_t id;

      IncomingBehaviour(NodeConnections& parent, size_t id) :
        ConnectionBehaviour(parent),
        id(id)
      {}

      void on_disconnect()
      {
        parent.incoming.erase(id);

        if (node.has_value())
        {
          LOG_DEBUG_FMT(
            "node incoming disconnect {} with node {}", id, node.value());
          parent.associated.erase(node.value());
        }
      }

      virtual void associate(const ccf::NodeId& n)
      {
        // It is possible that a peer terminates a connection and opens a new
        // one but the termination is seen by us _after_ messages on the new
        // connection are received. We re-associate the connection on the latest
        // received message, so that oubound messages are routed to the correct,
        // most up-to-date, incoming connection.
        auto search = parent.associated.find(n);
        if (search != parent.associated.end() && search->second.first == id)
        {
          // Incoming connection is already associated with n
          return;
        }

        parent.associated[n] = std::make_pair(id, parent.incoming.at(id));
        LOG_DEBUG_FMT("node incoming {} associated with {}", id, n);
        node = n;
      }
    };

    class OutgoingBehaviour : public ConnectionBehaviour
    {
    public:
      OutgoingBehaviour(NodeConnections& parent, const ccf::NodeId& node) :
        ConnectionBehaviour(parent, node)
      {}

      void on_bind_failed()
      {
        LOG_DEBUG_FMT("node bind failed: {}", node.value());
        reconnect();
      }

      void on_resolve_failed()
      {
        LOG_DEBUG_FMT("node resolve failed {}", node.value());
        reconnect();
      }

      void on_connect_failed()
      {
        LOG_DEBUG_FMT("node connect failed {}", node.value());
        reconnect();
      }

      void on_disconnect()
      {
        LOG_DEBUG_FMT("node disconnect failed {}", node.value());
        reconnect();
      }

      void reconnect()
      {
        parent.request_reconnect(node.value());
      }
    };

    class NodeServerBehaviour : public TCPServerBehaviour
    {
    public:
      NodeConnections& parent;

      NodeServerBehaviour(NodeConnections& parent) : parent(parent) {}

      void on_listening(
        const std::string& host, const std::string& service) override
      {
        LOG_INFO_FMT("Listening for node-to-node on {}:{}", host, service);
      }

      void on_accept(TCP& peer) override
      {
        auto id = parent.get_next_id();
        peer->set_behaviour(std::make_unique<IncomingBehaviour>(parent, id));
        parent.incoming.emplace(id, peer);

        LOG_DEBUG_FMT("node accept {}", id);
      }
    };

    Ledger& ledger;
    TCP listener;

    // The lifetime of outgoing connections is handled by node channels in the
    // enclave
    std::unordered_map<ccf::NodeId, TCP> outgoing;

    std::unordered_map<size_t, TCP> incoming;
    std::unordered_map<ccf::NodeId, std::pair<size_t, TCP>> associated;
    size_t next_id = 1;
    ringbuffer::WriterPtr to_enclave;
    std::set<ccf::NodeId> reconnect_queue;

    std::optional<std::string> client_interface = std::nullopt;
    size_t client_connection_timeout;

  public:
    NodeConnections(
      messaging::Dispatcher<ringbuffer::Message>& disp,
      Ledger& ledger,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::string& host,
      std::string& service,
      const std::optional<std::string>& client_interface,
      size_t client_connection_timeout_) :
      ledger(ledger),
      to_enclave(writer_factory.create_writer_to_inside()),
      client_interface(client_interface),
      client_connection_timeout(client_connection_timeout_)
    {
      listener->set_behaviour(std::make_unique<NodeServerBehaviour>(*this));
      listener->listen(host, service);
      host = listener->get_host();
      service = listener->get_service();

      register_message_handlers(disp);
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ccf::add_node, [this](const uint8_t* data, size_t size) {
          auto [id, hostname, service] =
            ringbuffer::read_message<ccf::add_node>(data, size);
          add_node(id, hostname, service);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ccf::remove_node, [this](const uint8_t* data, size_t size) {
          auto [id] = ringbuffer::read_message<ccf::remove_node>(data, size);
          remove_node(id);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ccf::node_outbound, [this](const uint8_t* data, size_t size) {
          // Read piece-by-piece rather than all at once
          ccf::NodeId to = serialized::read<ccf::NodeId::Value>(data, size);
          auto node = find(to, true);

          if (!node)
          {
            return;
          }

          // Rather than reading and reserialising, use the msg_type and from_id
          // that are already serialised on the ringbuffer
          auto data_to_send = data;
          auto size_to_send = size;

          // If the message is a consensus append entries message, affix the
          // corresponding ledger entries
          auto msg_type = serialized::read<ccf::NodeMsgType>(data, size);
          serialized::read<ccf::NodeId::Value>(data, size); // Ignore from_id
          if (
            msg_type == ccf::NodeMsgType::consensus_msg &&
            (serialized::read<aft::RaftMsgType>(data, size) ==
             aft::raft_append_entries))
          {
            // Parse the indices to be sent to the recipient.
            const auto& ae =
              serialized::overlay<consensus::AppendEntriesIndex>(data, size);

            // Find the total frame size, and write it along with the header.
            uint32_t frame = (uint32_t)size_to_send;
            std::optional<std::vector<uint8_t>> framed_entries = std::nullopt;

            framed_entries =
              ledger.read_framed_entries(ae.prev_idx + 1, ae.idx);
            if (framed_entries.has_value())
            {
              frame += (uint32_t)framed_entries->size();
              node.value()->write(sizeof(uint32_t), (uint8_t*)&frame);
              node.value()->write(size_to_send, data_to_send);

              frame = (uint32_t)framed_entries->size();
              node.value()->write(frame, framed_entries->data());
            }
            else
            {
              // Header-only AE
              node.value()->write(sizeof(uint32_t), (uint8_t*)&frame);
              node.value()->write(size_to_send, data_to_send);
            }

            LOG_DEBUG_FMT(
              "send AE to node {} [{}]: {}, {}",
              to.trim(),
              frame,
              ae.idx,
              ae.prev_idx);
          }
          else
          {
            // Write as framed data to the recipient.
            uint32_t frame = (uint32_t)size_to_send;

            LOG_DEBUG_FMT("node send to {} [{}]", to.trim(), frame);

            node.value()->write(sizeof(uint32_t), (uint8_t*)&frame);
            node.value()->write(size_to_send, data_to_send);
          }
        });
    }

    void request_reconnect(const ccf::NodeId& node)
    {
      reconnect_queue.insert(node);
    }

    void on_timer()
    {
      // Swap to local copy of queue. Although this should only be modified by
      // this thread, it may be modified recursively (ie - executing this
      // function may result in calls to request_reconnect). These recursive
      // calls are queued until the next iteration
      decltype(reconnect_queue) local_queue;
      std::swap(reconnect_queue, local_queue);

      for (const auto& node : local_queue)
      {
        LOG_DEBUG_FMT("reconnecting node {}", node);
        auto s = outgoing.find(node);
        if (s != outgoing.end())
        {
          s->second->reconnect();
        }
      }
    }

  private:
    bool add_node(
      const ccf::NodeId& node,
      const std::string& host,
      const std::string& service)
    {
      if (outgoing.find(node) != outgoing.end())
      {
        LOG_FAIL_FMT("Cannot add node connection {}: already in use", node);
        return false;
      }

      auto s = TCP(true, client_connection_timeout);
      s->set_behaviour(std::make_unique<OutgoingBehaviour>(*this, node));

      if (!s->connect(host, service, client_interface))
      {
        LOG_DEBUG_FMT("Node failed initial connect {}", node);
        return false;
      }

      outgoing.emplace(node, s);

      LOG_DEBUG_FMT(
        "Added node connection with {} ({}:{})", node, host, service);
      return true;
    }

    std::optional<TCP> find(const ccf::NodeId& node, bool use_incoming = false)
    {
      auto s = outgoing.find(node);

      if (s != outgoing.end())
      {
        return s->second;
      }

      if (use_incoming)
      {
        auto s = associated.find(node);

        if (s != associated.end())
        {
          return s->second.second;
        }
      }

      LOG_FAIL_FMT("Unknown node connection {}", node);
      return std::nullopt;
    }

    bool remove_node(const ccf::NodeId& node)
    {
      if (outgoing.erase(node) < 1)
      {
        LOG_FAIL_FMT("Cannot remove node connection {}: does not exist", node);
        return false;
      }

      LOG_DEBUG_FMT("Removed outgoing node connection with {}", node);

      return true;
    }

    size_t get_next_id()
    {
      auto id = next_id++;

      while (incoming.find(id) != incoming.end())
      {
        id = next_id++;
      }

      return id;
    }
  };

  using NodeConnectionsTickingReconnect = proxy_ptr<Timer<NodeConnections>>;
}
