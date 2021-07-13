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

          if (!node.has_value())
          {
            associate_incoming(from);
            node = from;
          }

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

      virtual void associate_incoming(const ccf::NodeId&) {}
    };

    class IncomingBehaviour : public ConnectionBehaviour
    {
    public:
      size_t id;

      IncomingBehaviour(NodeConnections& parent, size_t id_) :
        ConnectionBehaviour(parent),
        id(id_)
      {}

      void on_disconnect() override
      {
        parent.unassociated_incoming.erase(id);
      }

      void associate_incoming(const ccf::NodeId& n) override
      {
        const auto unassociated = parent.unassociated_incoming.find(id);
        CCF_ASSERT_FMT(
          unassociated != parent.unassociated_incoming.end(),
          "Associating node {} with incoming ID {}, but have already forgotten "
          "the incoming connection",
          n,
          id);

        // If we already have an associated connection, prefer it
        const auto existing = parent.connections.find(n);
        if (existing == parent.connections.end())
        {
          parent.connections[n] = unassociated->second;
        }

        parent.unassociated_incoming.erase(unassociated);
        LOG_DEBUG_FMT(
          "Node incoming connection ({}) associated with {}", id, n);
      }
    };

    class OutgoingBehaviour : public ConnectionBehaviour
    {
    public:
      OutgoingBehaviour(NodeConnections& parent, const ccf::NodeId& node) :
        ConnectionBehaviour(parent, node)
      {}

      void on_bind_failed() override
      {
        LOG_DEBUG_FMT("node bind failed: {}", node.value());
        reconnect();
      }

      void on_resolve_failed() override
      {
        LOG_DEBUG_FMT("node resolve failed {}", node.value());
        reconnect();
      }

      void on_connect_failed() override
      {
        LOG_DEBUG_FMT("node connect failed {}", node.value());
        reconnect();
      }

      void on_disconnect() override
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
        parent.unassociated_incoming.emplace(id, peer);
        LOG_DEBUG_FMT("Accepted new incoming node connection ({})", id);
      }
    };

    Ledger& ledger;
    TCP listener;

    std::unordered_map<ccf::NodeId, std::pair<std::string, std::string>>
      node_addresses;

    std::unordered_map<ccf::NodeId, TCP> connections;

    std::unordered_map<size_t, TCP> unassociated_incoming;
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
        disp,
        ccf::associate_node_address,
        [this](const uint8_t* data, size_t size) {
          auto [node_id, hostname, service] =
            ringbuffer::read_message<ccf::associate_node_address>(data, size);

          node_addresses[node_id] = {hostname, service};
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        ccf::close_node_outbound,
        [this](const uint8_t* data, size_t size) {
          auto [node_id] =
            ringbuffer::read_message<ccf::close_node_outbound>(data, size);

          remove_connection(node_id);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ccf::node_outbound, [this](const uint8_t* data, size_t size) {
          // Read piece-by-piece rather than all at once
          ccf::NodeId to = serialized::read<ccf::NodeId::Value>(data, size);

          TCP outbound_connection = nullptr;
          {
            const auto connection_it = connections.find(to);
            if (connection_it == connections.end())
            {
              const auto address_it = node_addresses.find(to);
              if (address_it == node_addresses.end())
              {
                LOG_FAIL_FMT("Ignoring node_outbound to unknown node {}", to);
                return;
              }

              const auto& [host, service] = address_it->second;
              outbound_connection = create_connection(to, host, service);
            }
            else
            {
              outbound_connection = connection_it->second;
            }
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
              outbound_connection->write(sizeof(uint32_t), (uint8_t*)&frame);
              outbound_connection->write(size_to_send, data_to_send);

              frame = (uint32_t)framed_entries->size();
              outbound_connection->write(frame, framed_entries->data());
            }
            else
            {
              // Header-only AE
              outbound_connection->write(sizeof(uint32_t), (uint8_t*)&frame);
              outbound_connection->write(size_to_send, data_to_send);
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

            outbound_connection->write(sizeof(uint32_t), (uint8_t*)&frame);
            outbound_connection->write(size_to_send, data_to_send);
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
        auto s = connections.find(node);
        if (s != connections.end())
        {
          s->second->reconnect();
        }
      }
    }

  private:
    TCP create_connection(
      const ccf::NodeId& node_id,
      const std::string& host,
      const std::string& service)
    {
      auto s = TCP(true, client_connection_timeout);
      s->set_behaviour(std::make_unique<OutgoingBehaviour>(*this, node_id));

      connections.emplace(node_id, s);
      LOG_DEBUG_FMT(
        "Added node connection with {} ({}:{})", node_id, host, service);

      if (!s->connect(host, service, client_interface))
      {
        LOG_DEBUG_FMT(
          "Failed to connect to {} on {}:{}", node_id, host, service);
        // Stored and returned even if connect fails, to allow later reconnect
        // attempts
      }

      return s;
    }

    bool remove_connection(const ccf::NodeId& node)
    {
      if (connections.erase(node) < 1)
      {
        LOG_DEBUG_FMT("Cannot remove node connection {}: does not exist", node);
        return false;
      }

      LOG_DEBUG_FMT("Removed node connection with {}", node);
      return true;
    }

    size_t get_next_id()
    {
      auto id = next_id++;

      while (unassociated_incoming.find(id) != unassociated_incoming.end())
      {
        id = next_id++;
      }

      return id;
    }
  };

  using NodeConnectionsTickingReconnect = proxy_ptr<Timer<NodeConnections>>;
}
