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
    class NodeConnectionBehaviour : public TCPBehaviour
    {
    private:
    public:
      NodeConnections& parent;
      std::optional<ccf::NodeId> node;
      std::optional<size_t> msg_size = std::nullopt;
      std::vector<uint8_t> pending;

      NodeConnectionBehaviour(
        NodeConnections& parent,
        std::optional<ccf::NodeId> node = std::nullopt) :
        parent(parent),
        node(node)
      {}

      void on_read(size_t len, uint8_t*& incoming)
      {
        LOG_DEBUG_FMT(
          "from node {} received {} bytes",
          node.value_or(UnassociatedNode),
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
              node.value_or(UnassociatedNode),
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
            node.value(),
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

    class NodeIncomingBehaviour : public NodeConnectionBehaviour
    {
    public:
      size_t id;
      std::optional<ccf::NodeId> node_id;

      NodeIncomingBehaviour(NodeConnections& parent, size_t id_) :
        NodeConnectionBehaviour(parent),
        id(id_)
      {}

      void on_disconnect() override
      {
        LOG_DEBUG_FMT("Disconnecting incoming connection {}", id);
        parent.unassociated_incoming.erase(id);

        if (node_id.has_value())
        {
          parent.remove_connection(node_id.value());
        }
      }

      void associate_incoming(const ccf::NodeId& n) override
      {
        node_id = n;

        const auto unassociated = parent.unassociated_incoming.find(id);
        CCF_ASSERT_FMT(
          unassociated != parent.unassociated_incoming.end(),
          "Associating node {} with incoming ID {}, but have already forgotten "
          "the incoming connection",
          n,
          id);

        // Always prefer this (probably) newer connection. Pathological case is
        // where both nodes open outgoings to each other at the same time, both
        // see the corresponding incoming connections and _drop_ their outgoing
        // connections. Both have a useless incoming connection they think they
        // can use. Assumption is that they progress at different rates, and one
        // of them eventually spots the dead connection and opens a new one
        // which succeeds.
        parent.connections[n] = unassociated->second;
        parent.unassociated_incoming.erase(unassociated);

        LOG_DEBUG_FMT(
          "Node incoming connection ({}) associated with {}", id, n);
      }
    };

    class NodeOutgoingBehaviour : public NodeConnectionBehaviour
    {
    public:
      NodeOutgoingBehaviour(NodeConnections& parent, const ccf::NodeId& node) :
        NodeConnectionBehaviour(parent, node)
      {}

      void on_bind_failed() override
      {
        LOG_DEBUG_FMT(
          "Disconnecting outgoing connection with {}: bind failed",
          node.value());
        parent.remove_connection(node.value());
      }

      void on_resolve_failed() override
      {
        LOG_DEBUG_FMT(
          "Disconnecting outgoing connection with {}: resolve failed",
          node.value());
        parent.remove_connection(node.value());
      }

      void on_connect_failed() override
      {
        LOG_DEBUG_FMT(
          "Disconnecting outgoing connection with {}: connect failed",
          node.value());
        parent.remove_connection(node.value());
      }

      void on_disconnect() override
      {
        LOG_DEBUG_FMT(
          "Disconnecting outgoing connection with {}: disconnected",
          node.value());
        parent.remove_connection(node.value());
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
        peer->set_behaviour(
          std::make_unique<NodeIncomingBehaviour>(parent, id));
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

    std::optional<std::string> client_interface = std::nullopt;
    std::optional<std::chrono::milliseconds> client_connection_timeout =
      std::nullopt;

  public:
    NodeConnections(
      messaging::Dispatcher<ringbuffer::Message>& disp,
      Ledger& ledger,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::string& host,
      std::string& service,
      const std::optional<std::string>& client_interface = std::nullopt,
      std::optional<std::chrono::milliseconds> client_connection_timeout_ =
        std::nullopt) :
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
              if (outbound_connection.is_null())
              {
                LOG_FAIL_FMT(
                  "Unable to connect to {}, dropping outbound message message",
                  to);
                return;
              }
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

            if (ae.idx > ae.prev_idx)
            {
              std::optional<asynchost::LedgerReadResult> read_result =
                ledger.read_entries(ae.prev_idx + 1, ae.idx);

              if (!read_result.has_value())
              {
                LOG_FAIL_FMT(
                  "Unable to send AppendEntries ({}, {}]: Ledger read failed",
                  ae.prev_idx,
                  ae.idx);
                return;
              }
              else if (ae.idx != read_result->end_idx)
              {
                // NB: This should never happen since we do not pass a max_size
                // to read_entries
                LOG_FAIL_FMT(
                  "Unable to send AppendEntries ({}, {}]: Ledger read returned "
                  "entries to {}",
                  ae.prev_idx,
                  ae.idx,
                  read_result->end_idx);
                return;
              }
              else
              {
                const auto& framed_entries = read_result->data;
                frame += (uint32_t)framed_entries.size();
                outbound_connection->write(sizeof(uint32_t), (uint8_t*)&frame);
                outbound_connection->write(size_to_send, data_to_send);

                outbound_connection->write(
                  framed_entries.size(), framed_entries.data());
              }
            }
            else
            {
              // Header-only AE
              outbound_connection->write(sizeof(uint32_t), (uint8_t*)&frame);
              outbound_connection->write(size_to_send, data_to_send);
            }

            LOG_DEBUG_FMT(
              "send AE to node {} [{}]: {}, {}",
              to,
              frame,
              ae.idx,
              ae.prev_idx);
          }
          else
          {
            // Write as framed data to the recipient.
            uint32_t frame = (uint32_t)size_to_send;

            LOG_DEBUG_FMT("node send to {} [{}]", to, frame);

            outbound_connection->write(sizeof(uint32_t), (uint8_t*)&frame);
            outbound_connection->write(size_to_send, data_to_send);
          }
        });
    }

  private:
    TCP create_connection(
      const ccf::NodeId& node_id,
      const std::string& host,
      const std::string& service)
    {
      auto s = TCP(true, client_connection_timeout);
      s->set_behaviour(std::make_unique<NodeOutgoingBehaviour>(*this, node_id));

      if (!s->connect(host, service, client_interface))
      {
        LOG_FAIL_FMT(
          "Failed to connect to {} on {}:{}", node_id, host, service);
        return nullptr;
      }

      connections.emplace(node_id, s);
      LOG_DEBUG_FMT(
        "Added node connection with {} ({}:{})", node_id, host, service);

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
}
