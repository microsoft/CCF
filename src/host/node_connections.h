// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "ledger.h"
#include "node/node_types.h"
#include "tcp.h"
#include "timer.h"

#include <chrono>
#include <unordered_map>

namespace asynchost
{
  static const auto UnassociatedNode = ccf::NodeId("Unknown");

  // See NodeConnectionsImpl::simultaneous_connect_window.
  static constexpr auto default_simultaneous_connect_window =
    std::chrono::seconds(2);

  template <class ConnType>
  class NodeConnectionsImpl
  {
  private:
    // Identifies the current connection with a peer, whether we opened it, and
    // when it was created. Knowing this is what allows two nodes which dialled
    // each other at the same moment to agree on which connection to keep.
    struct ConnectionInfo
    {
      ConnType socket = nullptr;
      bool outgoing = false;
      std::chrono::steady_clock::time_point created =
        std::chrono::steady_clock::now();
    };

    class NodeConnectionBehaviour : public SocketBehaviour<ConnType>
    {
    private:
    public:
      NodeConnectionsImpl& parent;
      std::optional<ccf::NodeId> node;
      std::optional<size_t> msg_size = std::nullopt;
      std::vector<uint8_t> pending;

      NodeConnectionBehaviour(
        const char* name,
        NodeConnectionsImpl& parent,
        std::optional<ccf::NodeId> node = std::nullopt) :
        SocketBehaviour<ConnType>(name, "TCP"),
        parent(parent),
        node(std::move(node))
      {}

      bool on_read(size_t len, uint8_t*& incoming, sockaddr /*unused*/) override
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

          ccf::NodeMsgType msg_type{};
          try
          {
            msg_type = serialized::read<ccf::NodeMsgType>(data, size);
          }
          catch (const std::exception& e)
          {
            LOG_DEBUG_FMT(
              "Received invalid node-to-node traffic. Unable to read message "
              "type ({}). Closing connection.",
              e.what());
            return false;
          }

          ccf::NodeId from;
          try
          {
            from = serialized::read<ccf::NodeId::Value>(data, size);
          }
          catch (const std::exception& e)
          {
            LOG_DEBUG_FMT(
              "Received invalid node-to-node traffic. Unable to read sender "
              "node ID ({}). Closing connection.",
              e.what());
            return false;
          }

          const auto size_post_headers = size;
          const auto header_size = size_pre_headers - size_post_headers;
          if (header_size > msg_size.value())
          {
            LOG_DEBUG_FMT(
              "Received invalid node-to-node traffic. Total msg size {} "
              "doesn't even contain headers (of size {})",
              msg_size.value(),
              header_size);
            return false;
          }
          const size_t payload_size = msg_size.value() - header_size;

          if (!node.has_value())
          {
            if (!associate_incoming(from))
            {
              // We are keeping an existing connection with this peer in
              // preference to this one. Close it, rather than leaving two
              // connections up and having to guess which one to write to.
              return false;
            }
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

        return true;
      }

      /// Returns false if this connection should be dropped rather than used.
      virtual bool associate_incoming(const ccf::NodeId& /*unused*/)
      {
        return true;
      }
    };

    class NodeIncomingBehaviour : public NodeConnectionBehaviour
    {
    public:
      using NodeConnectionBehaviour::parent;

      size_t id;
      std::optional<ccf::NodeId> node_id;

      NodeIncomingBehaviour(NodeConnectionsImpl& parent, size_t id_) :
        NodeConnectionBehaviour("Node Incoming", parent),
        id(id_)
      {}

      void on_disconnect() override
      {
        LOG_INFO_FMT("Disconnecting incoming connection {}", id);
        parent.unassociated_incoming.erase(id);

        if (node_id.has_value())
        {
          parent.remove_connection(node_id.value());
        }
      }

      bool associate_incoming(const ccf::NodeId& n) override
      {
        const auto unassociated = parent.unassociated_incoming.find(id);
        CCF_ASSERT_FMT(
          unassociated != parent.unassociated_incoming.end(),
          "Associating node {} with incoming ID {}, but have already forgotten "
          "the incoming connection",
          n,
          id);

        // If we already have a *recently created* outgoing connection to this
        // peer, then the two of us dialled each other at the same time and
        // there are now two connections where one is needed. Both nodes must
        // independently pick the same one to keep. If they do not, each
        // destroys the connection the other is relying on, and both are left
        // holding a socket whose far end is gone. Ordering by node ID gives
        // both sides the same answer using only information they already have.
        //
        // The age check matters. An incoming connection from a peer we already
        // have a settled connection to means that peer believes the link is
        // broken, and it is in a better position to know - it may have seen an
        // error we did not. Defending our own connection indefinitely would
        // deny the peer the only means it has of repairing a link that is dead
        // in a way we cannot detect, which is precisely the failure this change
        // exists to prevent. So we only defend a connection young enough to
        // still be part of a genuine race; anything older yields, as before.
        const auto existing = parent.connections.find(n);
        if (
          existing != parent.connections.end() && existing->second.outgoing &&
          (std::chrono::steady_clock::now() - existing->second.created) <
            parent.simultaneous_connect_window &&
          !parent.prefer_incoming_from(n))
        {
          LOG_INFO_FMT(
            "Refusing incoming node connection ({}) from {}: keeping our "
            "existing outgoing connection to resolve a simultaneous connect",
            id,
            n);
          return false;
        }

        node_id = n;
        parent.connections[n] = {unassociated->second, false};
        parent.unassociated_incoming.erase(unassociated);

        LOG_INFO_FMT("Node incoming connection ({}) associated with {}", id, n);
        return true;
      }
    };

    class NodeOutgoingBehaviour : public NodeConnectionBehaviour
    {
    public:
      using NodeConnectionBehaviour::node;
      using NodeConnectionBehaviour::parent;

      NodeOutgoingBehaviour(
        NodeConnectionsImpl& parent, const ccf::NodeId& node) :
        NodeConnectionBehaviour("Node Outgoing", parent, node)
      {}

      void on_bind_failed() override
      {
        LOG_INFO_FMT(
          "Disconnecting outgoing connection with {}: bind failed",
          *node); // NOLINT(bugprone-unchecked-optional-access)
        parent.remove_connection(
          *node); // NOLINT(bugprone-unchecked-optional-access)
      }

      void on_resolve_failed() override
      {
        LOG_INFO_FMT(
          "Disconnecting outgoing connection with {}: resolve failed",
          *node); // NOLINT(bugprone-unchecked-optional-access)
        parent.remove_connection(
          *node); // NOLINT(bugprone-unchecked-optional-access)
      }

      void on_connect_failed() override
      {
        LOG_INFO_FMT(
          "Disconnecting outgoing connection with {}: connect failed",
          *node); // NOLINT(bugprone-unchecked-optional-access)
        parent.remove_connection(
          *node); // NOLINT(bugprone-unchecked-optional-access)
      }

      void on_disconnect() override
      {
        LOG_INFO_FMT(
          "Disconnecting outgoing connection with {}: disconnected",
          *node); // NOLINT(bugprone-unchecked-optional-access)
        parent.remove_connection(
          *node); // NOLINT(bugprone-unchecked-optional-access)
      }
    };

    class NodeServerBehaviour : public SocketBehaviour<ConnType>
    {
    public:
      NodeConnectionsImpl& parent;

      NodeServerBehaviour(NodeConnectionsImpl& parent) :
        SocketBehaviour<ConnType>("Node Server", "TCP"),
        parent(parent)
      {}

      void on_accept(ConnType& peer) override
      {
        auto id = parent.get_next_id();
        peer->set_behaviour(
          std::make_unique<NodeIncomingBehaviour>(parent, id));
        parent.unassociated_incoming.emplace(id, peer);
        LOG_INFO_FMT("Accepted new incoming node connection ({})", id);
      }
    };

    Ledger& ledger;
    ConnType listener;

    std::unordered_map<ccf::NodeId, std::pair<std::string, std::string>>
      node_addresses;

    std::unordered_map<ccf::NodeId, ConnectionInfo> connections;

    // How recently we must have opened an outgoing connection to treat an
    // incoming connection from the same peer as a simultaneous connect rather
    // than as that peer trying to repair a link it believes is broken. A real
    // race is resolved within a round trip; this only needs to be long enough
    // to cover one, and short enough that a peer's repair is not denied for
    // any meaningful time.
    std::chrono::milliseconds simultaneous_connect_window{
      default_simultaneous_connect_window};

    // This node's own ID, which the host is never told directly. It is carried
    // in the sender field of every outbound message, and is only needed once
    // an outgoing connection exists - which implies we have already sent.
    std::optional<ccf::NodeId> self_node_id = std::nullopt;

    std::unordered_map<size_t, ConnType> unassociated_incoming;
    size_t next_id = 1;

    ringbuffer::WriterPtr to_enclave;

    std::optional<std::string> client_interface = std::nullopt;
    std::optional<std::chrono::milliseconds> client_connection_timeout =
      std::nullopt;

  public:
    NodeConnectionsImpl(
      messaging::Dispatcher<ringbuffer::Message>& disp,
      Ledger& ledger,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::string& host,
      std::string& port,
      const std::optional<std::string>& client_interface = std::nullopt,
      std::optional<std::chrono::milliseconds> client_connection_timeout_ =
        std::nullopt) :
      ledger(ledger),
      to_enclave(writer_factory.create_writer_to_inside()),
      client_interface(client_interface),
      client_connection_timeout(client_connection_timeout_)
    {
      listener->set_behaviour(std::make_unique<NodeServerBehaviour>(*this));
      listener->listen(host, port);
      host = listener->get_host();
      port = listener->get_port();

      register_message_handlers(disp);
    }

    // Only used by tests, to exercise the behaviour either side of the window
    // without having to wait for real time to pass.
    void set_simultaneous_connect_window(std::chrono::milliseconds window)
    {
      simultaneous_connect_window = window;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        ccf::associate_node_address,
        [this](const uint8_t* data, size_t size) {
          auto [node_id, hostname, port] =
            ringbuffer::read_message<ccf::associate_node_address>(data, size);

          node_addresses[node_id] = {hostname, port};
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

          // Peek at the sender ID without consuming it. This is the only place
          // the host learns its own node ID, which is needed to resolve
          // simultaneous connects consistently on both sides.
          if (!self_node_id.has_value())
          {
            const uint8_t* peek = data;
            size_t peek_size = size;
            try
            {
              serialized::read<ccf::NodeMsgType>(peek, peek_size);
              self_node_id = ccf::NodeId(
                serialized::read<ccf::NodeId::Value>(peek, peek_size));
            }
            catch (const std::exception& e)
            {
              LOG_DEBUG_FMT(
                "Unable to read own node ID from outbound: {}", e.what());
            }
          }

          ConnType outbound_connection = nullptr;
          {
            const auto connection_it = connections.find(to);
            if (connection_it == connections.end())
            {
              const auto address_it = node_addresses.find(to);
              if (address_it == node_addresses.end())
              {
                LOG_TRACE_FMT("Ignoring node_outbound to unknown node {}", to);
                return;
              }

              const auto& [host, port] = address_it->second;
              outbound_connection = create_connection(to, host, port);
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
              outbound_connection = connection_it->second.socket;
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
              serialized::overlay<::consensus::AppendEntriesIndex>(data, size);

            // Find the total frame size, and write it along with the header.
            auto frame = static_cast<uint32_t>(size_to_send);

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

              if (ae.idx != read_result->end_idx)
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

              const auto& framed_entries = read_result->data;
              frame += static_cast<uint32_t>(framed_entries.size());
              outbound_connection->write(
                sizeof(uint32_t), reinterpret_cast<uint8_t*>(&frame));
              outbound_connection->write(size_to_send, data_to_send);

              outbound_connection->write(
                framed_entries.size(), framed_entries.data());
            }
            else
            {
              // Header-only AE
              outbound_connection->write(
                sizeof(uint32_t), reinterpret_cast<uint8_t*>(&frame));
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
            auto frame = static_cast<uint32_t>(size_to_send);

            LOG_DEBUG_FMT("node send to {} [{}]", to, frame);

            outbound_connection->write(
              sizeof(uint32_t), reinterpret_cast<uint8_t*>(&frame));
            outbound_connection->write(size_to_send, data_to_send);
          }
        });
    }

  private:
    // Decide which of two simultaneously-created connections with a peer to
    // keep. Both nodes evaluate this for the same pair and must agree: the node
    // with the lower ID keeps the connection it opened, and the node with the
    // higher ID prefers the one its peer opened. Exactly one of the two
    // connections therefore survives, and both ends of it agree.
    bool prefer_incoming_from(const ccf::NodeId& peer) const
    {
      if (!self_node_id.has_value())
      {
        // We cannot have an outgoing connection without having sent a message,
        // so this should be unreachable. Fall back to the previous behaviour of
        // always preferring the newer connection.
        LOG_FAIL_FMT(
          "Resolving simultaneous connect with {} without knowing own node ID",
          peer);
        return true;
      }

      return self_node_id.value().value() > peer.value();
    }

    ConnType create_connection(
      const ccf::NodeId& node_id,
      const std::string& host,
      const std::string& port)
    {
      auto s = ConnType(true, client_connection_timeout);
      s->set_behaviour(std::make_unique<NodeOutgoingBehaviour>(*this, node_id));

      if (!s->connect(host, port, client_interface))
      {
        LOG_FAIL_FMT("Failed to connect to {} on {}:{}", node_id, host, port);
        return nullptr;
      }

      connections[node_id] = {s, true};
      LOG_INFO_FMT(
        "Added node connection with {} ({}:{})", node_id, host, port);

      return s;
    }

    // Remove the connection with this peer, if any.
    bool remove_connection(const ccf::NodeId& node)
    {
      if (connections.erase(node) < 1)
      {
        LOG_DEBUG_FMT("Cannot remove node connection {}: does not exist", node);
        return false;
      }

      LOG_INFO_FMT("Removed node connection with {}", node);
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

  using NodeConnections = NodeConnectionsImpl<TCP>;
}
