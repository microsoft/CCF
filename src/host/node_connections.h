// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/node_info_network.h"
#include "consensus/aft/raft_types.h"
#include "ds/serialized.h"
#include "ledger.h"
#include "ledger_subsystem.h"
#include "node/node_transport.h"
#include "node/node_types.h"
#include "node_tls.h"
#include "tcp.h"
#include "timer.h"

#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <variant>

namespace asynchost
{
  static const auto UnassociatedNode = ccf::NodeId("Unknown");

  // See NodeConnectionsImpl::simultaneous_connect_window.
  static constexpr auto default_simultaneous_connect_window =
    std::chrono::seconds(2);

  // Host implementation of the node-to-node transport.
  //
  // Outbound operations may be called from any thread and are handled in two
  // steps. An AppendEntries message must not read the ledger until the appends
  // the node submitted before it have been applied, so each operation is first
  // submitted to the same lane as ledger mutations, where any ledger entries
  // are read and the frame is assembled. The result is queued for the libuv
  // thread, which owns the sockets and drains the queue from flush_outbound().
  // Address and close updates take the same path so that their order relative
  // to sends is preserved. All other state is confined to the libuv thread.
  //
  // Inbound frames are copied into owned storage and passed to the inbound
  // handler on the libuv thread.
  template <class ConnType>
  class NodeConnectionsImpl : public ccf::AbstractNodeTransport
  {
  private:
    class NodeConnectionBehaviour;
    // Identifies the current connection with a peer, whether we opened it, and
    // when it was created. Knowing this is what allows two nodes which dialled
    // each other at the same moment to agree on which connection to keep.
    struct ConnectionInfo
    {
      ConnType socket = nullptr;
      bool outgoing = false;
      std::chrono::steady_clock::time_point created =
        std::chrono::steady_clock::now();
      NodeConnectionBehaviour* behaviour = nullptr;
    };

    class NodeConnectionBehaviour : public SocketBehaviour<ConnType>
    {
    private:
    public:
      NodeConnectionsImpl& parent;
      std::optional<ccf::NodeId> node;
      std::optional<size_t> msg_size = std::nullopt;
      std::vector<uint8_t> pending;
      std::unique_ptr<NodeTLSSession> tls;
      NodeTLSSession::Write write;
      bool announced_tls = false;

      NodeConnectionBehaviour(
        const char* name,
        NodeConnectionsImpl& parent,
        std::optional<ccf::NodeId> node = std::nullopt) :
        SocketBehaviour<ConnType>(name, "TCP"),
        parent(parent),
        node(std::move(node))
      {
        if (parent.tls_enabled && parent.tls_context != nullptr)
        {
          tls = std::make_unique<NodeTLSSession>(
            parent.tls_context,
            this->node,
            parent.max_inbound_frame_size + 4,
            parent.tls_record_limit);
        }
      }

      bool send(const std::vector<uint8_t>& frame)
      {
        if (!parent.tls_enabled)
        {
          return write(frame.size(), frame.data());
        }
        if (tls == nullptr)
        {
          return false;
        }
        try
        {
          tls->enqueue(frame);
          return receive_tls({});
        }
        catch (const std::exception& e)
        {
          LOG_DEBUG_FMT("Dropping node TLS send: {}", e.what());
          return false;
        }
      }

      bool receive_tls(std::span<const uint8_t> input)
      {
        if (tls == nullptr)
        {
          return false;
        }
        const auto result =
          tls->pump(input, write, [this](size_t len, const uint8_t* data) {
            return read_frames(len, data);
          });
        if (result && tls->peer().has_value() && !announced_tls)
        {
          LOG_INFO_FMT(
            "Node TLS 1.3 mutually authenticated with {}", tls->peer().value());
          announced_tls = true;
        }
        return result;
      }

      bool on_read(size_t len, uint8_t*& incoming, sockaddr /*unused*/) override
      {
        if (parent.tls_enabled)
        {
          return receive_tls({incoming, len});
        }
        return read_frames(len, incoming);
      }

      bool read_frames(size_t len, const uint8_t* incoming)
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

            // Reject before buffering the body, since the size is
            // peer-controlled
            if (msg_size.value() > parent.max_inbound_frame_size)
            {
              LOG_FAIL_FMT(
                "Received node-to-node frame of {} bytes from {}, exceeding "
                "the maximum of {}. Closing connection.",
                msg_size.value(),
                node.value_or(UnassociatedNode),
                parent.max_inbound_frame_size);
              return false;
            }
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

          if (
            parent.tls_enabled &&
            (msg_type != ccf::NodeMsgType::consensus_msg ||
             !tls->peer().has_value() || tls->peer().value() != from))
          {
            LOG_FAIL_FMT(
              "Rejecting node TLS frame: non-consensus type or sender "
              "different from authenticated peer");
            return false;
          }

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

          parent.deliver_inbound(
            msg_type, from, std::vector<uint8_t>(data, data + payload_size));

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
        parent.incoming_created.erase(id);
        if (node_id.has_value())
        {
          const auto current = parent.connections.find(node_id.value());
          if (
            current != parent.connections.end() &&
            current->second.behaviour == this)
          {
            parent.remove_connection(node_id.value());
          }
        }
        else
        {
          // Erasing the last socket owner can destroy this behaviour. Do not
          // access any members after removing the unassociated connection.
          parent.unassociated_incoming.erase(id);
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
        parent.connections[n] = {
          unassociated->second, false, std::chrono::steady_clock::now(), this};
        parent.unassociated_incoming.erase(unassociated);
        parent.incoming_created.erase(id);

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
        if (parent.tls_enabled && parent.unassociated_incoming.size() >= 128)
        {
          LOG_DEBUG_FMT("Rejecting node TLS connection: pending accept limit");
          return;
        }
        auto id = parent.get_next_id();
        auto behaviour = std::make_unique<NodeIncomingBehaviour>(parent, id);
        behaviour->write =
          [this, socket = peer.operator->()](size_t n, const uint8_t* p) {
            return parent.tls_enabled ?
              socket->write_bounded(n, p, 2 * parent.max_inbound_frame_size) :
              socket->write(n, p);
          };
        peer->set_behaviour(std::move(behaviour));
        parent.unassociated_incoming.emplace(id, peer);
        if (parent.tls_enabled)
        {
          parent.incoming_created.emplace(id, std::chrono::steady_clock::now());
        }
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
    std::unordered_map<size_t, std::chrono::steady_clock::time_point>
      incoming_created;
    size_t next_id = 1;

    // Declared frame sizes above this are rejected and the connection closed.
    size_t max_inbound_frame_size;

    std::mutex inbound_handler_mutex;
    std::shared_ptr<ccf::NodeInboundHandler> inbound_handler;

    std::optional<std::string> client_interface = std::nullopt;
    std::optional<std::chrono::milliseconds> client_connection_timeout =
      std::nullopt;

    LedgerSubsystem& ledger_subsystem;
    const bool tls_enabled = false;
    const size_t tls_record_limit;
    std::shared_ptr<NodeTLSContext> tls_context;

    // Work handed from the ledger lane back to the loop thread, in order.
    struct AssociateAddress
    {
      ccf::NodeId node_id;
      std::string host;
      std::string port;
    };
    struct CloseOutbound
    {
      ccf::NodeId node_id;
    };
    struct SendFrame
    {
      ccf::NodeId to;
      ccf::NodeId from;
      std::vector<uint8_t> frame;
    };
    using OutboundItem = std::
      variant<AssociateAddress, CloseOutbound, SendFrame, NodeTLSCredentials>;

    std::mutex outbound_mutex;
    std::deque<OutboundItem> outbound_ready;

    // Runs fn after every ledger mutation submitted before it. fn must only
    // enqueue to outbound_ready; the loop thread applies the result.
    template <typename F>
    void ordered(const char* what, F&& fn)
    {
      if (!ledger_subsystem.run_in_mutation_order(what, std::forward<F>(fn)))
      {
        LOG_DEBUG_FMT("Dropping {} because the host is shutting down", what);
      }
    }

    void enqueue_ready(OutboundItem&& item)
    {
      std::lock_guard guard(outbound_mutex);
      outbound_ready.push_back(std::move(item));
    }

    void deliver_inbound(
      ccf::NodeMsgType msg_type,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload)
    {
      std::shared_ptr<ccf::NodeInboundHandler> handler;
      {
        std::lock_guard guard(inbound_handler_mutex);
        handler = inbound_handler;
      }

      if (handler == nullptr)
      {
        LOG_DEBUG_FMT(
          "Ignoring node message from {}: no inbound handler", from);
        return;
      }

      handler->recv_node_inbound(
        msg_type, from, std::move(payload), tls_enabled);
    }

  public:
    bool supports_tls() const override
    {
      return tls_enabled;
    }

    ccf::NodeTransportKind select_transport(const ccf::NodeId&) const override
    {
      return tls_enabled ? ccf::NodeTransportKind::TLS :
                           ccf::NodeTransportKind::Legacy;
    }

    void set_tls_credentials(
      const ccf::crypto::Pem& service,
      const ccf::crypto::Pem& certificate,
      const ccf::crypto::Pem& private_key) override
    {
      if (tls_enabled)
      {
        ordered(
          "Node TLS credentials",
          [this,
           credentials =
             NodeTLSCredentials{service, certificate, private_key}]() mutable {
            enqueue_ready(std::move(credentials));
          });
      }
    }

    NodeConnectionsImpl(
      Ledger& ledger,
      LedgerSubsystem& ledger_subsystem_,
      std::string& host,
      std::string& port,
      size_t max_inbound_frame_size_,
      const std::optional<std::string>& client_interface = std::nullopt,
      std::optional<std::chrono::milliseconds> client_connection_timeout_ =
        std::nullopt,
      bool tls_enabled_ = false,
      size_t tls_record_limit_ = max_node_tls_records_per_key) :
      ledger(ledger),
      max_inbound_frame_size(max_inbound_frame_size_),
      client_interface(client_interface),
      client_connection_timeout(client_connection_timeout_),
      ledger_subsystem(ledger_subsystem_),
      tls_enabled(tls_enabled_),
      tls_record_limit(tls_record_limit_)
    {
      if (
        tls_enabled &&
        (tls_record_limit < 4 ||
         tls_record_limit > max_node_tls_records_per_key))
      {
        throw std::logic_error("Node TLS record limit must be in [4, 2^24]");
      }
      listener->set_behaviour(std::make_unique<NodeServerBehaviour>(*this));
      listener->listen(host, port);
      host = listener->get_host();
      port = listener->get_port();
    }

    // Only used by tests, to exercise the behaviour either side of the window
    // without having to wait for real time to pass.
    void set_simultaneous_connect_window(std::chrono::milliseconds window)
    {
      simultaneous_connect_window = window;
    }

    void set_inbound_handler(
      std::shared_ptr<ccf::NodeInboundHandler> handler) override
    {
      std::lock_guard guard(inbound_handler_mutex);
      inbound_handler = std::move(handler);
    }

    void associate_node_address(
      const ccf::NodeId& node_id,
      const std::string& hostname,
      const std::string& port,
      const std::string& = {},
      const std::string& = {}) override
    {
      ordered("Node address association", [this, node_id, hostname, port]() {
        enqueue_ready(AssociateAddress{node_id, hostname, port});
      });
    }

    void close(const ccf::NodeId& node_id) override
    {
      ordered("Node connection close", [this, node_id]() {
        enqueue_ready(CloseOutbound{node_id});
      });
    }

    void send(
      const ccf::NodeId& to,
      ccf::NodeMsgType msg_type,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload,
      ccf::NodeTransportKind = ccf::NodeTransportKind::Legacy) override
    {
      if (tls_enabled && msg_type != ccf::NodeMsgType::consensus_msg)
      {
        LOG_FAIL_FMT("TLS node transport only supports consensus messages");
        return;
      }
      ordered(
        "Node send",
        [this, to, msg_type, from, payload = std::move(payload)]() {
          auto frame = assemble_frame(to, msg_type, from, payload);
          if (frame.has_value())
          {
            enqueue_ready(SendFrame{to, from, std::move(frame.value())});
          }
        });
    }

    // Loop thread, once the loop has exited and the node has stopped. Closes
    // every socket now rather than when the last owner releases this object,
    // since the node may retain its reference until process exit. Frames not
    // yet written are discarded, as when the loop stops with them queued.
    void shutdown()
    {
      set_inbound_handler(nullptr);
      {
        std::lock_guard guard(outbound_mutex);
        outbound_ready.clear();
      }
      connections.clear();
      unassociated_incoming.clear();
      incoming_created.clear();
      node_addresses.clear();
      listener = nullptr;
    }

    // Loop thread: apply everything the ledger lane has finished, in order.
    void flush_outbound()
    {
      if (tls_enabled)
      {
        const auto now = std::chrono::steady_clock::now();
        const auto timeout =
          client_connection_timeout.value_or(std::chrono::milliseconds(2000));
        for (auto it = incoming_created.begin(); it != incoming_created.end();)
        {
          if (now - it->second >= timeout)
          {
            unassociated_incoming.erase(it->first);
            it = incoming_created.erase(it);
          }
          else
          {
            ++it;
          }
        }
        for (auto it = connections.begin(); it != connections.end();)
        {
          const auto& info = it->second;
          if (
            info.outgoing && now - info.created >= timeout &&
            (info.behaviour->tls == nullptr ||
             !info.behaviour->tls->peer().has_value()))
          {
            it = connections.erase(it);
          }
          else
          {
            ++it;
          }
        }
      }
      std::deque<OutboundItem> ready;
      {
        std::lock_guard guard(outbound_mutex);
        std::swap(ready, outbound_ready);
      }

      for (auto& item : ready)
      {
        std::visit(
          [this](auto&& it) {
            using T = std::decay_t<decltype(it)>;
            if constexpr (std::is_same_v<T, AssociateAddress>)
            {
              node_addresses[it.node_id] = {it.host, it.port};
            }
            else if constexpr (std::is_same_v<T, CloseOutbound>)
            {
              remove_connection(it.node_id);
            }
            else if constexpr (std::is_same_v<T, NodeTLSCredentials>)
            {
              auto updated_context = std::make_shared<NodeTLSContext>(it);
              // Renewal changes the identity presented on subsequent
              // connections; reconnect existing peers to apply it immediately.
              connections.clear();
              unassociated_incoming.clear();
              incoming_created.clear();
              tls_context = std::move(updated_context);
            }
            else
            {
              // The sender field of outbound messages is the only place the
              // host learns its own node ID, which is needed to resolve
              // simultaneous connects consistently on both sides.
              if (!self_node_id.has_value())
              {
                self_node_id = it.from;
              }
              send_frame(it.to, it.frame);
            }
          },
          item);
      }
    }

  private:
    // Ordered step: for an AppendEntries message, read the ledger entries it
    // refers to and append them to the message. Returns the complete framed
    // bytes to write to the peer, or nullopt if the message must be dropped.
    //
    // Wire format: [u32 frame size][msg type][sender ID][payload][entries].
    std::optional<std::vector<uint8_t>> assemble_frame(
      const ccf::NodeId& to,
      ccf::NodeMsgType msg_type,
      const ccf::NodeId& from,
      const std::vector<uint8_t>& payload)
    {
      const auto& from_value = from.value();
      std::vector<uint8_t> header(
        sizeof(msg_type) + sizeof(size_t) + from_value.size());
      {
        auto* hdata = header.data();
        auto hsize = header.size();
        serialized::write(hdata, hsize, msg_type);
        serialized::write(hdata, hsize, from_value);
      }

      const uint8_t* data = payload.data();
      size_t size = payload.size();

      std::vector<uint8_t> entries;
      std::optional<::consensus::AppendEntriesIndex> ae_index;

      if (
        msg_type == ccf::NodeMsgType::consensus_msg &&
        (serialized::read<aft::RaftMsgType>(data, size) ==
         aft::raft_append_entries))
      {
        const auto& ae =
          serialized::overlay<::consensus::AppendEntriesIndex>(data, size);
        ae_index = ae;

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
            return std::nullopt;
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
            return std::nullopt;
          }

          entries = std::move(read_result->data);
        }
      }

      if (
        tls_enabled &&
        header.size() + payload.size() + entries.size() >
          max_inbound_frame_size)
      {
        LOG_FAIL_FMT("Dropping oversized outbound node TLS frame");
        return std::nullopt;
      }
      const auto frame_size =
        static_cast<uint32_t>(header.size() + payload.size() + entries.size());
      std::vector<uint8_t> frame;
      frame.reserve(sizeof(frame_size) + frame_size);
      frame.insert(
        frame.end(),
        reinterpret_cast<const uint8_t*>(&frame_size),
        reinterpret_cast<const uint8_t*>(&frame_size) + sizeof(frame_size));
      frame.insert(frame.end(), header.begin(), header.end());
      frame.insert(frame.end(), payload.begin(), payload.end());
      frame.insert(frame.end(), entries.begin(), entries.end());

      if (ae_index.has_value())
      {
        LOG_DEBUG_FMT(
          "send AE to node {} [{}]: {}, {}",
          to,
          frame_size,
          ae_index->idx,
          ae_index->prev_idx);
      }
      else
      {
        LOG_DEBUG_FMT("node send to {} [{}]", to, frame_size);
      }

      return frame;
    }

    // Loop step: find or open the connection to the peer and write the frame.
    void send_frame(const ccf::NodeId& to, const std::vector<uint8_t>& frame)
    {
      ConnType outbound_connection = nullptr;
      const auto connection_it = connections.find(to);
      if (connection_it == connections.end())
      {
        const auto address_it = node_addresses.find(to);
        if (address_it == node_addresses.end())
        {
          LOG_TRACE_FMT("Ignoring node send to unknown node {}", to);
          return;
        }

        const auto& [host, port] = address_it->second;
        outbound_connection = create_connection(to, host, port);
        if (outbound_connection.is_null())
        {
          LOG_FAIL_FMT(
            "Unable to connect to {}, dropping outbound message message", to);
          return;
        }
      }
      else
      {
        outbound_connection = connection_it->second.socket;
      }

      auto* behaviour = connections.at(to).behaviour;
      if (!behaviour->send(frame))
      {
        remove_connection(to);
      }
    }

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
      auto behaviour = std::make_unique<NodeOutgoingBehaviour>(*this, node_id);
      auto* behaviour_ptr = behaviour.get();
      behaviour->write = [this,
                          socket = s.operator->()](size_t n, const uint8_t* p) {
        return tls_enabled ?
          socket->write_bounded(n, p, 2 * max_inbound_frame_size) :
          socket->write(n, p);
      };
      s->set_behaviour(std::move(behaviour));

      if (!s->connect(host, port, client_interface))
      {
        LOG_FAIL_FMT("Failed to connect to {} on {}:{}", node_id, host, port);
        return nullptr;
      }

      connections[node_id] = {
        s, true, std::chrono::steady_clock::now(), behaviour_ptr};
      LOG_INFO_FMT(
        "Added node connection with {} ({}:{})", node_id, host, port);

      return s;
    }

    // Remove the connection with this peer, if any.
    bool remove_connection(ccf::NodeId node)
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

  // The legacy and TLS listeners own independent connection maps and framing
  // state. Selection is an advertised-capability decision, never a retry or
  // fallback decision after a network failure.
  template <class ConnType>
  class DualNodeConnectionsImpl : public ccf::AbstractNodeTransport
  {
    using Kind = ccf::NodeTransportKind;
    using Transport = NodeConnectionsImpl<ConnType>;
    std::unique_ptr<Transport> legacy;
    std::unique_ptr<Transport> tls;

    struct Route
    {
      Kind kind;
      bool advertised = false;
      bool received = false;
      std::array<std::string, 4> addresses{};
    };
    mutable std::mutex mutex;
    std::unordered_map<ccf::NodeId, Route> routes;
    std::shared_ptr<ccf::NodeInboundHandler> inbound_handler;

    class Inbound : public ccf::NodeInboundHandler
    {
      DualNodeConnectionsImpl& owner;
      const Kind kind;

    public:
      Inbound(DualNodeConnectionsImpl& owner_, Kind kind_) :
        owner(owner_),
        kind(kind_)
      {}

      void recv_node_inbound(
        ccf::NodeMsgType type,
        const ccf::NodeId& from,
        std::vector<uint8_t>&& payload,
        bool authenticated = false) override
      {
        if (
          (kind == Kind::TLS) != authenticated ||
          (authenticated && type != ccf::NodeMsgType::consensus_msg))
        {
          return;
        }
        std::shared_ptr<ccf::NodeInboundHandler> handler;
        {
          std::lock_guard guard(owner.mutex);
          auto it = owner.routes.find(from);
          if (it == owner.routes.end() && authenticated)
          {
            it = owner.routes.try_emplace(from, Route{Kind::TLS}).first;
          }
          // A legacy sender field is untrusted until channel authentication
          // runs on the ingress lane. It must not allocate persistent routes
          // or prevent subsequent TLS-authenticated bootstrap traffic.
          if (it != owner.routes.end())
          {
            auto& route = it->second;
            if (route.kind != kind)
            {
              return;
            }
            if (!route.received)
            {
              LOG_INFO_FMT(
                "Node transport {} received from {}",
                kind == Kind::TLS ? "TLS" : "legacy",
                from);
              route.received = true;
            }
          }
          handler = owner.inbound_handler;
        }
        if (handler != nullptr)
        {
          handler->recv_node_inbound(
            type, from, std::move(payload), authenticated);
        }
      }
    };

  public:
    DualNodeConnectionsImpl(
      Ledger& ledger,
      LedgerSubsystem& ledger_subsystem,
      ccf::NodeInfoNetwork::NodeToNodeInterface& interface,
      size_t max_message_size,
      const std::optional<std::string>& client_interface = std::nullopt,
      std::optional<std::chrono::milliseconds> timeout = std::nullopt,
      size_t tls_record_limit = max_node_tls_records_per_key)
    {
      if (interface.bind_address.empty() && interface.tls_bind_address.empty())
      {
        throw std::logic_error(
          "At least one node-to-node bind address is required");
      }
      if (
        (interface.bind_address.empty() &&
         !interface.published_address.empty()) ||
        (interface.tls_bind_address.empty() &&
         !interface.tls_published_address.empty()))
      {
        throw std::logic_error(
          "A published node address requires its corresponding bind address");
      }
      const auto listen =
        [&](auto& transport, auto& bind, auto& published, Kind kind) {
          if (bind.empty())
          {
            return;
          }
          auto [host, port] = ccf::split_net_address(bind);
          transport = std::make_unique<Transport>(
            ledger,
            ledger_subsystem,
            host,
            port,
            max_message_size,
            client_interface,
            timeout,
            kind == Kind::TLS,
            tls_record_limit);
          bind = ccf::make_net_address(host, port);
          if (published.empty())
          {
            published = bind;
          }
          transport->set_inbound_handler(
            std::make_shared<Inbound>(*this, kind));
        };
      listen(
        legacy,
        interface.bind_address,
        interface.published_address,
        Kind::Legacy);
      listen(
        tls,
        interface.tls_bind_address,
        interface.tls_published_address,
        Kind::TLS);
    }

    ~DualNodeConnectionsImpl() override
    {
      shutdown();
    }

    bool supports_tls() const override
    {
      return tls != nullptr;
    }

    Kind select_transport(const ccf::NodeId& peer) const override
    {
      std::lock_guard guard(mutex);
      const auto it = routes.find(peer);
      // Before advertisement, legacy channels may reply over their existing
      // incoming socket. This bootstrap default never creates a stored route.
      return it == routes.end() ?
        (legacy != nullptr ? Kind::Legacy : Kind::Unavailable) :
        it->second.kind;
    }

    size_t peer_route_count() const
    {
      std::lock_guard guard(mutex);
      return routes.size();
    }

    void set_tls_credentials(
      const ccf::crypto::Pem& service,
      const ccf::crypto::Pem& certificate,
      const ccf::crypto::Pem& key) override
    {
      if (tls != nullptr)
      {
        tls->set_tls_credentials(service, certificate, key);
      }
    }

    void associate_node_address(
      const ccf::NodeId& peer,
      const std::string& host,
      const std::string& port,
      const std::string& tls_host = {},
      const std::string& tls_port = {}) override
    {
      std::lock_guard guard(mutex);
      const auto kind = legacy != nullptr && !host.empty() && !port.empty() ?
        Kind::Legacy :
        (tls != nullptr && !tls_host.empty() && !tls_port.empty() ?
           Kind::TLS :
           Kind::Unavailable);
      const std::array<std::string, 4> addresses{
        host, port, tls_host, tls_port};
      const auto previous = routes.find(peer);
      const bool reconnect = previous != routes.end() &&
        (previous->second.kind != kind ||
         (previous->second.advertised &&
          previous->second.addresses != addresses));
      const bool received = previous != routes.end() &&
        previous->second.kind == kind && previous->second.received;
      routes.insert_or_assign(peer, Route{kind, true, received, addresses});
      if (legacy != nullptr)
      {
        if (reconnect)
        {
          legacy->close(peer);
        }
        legacy->associate_node_address(peer, host, port);
      }
      if (tls != nullptr)
      {
        if (reconnect)
        {
          tls->close(peer);
        }
        tls->associate_node_address(peer, tls_host, tls_port);
      }
    }

    void send(
      const ccf::NodeId& to,
      ccf::NodeMsgType type,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload,
      Kind kind = Kind::Legacy) override
    {
      std::lock_guard guard(mutex);
      const auto it = routes.find(to);
      const auto selected = it == routes.end() ?
        (legacy != nullptr ? Kind::Legacy : Kind::Unavailable) :
        it->second.kind;
      if (
        selected != kind || kind == Kind::Unavailable ||
        (kind == Kind::TLS && type != ccf::NodeMsgType::consensus_msg))
      {
        return;
      }
      auto& transport = kind == Kind::TLS ? tls : legacy;
      transport->send(to, type, from, std::move(payload), kind);
    }

    void close(const ccf::NodeId& peer) override
    {
      if (legacy != nullptr)
      {
        legacy->close(peer);
      }
      if (tls != nullptr)
      {
        tls->close(peer);
      }
    }

    void set_inbound_handler(
      std::shared_ptr<ccf::NodeInboundHandler> handler) override
    {
      std::lock_guard guard(mutex);
      inbound_handler = std::move(handler);
    }

    void flush_outbound()
    {
      if (legacy != nullptr)
      {
        legacy->flush_outbound();
      }
      if (tls != nullptr)
      {
        tls->flush_outbound();
      }
    }

    void shutdown()
    {
      set_inbound_handler(nullptr);
      if (legacy != nullptr)
      {
        legacy->shutdown();
      }
      if (tls != nullptr)
      {
        tls->shutdown();
      }
    }
  };

  using NodeConnections = DualNodeConnectionsImpl<TCP>;

  class FlushNodeOutboundImpl
  {
  private:
    NodeConnections& node;

  public:
    FlushNodeOutboundImpl(NodeConnections& node_) : node(node_) {}

    void on_timer()
    {
      node.flush_outbound();
    }
  };

  using FlushNodeOutbound = ccf::uv::proxy_ptr<Timer<FlushNodeOutboundImpl>>;
}
