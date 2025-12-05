// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../tcp/msg_types.h"
#include "../udp/msg_types.h"
#include "tcp.h"
#include "udp.h"

#include <unordered_map>

namespace // NOLINT(cert-dcl59-cpp)
{
  template <class T>
  constexpr bool isTCP()
  {
    return std::is_same<T, asynchost::TCP>();
  }

  template <class T>
  constexpr bool isUDP()
  {
    return std::is_same<T, asynchost::UDP>();
  }

  template <class T>
  constexpr const char* getConnTypeName()
  {
    if constexpr (isTCP<T>())
    {
      return "TCP";
    }
    else if constexpr (isUDP<T>())
    {
      return "UDP";
    }
    else
    {
      throw std::runtime_error("Invalid connection type");
    }
  }
}

namespace asynchost
{
  /**
   * Generates next ID, passed as an argument to RPCConnectionsImpl so that we
   * can have multiple and avoid reusing the same ConnID across each.
   */
  class ConnIDGenerator
  {
  public:
    /// This is the same as ccf::tls::ConnID and udp::ConnID
    using ConnID = int64_t;
    static_assert(std::is_same<::tcp::ConnID, udp::ConnID>());
    static_assert(std::is_same<::tcp::ConnID, ConnID>());

    ConnIDGenerator() : next_id(1) {}

    template <class T>
    ConnID get_next_id(T& sockets)
    {
      auto id = next_id++;
      const auto initial = id;

      if (next_id < 0)
      {
        next_id = 1;
      }

      while (sockets.find(id) != sockets.end())
      {
        id++;

        if (id < 0)
        {
          id = 1;
        }

        if (id == initial)
        {
          throw std::runtime_error(
            "Exhausted all IDs for host RPC connections");
        }
      }

      return id;
    }

  private:
    std::atomic<ConnID> next_id;
  };

  template <class ConnType>
  class RPCConnectionsImpl
  {
    using ConnID = ConnIDGenerator::ConnID;

    class RPCClientBehaviour : public SocketBehaviour<ConnType>
    {
    public:
      RPCConnectionsImpl& parent;
      ConnID id;

      RPCClientBehaviour(RPCConnectionsImpl& parent, ConnID id) :
        SocketBehaviour<ConnType>("RPC Client", getConnTypeName<ConnType>()),
        parent(parent),
        id(id)
      {
        parent.mark_active(id);
      }

      void on_resolve_failed() override
      {
        LOG_DEBUG_FMT("rpc resolve failed {}", id);
        cleanup();
      }

      void on_connect_failed() override
      {
        LOG_DEBUG_FMT("rpc connect failed {}", id);
        cleanup();
      }

      bool on_read(size_t len, uint8_t*& data, sockaddr /*unused*/) override
      {
        LOG_DEBUG_FMT("rpc read {}: {}", id, len);

        parent.mark_active(id);

        RINGBUFFER_WRITE_MESSAGE(
          ::tcp::tcp_inbound,
          parent.to_enclave,
          id,
          serializer::ByteRange{data, len});

        return true;
      }

      void on_disconnect() override
      {
        LOG_DEBUG_FMT("rpc disconnect {}", id);
        cleanup();
      }

      void cleanup()
      {
        if constexpr (isTCP<ConnType>())
        {
          RINGBUFFER_WRITE_MESSAGE(::tcp::tcp_close, parent.to_enclave, id);
        }
      }
    };

    class RPCServerBehaviour : public SocketBehaviour<ConnType>
    {
    public:
      RPCConnectionsImpl& parent;
      ConnID id;

      RPCServerBehaviour(RPCConnectionsImpl& parent, ConnID id) :
        SocketBehaviour<ConnType>("RPC Client", getConnTypeName<ConnType>()),
        parent(parent),
        id(id)
      {}

      void on_accept(ConnType& peer) override
      {
        // UDP connections don't register peers
        if constexpr (isUDP<ConnType>())
        {
          return;
        }

        auto client_id = parent.get_next_id();
        peer->set_behaviour(
          std::make_unique<RPCClientBehaviour>(parent, client_id));
        parent.sockets.emplace(client_id, peer);

        on_start(client_id);
      }

      void on_start(int64_t peer_id) override
      {
        const auto interface_name = parent.get_interface_listen_name(id);

        LOG_DEBUG_FMT(
          "rpc start {} on interface \"{}\" as {}",
          peer_id,
          interface_name,
          this->conn_name);

        if constexpr (isTCP<ConnType>())
        {
          RINGBUFFER_WRITE_MESSAGE(
            ::tcp::tcp_start, parent.to_enclave, peer_id, interface_name);
          return;
        }

        if constexpr (isUDP<ConnType>())
        {
          RINGBUFFER_WRITE_MESSAGE(
            udp::udp_start, parent.to_enclave, peer_id, interface_name);
          return;
        }
      }

      bool on_read(size_t len, uint8_t*& data, sockaddr addr) override
      {
        // UDP connections don't have clients, it's all done in the server
        if constexpr (isUDP<ConnType>())
        {
          auto [addr_family, addr_data] = udp::sockaddr_encode(addr);

          LOG_DEBUG_FMT("rpc udp read into ring buffer {}: {}", id, len);
          RINGBUFFER_WRITE_MESSAGE(
            udp::udp_inbound,
            parent.to_enclave,
            id,
            addr_family,
            addr_data,
            serializer::ByteRange{data, len});
        }

        return true;
      }

      void cleanup()
      {
        parent.sockets.erase(id);
      }
    };

    std::unordered_map<ConnID, ConnType> sockets;
    ConnIDGenerator& idGen;

    // Measured in seconds
    std::unordered_map<ConnID, size_t> idle_times;

    std::optional<std::chrono::milliseconds> client_connection_timeout =
      std::nullopt;

    std::optional<std::chrono::seconds> idle_connection_timeout = std::nullopt;

    ringbuffer::WriterPtr to_enclave;

  public:
    RPCConnectionsImpl(
      ringbuffer::AbstractWriterFactory& writer_factory,
      ConnIDGenerator& idGen,
      std::optional<std::chrono::milliseconds> client_connection_timeout_ =
        std::nullopt,
      std::optional<std::chrono::seconds> idle_connection_timeout_ =
        std::nullopt) :
      idGen(idGen),
      client_connection_timeout(client_connection_timeout_),
      idle_connection_timeout(idle_connection_timeout_),
      to_enclave(writer_factory.create_writer_to_inside())
    {}

    bool listen(
      ConnID id, std::string& host, std::string& port, const std::string& name)
    {
      if (id == 0)
      {
        id = get_next_id();
      }

      if (sockets.find(id) != sockets.end())
      {
        LOG_FAIL_FMT("Cannot listen on id {}: already in use", id);
        return false;
      }

      ConnType s;
      s->set_behaviour(std::make_unique<RPCServerBehaviour>(*this, id));

      if (!s->listen(host, port, name))
      {
        return false;
      }

      host = s->get_host();
      port = s->get_port();

      sockets.emplace(id, s);

      // UDP connections don't have peers, so we need to register the main
      // socket TCP connections started via peer, on on_accept behaviour call
      if constexpr (isUDP<ConnType>())
      {
        s->start(id);
      }

      return true;
    }

    bool connect(ConnID id, const std::string& host, const std::string& port)
    {
      if (id == 0)
      {
        id = get_next_id();
      }

      if (sockets.find(id) != sockets.end())
      {
        LOG_FAIL_FMT("Cannot connect on id {}: already in use", id);
        return false;
      }

      auto s = ConnType(true, client_connection_timeout);
      s->set_behaviour(std::make_unique<RPCClientBehaviour>(*this, id));

      if (!s->connect(host, port))
      {
        return false;
      }

      sockets.emplace(id, s);
      return true;
    }

    bool write(ConnID id, size_t len, const uint8_t* data, sockaddr addr = {})
    {
      auto s = sockets.find(id);

      if (s == sockets.end())
      {
        LOG_FAIL_FMT(
          "Received an outbound message for id {} which is not a known "
          "connection. Ignoring message of {} bytes",
          id,
          len);
        return false;
      }

      if (s->second.is_null())
      {
        return false;
      }

      mark_active(id);

      return s->second->write(len, data, addr);
    }

    bool stop(ConnID id)
    {
      // Invalidating the TCP socket will result in the handle being closed. No
      // more messages will be read from or written to the TCP socket.
      sockets[id] = nullptr;

      RINGBUFFER_WRITE_MESSAGE(::tcp::tcp_close, to_enclave, id);

      return true;
    }

    bool close(ConnID id)
    {
      if (sockets.erase(id) < 1)
      {
        LOG_DEBUG_FMT("Cannot close id {}: does not exist", id);
        return false;
      }

      // Make sure idle_times is cleaned up here, though in practice it should
      // have been cleared when an earlier stop() was called
      idle_times.erase(id);

      return true;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ::tcp::tcp_outbound, [this](const uint8_t* data, size_t size) {
          auto [id, body] =
            ringbuffer::read_message<::tcp::tcp_outbound>(data, size);

          auto connect_id = static_cast<ConnID>(id);
          LOG_DEBUG_FMT("rpc write from enclave {}: {}", connect_id, body.size);

          write(connect_id, body.size, body.data);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ::tcp::tcp_connect, [this](const uint8_t* data, size_t size) {
          auto [id, host, port] =
            ringbuffer::read_message<::tcp::tcp_connect>(data, size);

          LOG_DEBUG_FMT("rpc connect request from enclave {}", id);

          if (check_enclave_side_id(id))
          {
            connect(id, host, port);
          }
          else
          {
            LOG_FAIL_FMT(
              "rpc session id is not in dedicated from-enclave range ({})", id);
          }
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ::tcp::tcp_stop, [this](const uint8_t* data, size_t size) {
          auto [id, msg] =
            ringbuffer::read_message<::tcp::tcp_stop>(data, size);

          LOG_DEBUG_FMT("rpc stop from enclave {}, {}", id, msg);
          stop(id);

          // Immediately stop tracking idle timeout for this ID too
          idle_times.erase(id);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ::tcp::tcp_closed, [this](const uint8_t* data, size_t size) {
          auto [id] = ringbuffer::read_message<::tcp::tcp_closed>(data, size);

          LOG_DEBUG_FMT("rpc closed from enclave {}", id);
          close(id);
        });
    }

    void register_udp_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, udp::udp_outbound, [this](const uint8_t* data, size_t size) {
          auto [id, addr_family, addr_data, body] =
            ringbuffer::read_message<udp::udp_outbound>(data, size);

          auto connect_id = static_cast<ConnID>(id);
          LOG_DEBUG_FMT("rpc write from enclave {}: {}", connect_id, body.size);

          auto addr = udp::sockaddr_decode(addr_family, addr_data);
          write(connect_id, body.size, body.data, addr);
        });
    }

    void mark_active(ConnID id)
    {
      idle_times[id] = 0;
    }

    void on_timer()
    {
      if (!idle_connection_timeout.has_value())
      {
        return;
      }

      const size_t max_idle_time = idle_connection_timeout->count();

      auto it = idle_times.begin();
      while (it != idle_times.end())
      {
        auto& [id, idle_time] = *it;
        if (idle_time > max_idle_time)
        {
          LOG_INFO_FMT(
            "Closing socket {} after {}s idle (max = {}s)",
            id,
            idle_time,
            max_idle_time);
          stop(id);
          it = idle_times.erase(it);
        }
        else
        {
          idle_time += 1;
          ++it;
        }
      }
    }

  private:
    ConnID get_next_id()
    {
      return idGen.get_next_id(sockets);
    }

    bool check_enclave_side_id(ConnID id)
    {
      return id < 0;
    }

    std::string get_interface_listen_name(ConnID id)
    {
      const auto it = sockets.find(id);
      if (it == sockets.end())
      {
        LOG_FAIL_FMT(
          "Requested interface number {}, has {}", id, sockets.size());
        throw std::logic_error(fmt::format("No socket with id {}", id));
      }

      auto listen_name = it->second->get_listen_name();
      if (!listen_name.has_value())
      {
        throw std::logic_error(
          fmt::format("Interface {} has no listen name", id));
      }

      return listen_name.value();
    }
  };

  template <class ConnType>
  using RPCConnections = proxy_ptr<Timer<RPCConnectionsImpl<ConnType>>>;
}
