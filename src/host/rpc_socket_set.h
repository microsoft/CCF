// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/node_info_network.h"
#include "host/tcp.h"
#include "host/udp.h"

#include <string>
#include <type_traits>
#include <unordered_map>

namespace ccf
{
  template <class T>
  constexpr bool socket_is_tcp()
  {
    return std::is_same_v<T, asynchost::TCP>;
  }

  template <class T>
  constexpr bool socket_is_udp()
  {
    return std::is_same_v<T, asynchost::UDP>;
  }

  // Callbacks an RPCSocketSet needs from its owner (RPCConnectionManager).
  //
  // These all run on the libuv loop thread, invoked from socket behaviours.
  class SocketSetHost
  {
  public:
    using ConnID = ::tcp::ConnID;

    virtual ~SocketSetHost() = default;

    // Allocate the next positive (host-side) connection id.
    virtual ConnID get_next_server_id() = 0;

    // A new connection endpoint is ready and should be given a session. For
    // stream sockets this is a freshly accepted peer; for datagram sockets it
    // is the listening socket itself. `udp` selects the datagram path.
    virtual void on_socket_start(
      ConnID id, const ListenInterfaceID& interface_id, bool udp) = 0;

    // Inbound bytes for connection `id`. `addr` identifies the source peer for
    // datagram sockets and is unused for stream sockets.
    virtual void on_socket_inbound(
      ConnID id, const uint8_t* data, size_t len, sockaddr addr) = 0;

    // The socket for `id` failed or disconnected.
    virtual void on_socket_gone(ConnID id) = 0;
  };

  // Owns the libuv sockets of a single transport type (TCP or UDP) and bridges
  // their callbacks to a SocketSetHost. All methods must be called on the loop
  // thread. This is composed (not inherited) into RPCConnectionManager so that
  // a single manager can own both a TCP and a UDP set while keeping the
  // transport-specific socket handling isolated here.
  template <class ConnType>
  class RPCSocketSet
  {
  public:
    using ConnID = ::tcp::ConnID;

  private:
    SocketSetHost& host;
    std::unordered_map<ConnID, ConnType> sockets;
    std::unordered_map<ConnID, ListenInterfaceID> listen_socket_interface;

    ListenInterfaceID interface_for(ConnID id)
    {
      const auto it = listen_socket_interface.find(id);
      if (it == listen_socket_interface.end())
      {
        throw std::logic_error(
          fmt::format("No listening interface for socket {}", id));
      }
      return it->second;
    }

    // Behaviour for an accepted stream peer or an outbound client socket.
    class PeerBehaviour : public asynchost::SocketBehaviour<ConnType>
    {
    public:
      RPCSocketSet& set;
      ConnID id;

      PeerBehaviour(RPCSocketSet& set_, ConnID id_) :
        asynchost::SocketBehaviour<ConnType>("RPC", "TCP"),
        set(set_),
        id(id_)
      {}

      bool on_read(size_t len, uint8_t*& data, sockaddr /*addr*/) override
      {
        set.host.on_socket_inbound(id, data, len, sockaddr{});
        return true;
      }

      void on_disconnect() override
      {
        set.host.on_socket_gone(id);
      }

      void on_connect_failed() override
      {
        set.host.on_socket_gone(id);
      }

      void on_resolve_failed() override
      {
        set.host.on_socket_gone(id);
      }
    };

    // Behaviour for the listening socket. For TCP it accepts peers; for UDP it
    // is also the data-carrying socket, delivering reads with a source address.
    class ListenBehaviour : public asynchost::SocketBehaviour<ConnType>
    {
    public:
      RPCSocketSet& set;
      ConnID id;

      ListenBehaviour(RPCSocketSet& set_, ConnID id_) :
        asynchost::SocketBehaviour<ConnType>("RPC", "TCP"),
        set(set_),
        id(id_)
      {}

      void on_accept(ConnType& peer) override
      {
        if constexpr (socket_is_tcp<ConnType>())
        {
          const auto peer_id = set.host.get_next_server_id();
          peer->set_behaviour(
            std::make_unique<PeerBehaviour>(set, peer_id));
          set.sockets.emplace(peer_id, peer);
          set.host.on_socket_start(peer_id, set.interface_for(id), false);
        }
      }

      void on_start(int64_t /*peer_id*/) override
      {
        if constexpr (socket_is_udp<ConnType>())
        {
          set.host.on_socket_start(id, set.interface_for(id), true);
        }
      }

      bool on_read(size_t len, uint8_t*& data, sockaddr addr) override
      {
        if constexpr (socket_is_udp<ConnType>())
        {
          set.host.on_socket_inbound(id, data, len, addr);
        }
        return true;
      }
    };

  public:
    explicit RPCSocketSet(SocketSetHost& host_) : host(host_) {}

    bool listen(
      ConnID id,
      const std::string& addr_host,
      const std::string& addr_port,
      const ListenInterfaceID& name)
    {
      if (sockets.find(id) != sockets.end())
      {
        LOG_FAIL_FMT("Cannot listen on id {}: already in use", id);
        return false;
      }

      ConnType s;
      s->set_behaviour(std::make_unique<ListenBehaviour>(*this, id));

      std::string h = addr_host;
      std::string p = addr_port;
      if (!s->listen(h, p, name))
      {
        return false;
      }

      sockets.emplace(id, s);
      listen_socket_interface.emplace(id, name);

      // UDP has no accept step: the listening socket carries data, so start it
      // immediately to trigger session creation.
      if constexpr (socket_is_udp<ConnType>())
      {
        s->start(id);
      }

      return true;
    }

    // Open an outbound stream connection (TCP only).
    bool connect(
      ConnID id, const std::string& addr_host, const std::string& addr_port)
    {
      if constexpr (socket_is_tcp<ConnType>())
      {
        if (sockets.find(id) != sockets.end())
        {
          LOG_FAIL_FMT("Cannot connect on id {}: already in use", id);
          return false;
        }

        auto s = ConnType(true);
        s->set_behaviour(std::make_unique<PeerBehaviour>(*this, id));
        if (!s->connect(addr_host, addr_port))
        {
          return false;
        }
        sockets.emplace(id, s);
        return true;
      }
      else
      {
        (void)id;
        (void)addr_host;
        (void)addr_port;
        return false;
      }
    }

    bool write(ConnID id, const std::vector<uint8_t>& data, sockaddr addr)
    {
      auto it = sockets.find(id);
      if (it == sockets.end() || it->second.is_null())
      {
        return false;
      }
      return it->second->write(data.size(), data.data(), addr);
    }

    // Invalidate the socket: the uv handle is closed, no further reads or
    // writes occur, but the entry is retained until close().
    bool stop(ConnID id)
    {
      auto it = sockets.find(id);
      if (it == sockets.end())
      {
        return false;
      }
      it->second = nullptr;
      return true;
    }

    bool close(ConnID id)
    {
      listen_socket_interface.erase(id);
      return sockets.erase(id) > 0;
    }

    bool has(ConnID id) const
    {
      return sockets.find(id) != sockets.end();
    }
  };
}
