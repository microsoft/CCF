// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

#include <uv.h>

namespace asynchost
{
  /**
   * @brief Callback service for user-specific behaviour for TCP and UDP
   * connections.
   *
   * @tparam ConnType Either TCP (proxy_ptr<TCPImpl>) or UDP
   * (proxy_ptr<UDPImpl>).
   */
  template <class ConnType>
  class SocketBehaviour
  {
  protected:
    const char* name;
    const char* conn_name;

  public:
    SocketBehaviour(const char* name, const char* conn_name) :
      name(name),
      conn_name(conn_name)
    {}
    virtual ~SocketBehaviour() {}

    /// To be implemented by clients
    virtual void on_read(size_t, uint8_t*&, sockaddr) {}

    /// To be implemented by servers with connections
    virtual void on_accept(ConnType&) {}

    /// To be implemented by all servers (after registration)
    virtual void on_start(int64_t) {}

    /// Generic loggers for common reactions
    virtual void on_listening(
      const std::string& host, const std::string& service)
    {
      LOG_INFO_FMT("{} {} listening on {}:{}", conn_name, name, host, service);
    }
    virtual void on_connect()
    {
      LOG_INFO_FMT("{} {} connected", conn_name, name);
    }
    virtual void on_disconnect()
    {
      LOG_TRACE_FMT("{} {} disconnected", conn_name, name);
    }

    /// Failure loggers for when things go wrong, but not fatal
    virtual void on_bind_failed()
    {
      LOG_INFO_FMT("{} {} bind failed", conn_name, name);
    }
    virtual void on_connect_failed()
    {
      LOG_INFO_FMT("{} {} connect failed", conn_name, name);
    }

    /// Failure loggers for when things go wrong, fataly
    virtual void on_resolve_failed()
    {
      LOG_FATAL_FMT("{} {} resolve failed", conn_name, name);
    }
    virtual void on_listen_failed()
    {
      LOG_FATAL_FMT("{} {} listen failed", conn_name, name);
    }
  };

  std::pair<std::string, std::string> addr_to_str(
    const sockaddr* addr, int address_family = AF_INET)
  {
    constexpr auto buf_len = INET6_ADDRSTRLEN;
    char buf[buf_len] = {};
    int rc;

    if (address_family == AF_INET6)
    {
      const auto in6 = (const sockaddr_in6*)addr;
      if ((rc = uv_ip6_name(in6, buf, buf_len)) != 0)
      {
        LOG_FAIL_FMT("uv_ip6_name failed: {}", uv_strerror(rc));
      }

      return {
        fmt::format("[{}]", buf), fmt::format("{}", ntohs(in6->sin6_port))};
    }

    assert(address_family == AF_INET);
    const auto in4 = (const sockaddr_in*)addr;
    if ((rc = uv_ip4_name(in4, buf, buf_len)) != 0)
    {
      LOG_FAIL_FMT("uv_ip4_name failed: {}", uv_strerror(rc));
    }

    return {buf, fmt::format("{}", ntohs(in4->sin_port))};
  }
}