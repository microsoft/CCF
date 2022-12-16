// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "before_io.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"
#include "dns.h"
#include "ds/pending_io.h"
#include "proxy.h"
#include "socket.h"

#include <netinet/in.h>
#include <optional>

namespace asynchost
{
  class TCPImpl;
  using TCP = proxy_ptr<TCPImpl>;

  class TCPImpl : public with_uv_handle<uv_tcp_t>
  {
  private:
    friend class close_ptr<TCPImpl>;

    static constexpr int backlog = 128;
    static constexpr size_t max_read_size = 16384;

    // Each uv iteration, read only a capped amount from all sockets.
    static constexpr auto max_read_quota = max_read_size * 4;
    static size_t remaining_read_quota;

    enum Status
    {
      FRESH,
      LISTENING_RESOLVING,
      LISTENING,
      BINDING,
      BINDING_FAILED,
      CONNECTING_RESOLVING,
      CONNECTING,
      CONNECTED,
      DISCONNECTED,
      RESOLVING_FAILED,
      LISTENING_FAILED,
      CONNECTING_FAILED,
      RECONNECTING
    };

    bool is_client;
    std::optional<std::chrono::milliseconds> connection_timeout = std::nullopt;
    Status status;
    std::unique_ptr<SocketBehaviour<TCP>> behaviour;
    using PendingWrites = std::vector<PendingIO<uv_write_t>>;
    PendingWrites pending_writes;

    std::string host;
    std::string port;
    std::optional<std::string> client_host = std::nullopt;
    std::optional<std::string> listen_name = std::nullopt;

    addrinfo* client_addr_base = nullptr;
    addrinfo* addr_base = nullptr;
    addrinfo* addr_current = nullptr;

    bool port_assigned() const
    {
      return port != "0";
    }

    std::string get_address_name() const
    {
      const std::string port_suffix =
        port_assigned() ? fmt::format(":{}", port) : "";

      if (addr_current != nullptr && addr_current->ai_family == AF_INET6)
      {
        return fmt::format("[{}]{}", host, port_suffix);
      }
      else
      {
        return fmt::format("{}{}", host, port_suffix);
      }
    }

    TCPImpl(
      bool is_client_ = false,
      std::optional<std::chrono::milliseconds> connection_timeout_ =
        std::nullopt) :
      is_client(is_client_),
      connection_timeout(connection_timeout_),
      status(FRESH)
    {
      if (!init())
      {
        throw std::logic_error("uv tcp initialization failed");
      }

      uv_handle.data = this;
    }

    ~TCPImpl()
    {
      {
        std::unique_lock<ccf::pal::Mutex> guard(pending_resolve_requests_mtx);
        for (auto& req : pending_resolve_requests)
        {
          // The UV request objects can stay, but if there are any references
          // to `this` left, we need to remove them.
          if (req->data == this)
          {
            req->data = nullptr;
          }
        }
      }
      if (addr_base != nullptr)
      {
        uv_freeaddrinfo(addr_base);
      }
      if (client_addr_base != nullptr)
      {
        uv_freeaddrinfo(client_addr_base);
      }
    }

  public:
    static void reset_read_quota()
    {
      remaining_read_quota = max_read_quota;
    }

    void set_behaviour(std::unique_ptr<SocketBehaviour<TCP>> b)
    {
      behaviour = std::move(b);
    }

    std::string get_host() const
    {
      return host;
    }

    std::string get_port() const
    {
      return port;
    }

    std::string get_peer_name() const
    {
      sockaddr_storage sa = {};
      int name_len = sizeof(sa);
      if (uv_tcp_getpeername(&uv_handle, (sockaddr*)&sa, &name_len) < 0)
      {
        LOG_FAIL_FMT("uv_tcp_getpeername failed");
        return "";
      }
      switch (sa.ss_family)
      {
        case AF_INET:
        {
          char tmp[INET_ADDRSTRLEN];
          sockaddr_in* sa4 = (sockaddr_in*)&sa;
          uv_ip4_name(sa4, tmp, sizeof(tmp));
          return tmp;
        }
        case AF_INET6:
        {
          char tmp[INET6_ADDRSTRLEN];
          sockaddr_in6* sa6 = (sockaddr_in6*)&sa;
          uv_ip6_name(sa6, tmp, sizeof(tmp));
          return tmp;
        }
        default:
          return fmt::format("unknown family: {}", sa.ss_family);
      }
    }

    std::optional<std::string> get_listen_name() const
    {
      return listen_name;
    }

    void client_bind()
    {
      int rc;
      if ((rc = uv_tcp_bind(&uv_handle, client_addr_base->ai_addr, 0)) < 0)
      {
        assert_status(BINDING, BINDING_FAILED);
        LOG_FAIL_FMT("uv_tcp_bind failed: {}", uv_strerror(rc));
        behaviour->on_bind_failed();
      }
      else
      {
        assert_status(BINDING, CONNECTING_RESOLVING);
        if (addr_current != nullptr)
        {
          connect_resolved();
        }
        else
        {
          resolve(this->host, this->port, true);
        }
      }
    }

    static void on_client_resolved(
      uv_getaddrinfo_t* req, int rc, struct addrinfo*)
    {
      static_cast<TCPImpl*>(req->data)->on_client_resolved(req, rc);
    }

    void on_client_resolved(uv_getaddrinfo_t* req, int rc)
    {
      if (!uv_is_closing((uv_handle_t*)&uv_handle))
      {
        if (rc < 0)
        {
          assert_status(BINDING, BINDING_FAILED);
          LOG_DEBUG_FMT("TCP client resolve failed: {}", uv_strerror(rc));
          behaviour->on_bind_failed();
        }
        else
        {
          client_addr_base = req->addrinfo;
          client_bind();
        }
      }

      delete req;
    }

    /// This is to mimic UDP's implementation. TCP's start is on_accept.
    void start(int64_t id) {}

    bool connect(
      const std::string& host,
      const std::string& port,
      const std::optional<std::string>& client_host = std::nullopt)
    {
      // If a client host is set, bind to this first. Otherwise, connect
      // straight away.
      if (client_host.has_value())
      {
        this->client_host = client_host;
        this->host = host;
        this->port = port;

        if (client_addr_base != nullptr)
        {
          uv_freeaddrinfo(client_addr_base);
          client_addr_base = nullptr;
        }

        status = BINDING;
        if (!DNS::resolve(
              client_host.value(), "0", this, on_client_resolved, false))
        {
          LOG_DEBUG_FMT("Bind to '{}' failed", client_host.value());
          status = BINDING_FAILED;
          return false;
        }
      }
      else
      {
        assert_status(FRESH, CONNECTING_RESOLVING);
        return resolve(host, port, true);
      }

      return true;
    }

    bool reconnect()
    {
      switch (status)
      {
        case BINDING_FAILED:
        {
          // Try again, from the start.
          LOG_DEBUG_FMT("Reconnect from initial state");
          assert_status(BINDING_FAILED, BINDING);
          return connect(host, port, client_host);
        }
        case RESOLVING_FAILED:
        case CONNECTING_FAILED:
        {
          // Try again, starting with DNS.
          LOG_DEBUG_FMT("Reconnect from DNS");
          status = CONNECTING_RESOLVING;
          return resolve(host, port, true);
        }

        case DISCONNECTED:
        {
          // It's possible there was a request to close the uv_handle in the
          // meanwhile; in that case we abort the reconnection attempt.
          if (!uv_is_closing((uv_handle_t*)&uv_handle))
          {
            // Close and reset the uv_handle before trying again with the same
            // addr_current that succeeded previously.
            LOG_DEBUG_FMT("Reconnect from resolved address");
            status = RECONNECTING;
            uv_close((uv_handle_t*)&uv_handle, on_reconnect);
          }
          return true;
        }

        default:
        {
          LOG_DEBUG_FMT(
            "Unexpected status during reconnect, ignoring: {}", status);
        }
      }

      return false;
    }

    bool listen(
      const std::string& host,
      const std::string& port,
      const std::optional<std::string>& name = std::nullopt)
    {
      assert_status(FRESH, LISTENING_RESOLVING);
      bool ret = resolve(host, port, false);
      listen_name = name;
      return ret;
    }

    bool write(size_t len, const uint8_t* data, sockaddr addr = {})
    {
      auto req = new uv_write_t;
      char* copy = new char[len];
      if (data)
        memcpy(copy, data, len);
      req->data = copy;

      switch (status)
      {
        case BINDING:
        case BINDING_FAILED:
        case CONNECTING_RESOLVING:
        case CONNECTING:
        case RESOLVING_FAILED:
        case CONNECTING_FAILED:
        case RECONNECTING:
        {
          pending_writes.emplace_back(req, len, sockaddr{}, free_write);
          break;
        }

        case CONNECTED:
        {
          return send_write(req, len);
        }

        case DISCONNECTED:
        {
          LOG_DEBUG_FMT("Disconnected: Ignoring write of size {}", len);
          free_write(req);
          break;
        }

        default:
        {
          free_write(req);
          throw std::logic_error(
            fmt::format("Unexpected status during write: {}", status));
        }
      }

      return true;
    }

  private:
    bool init()
    {
      assert_status(FRESH, FRESH);

      int rc;
      if ((rc = uv_tcp_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL_FMT("uv_tcp_init failed: {}", uv_strerror(rc));
        return false;
      }

      if ((rc = uv_tcp_nodelay(&uv_handle, true)) < 0)
      {
        LOG_FAIL_FMT("uv_tcp_nodelay failed: {}", uv_strerror(rc));
        return false;
      }

      if (is_client)
      {
        uv_os_sock_t sock;
        if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        {
          LOG_FAIL_FMT("socket creation failed: {}", strerror(errno));
          return false;
        }

        if (connection_timeout.has_value())
        {
          auto const t = connection_timeout.value();
          setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &t, sizeof(t));
        }

        if ((rc = uv_tcp_open(&uv_handle, sock)) < 0)
        {
          LOG_FAIL_FMT("uv_tcp_open failed: {}", uv_strerror(rc));
          return false;
        }
      }

      if ((rc = uv_tcp_keepalive(&uv_handle, 1, 30)) < 0)
      {
        LOG_FAIL_FMT("uv_tcp_keepalive failed: {}", uv_strerror(rc));
        return false;
      }

      uv_handle.data = this;
      return true;
    }

    bool send_write(uv_write_t* req, size_t len)
    {
      char* copy = (char*)req->data;

      uv_buf_t buf;
      buf.base = copy;
      buf.len = len;

      int rc;

      if ((rc = uv_write(req, (uv_stream_t*)&uv_handle, &buf, 1, on_write)) < 0)
      {
        free_write(req);
        LOG_FAIL_FMT("uv_write failed: {}", uv_strerror(rc));
        assert_status(CONNECTED, DISCONNECTED);
        behaviour->on_disconnect();
        return false;
      }

      return true;
    }

    void update_resolved_address(int address_family, sockaddr* sa)
    {
      auto [h, p] = addr_to_str(sa, address_family);
      host = h;
      port = p;
      LOG_TRACE_FMT("TCP update address to {}:{}", host, port);
    }

    void listen_resolved()
    {
      int rc;

      while (addr_current != nullptr)
      {
        update_resolved_address(addr_current->ai_family, addr_current->ai_addr);

        if ((rc = uv_tcp_bind(&uv_handle, addr_current->ai_addr, 0)) < 0)
        {
          addr_current = addr_current->ai_next;
          LOG_FAIL_FMT(
            "uv_tcp_bind failed on {}: {}",
            get_address_name(),
            uv_strerror(rc));
          continue;
        }

        if ((rc = uv_listen((uv_stream_t*)&uv_handle, backlog, on_accept)) < 0)
        {
          LOG_FAIL_FMT(
            "uv_listen failed on {}: {}", get_address_name(), uv_strerror(rc));
          addr_current = addr_current->ai_next;
          continue;
        }

        // If bound on port 0 (ie - asking the OS to assign a port), then we
        // need to call uv_tcp_getsockname to retrieve the bound port
        // (addr_current will not contain it)
        if (!port_assigned())
        {
          sockaddr_storage sa_storage;
          const auto sa = (sockaddr*)&sa_storage;
          int sa_len = sizeof(sa_storage);
          if ((rc = uv_tcp_getsockname(&uv_handle, sa, &sa_len)) != 0)
          {
            LOG_FAIL_FMT("uv_tcp_getsockname failed: {}", uv_strerror(rc));
          }
          update_resolved_address(addr_current->ai_family, sa);
        }

        assert_status(LISTENING_RESOLVING, LISTENING);
        behaviour->on_listening(host, port);
        return;
      }

      assert_status(LISTENING_RESOLVING, LISTENING_FAILED);
      behaviour->on_listen_failed();
    }

    bool connect_resolved()
    {
      auto req = new uv_connect_t;
      int rc;

      while (addr_current != nullptr)
      {
        if (
          (rc = uv_tcp_connect(
             req, &uv_handle, addr_current->ai_addr, on_connect)) < 0)
        {
          LOG_DEBUG_FMT("uv_tcp_connect retry: {}", uv_strerror(rc));
          addr_current = addr_current->ai_next;
          continue;
        }

        assert_status(CONNECTING_RESOLVING, CONNECTING);
        return true;
      }

      assert_status(CONNECTING_RESOLVING, CONNECTING_FAILED);
      delete req;

      // This should show even when verbose logs are off
      LOG_INFO_FMT(
        "Unable to connect: all resolved addresses failed: {}:{}", host, port);

      behaviour->on_connect_failed();
      return false;
    }

    void assert_status(Status from, Status to)
    {
      if (status != from)
      {
        throw std::logic_error(fmt::format(
          "Trying to transition from {} to {} but current status is {}",
          from,
          to,
          status));
      }

      status = to;
    }

    bool resolve(
      const std::string& host, const std::string& port, bool async = true)
    {
      this->host = host;
      this->port = port;

      if (addr_base != nullptr)
      {
        uv_freeaddrinfo(addr_base);
        addr_base = nullptr;
        addr_current = nullptr;
      }

      if (!DNS::resolve(host, port, this, on_resolved, async))
      {
        LOG_DEBUG_FMT("Resolving '{}' failed", host);
        status = RESOLVING_FAILED;
        return false;
      }

      return true;
    }

    static void on_resolved(uv_getaddrinfo_t* req, int rc, struct addrinfo* res)
    {
      std::unique_lock<ccf::pal::Mutex> guard(pending_resolve_requests_mtx);
      pending_resolve_requests.erase(req);

      if (req->data)
      {
        static_cast<TCPImpl*>(req->data)->on_resolved(req, rc);
      }
      else
      {
        // The TCPImpl that submitted the request has been destroyed, but we
        // need to clean up the request object.
        uv_freeaddrinfo(res);
        delete req;
      }
    }

    void on_resolved(uv_getaddrinfo_t* req, int rc)
    {
      // It is possible that on_resolved is triggered after there has been a
      // request to close uv_handle. In this scenario, we should not try to
      // do anything with the handle and return immediately (otherwise,
      // uv_close cb will abort).
      if (uv_is_closing((uv_handle_t*)&uv_handle))
      {
        LOG_DEBUG_FMT("on_resolved: closing");
        uv_freeaddrinfo(req->addrinfo);
        delete req;
        return;
      }

      if (rc < 0)
      {
        status = RESOLVING_FAILED;
        LOG_DEBUG_FMT("TCP resolve failed: {}", uv_strerror(rc));
        behaviour->on_resolve_failed();
      }
      else
      {
        addr_base = req->addrinfo;
        addr_current = addr_base;

        switch (status)
        {
          case CONNECTING_RESOLVING:
          {
            connect_resolved();
            break;
          }

          case LISTENING_RESOLVING:
          {
            listen_resolved();
            break;
          }

          default:
          {
            throw std::logic_error(
              fmt::format("Unexpected status during on_resolved: {}", status));
          }
        }
      }

      delete req;
    }

    static void on_accept(uv_stream_t* handle, int rc)
    {
      static_cast<TCPImpl*>(handle->data)->on_accept(rc);
    }

    void on_accept(int rc)
    {
      if (rc < 0)
      {
        LOG_DEBUG_FMT("on_accept failed: {}", uv_strerror(rc));
        return;
      }

      TCP peer;

      if (
        (rc = uv_accept(
           (uv_stream_t*)&uv_handle, (uv_stream_t*)&peer->uv_handle)) < 0)
      {
        LOG_DEBUG_FMT("uv_accept failed: {}", uv_strerror(rc));
        return;
      }

      peer->assert_status(FRESH, CONNECTED);

      if (!peer->read_start())
        return;

      behaviour->on_accept(peer);
    }

    static void on_connect(uv_connect_t* req, int rc)
    {
      auto self = static_cast<TCPImpl*>(req->handle->data);
      delete req;

      if (rc == UV_ECANCELED)
      {
        // Break reconnection loop early if cancelled
        LOG_FAIL_FMT("on_connect: cancelled");
        return;
      }

      self->on_connect(rc);
    }

    void on_connect(int rc)
    {
      if (rc < 0)
      {
        // Try again on the next address.
        LOG_DEBUG_FMT("uv_tcp_connect async retry: {}", uv_strerror(rc));
        addr_current = addr_current->ai_next;
        assert_status(CONNECTING, CONNECTING_RESOLVING);
        connect_resolved();
      }
      else
      {
        assert_status(CONNECTING, CONNECTED);

        if (!read_start())
        {
          return;
        }

        for (auto& w : pending_writes)
        {
          send_write(w.req, w.len);
          w.req = nullptr;
        }

        PendingWrites().swap(pending_writes);
        behaviour->on_connect();
      }
    }

    bool read_start()
    {
      int rc;

      if ((rc = uv_read_start((uv_stream_t*)&uv_handle, on_alloc, on_read)) < 0)
      {
        assert_status(CONNECTED, DISCONNECTED);
        LOG_FAIL_FMT("uv_read_start failed: {}", uv_strerror(rc));

        if (behaviour)
        {
          behaviour->on_disconnect();
        }

        return false;
      }

      return true;
    }

    static void on_alloc(
      uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
    {
      static_cast<TCPImpl*>(handle->data)->on_alloc(suggested_size, buf);
    }

    void on_alloc(size_t suggested_size, uv_buf_t* buf)
    {
      auto alloc_size = std::min(suggested_size, max_read_size);

      alloc_size = std::min(alloc_size, remaining_read_quota);
      remaining_read_quota -= alloc_size;
      LOG_TRACE_FMT(
        "Allocating {} bytes for TCP read ({} of quota remaining)",
        alloc_size,
        remaining_read_quota);

      buf->base = new char[alloc_size];
      buf->len = alloc_size;
    }

    void on_free(const uv_buf_t* buf)
    {
      delete[] buf->base;
    }

    static void on_read(uv_stream_t* handle, ssize_t sz, const uv_buf_t* buf)
    {
      static_cast<TCPImpl*>(handle->data)->on_read(sz, buf);
    }

    void on_read(ssize_t sz, const uv_buf_t* buf)
    {
      if (sz == 0)
      {
        on_free(buf);
        return;
      }

      if (sz == UV_ENOBUFS)
      {
        LOG_DEBUG_FMT("TCP on_read reached allocation quota");
        on_free(buf);
        return;
      }

      if (sz < 0)
      {
        assert_status(CONNECTED, DISCONNECTED);
        on_free(buf);
        uv_read_stop((uv_stream_t*)&uv_handle);

        LOG_DEBUG_FMT("TCP on_read: {}", uv_strerror(sz));
        behaviour->on_disconnect();
        return;
      }

      uint8_t* p = (uint8_t*)buf->base;
      behaviour->on_read((size_t)sz, p, {});

      if (p != nullptr)
      {
        on_free(buf);
      }
    }

    static void on_write(uv_write_t* req, int)
    {
      free_write(req);
    }

    static void free_write(uv_write_t* req)
    {
      if (req == nullptr)
      {
        return;
      }

      char* copy = (char*)req->data;
      delete[] copy;
      delete req;
    }

    static void on_reconnect(uv_handle_t* handle)
    {
      static_cast<TCPImpl*>(handle->data)->on_reconnect();
    }

    void on_reconnect()
    {
      assert_status(RECONNECTING, FRESH);

      if (!init())
      {
        assert_status(FRESH, CONNECTING_FAILED);
        behaviour->on_connect_failed();
        return;
      }

      if (client_addr_base != nullptr)
      {
        assert_status(FRESH, BINDING);
        client_bind();
      }
      else
      {
        assert_status(FRESH, CONNECTING_RESOLVING);
        connect_resolved();
      }
    }
  };

  class ResetTCPReadQuotaImpl
  {
  public:
    ResetTCPReadQuotaImpl() {}

    void before_io()
    {
      TCPImpl::reset_read_quota();
    }
  };

  using ResetTCPReadQuota = proxy_ptr<BeforeIO<ResetTCPReadQuotaImpl>>;
}
