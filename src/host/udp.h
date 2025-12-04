// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "before_io.h"
#include "ccf/pal/locking.h"
#include "dns.h"
#include "ds/internal_logger.h"
#include "ds/pending_io.h"
#include "proxy.h"
#include "socket.h"

#include <optional>

namespace asynchost
{
  // NOLINTBEGIN(cppcoreguidelines-virtual-class-destructor)
  class UDPImpl;
  using UDP = proxy_ptr<UDPImpl>;

  /// For now this is server only, as we have no immediate plans to
  /// create node-to-node UDP channels or use UDP for REST between nodes
  class UDPImpl : public with_uv_handle<uv_udp_t>
  {
  private:
    friend class close_ptr<UDPImpl>;

    static constexpr int backlog = 128;
    static constexpr size_t max_read_size = 16384;

    // Each uv iteration, read only a capped amount from all sockets.
    static constexpr auto max_read_quota = max_read_size * 4;
    static size_t remaining_read_quota;

    // This is a simplified version of the state machine for QUIC that
    // mostly follows plain UDP state. We should add more when we need
    // for QUIC, not predict complexity prematurely.
    enum Status : uint8_t
    {
      // Starting state + failure recovery (if any)
      FRESH,
      // DNS::resolve
      RESOLVING,
      RESOLVING_FAILED,
      // uv_udp_recv_start <-> on_read
      READING,
      READING_FAILED,
      // uv_udp_send has no state (it's synchronous)
      WRITING_FAILED,
      // There is no connected/reconnect/disconnect
    };

    /// Current status
    Status status{FRESH};
    /// Callback behaviour from user
    std::unique_ptr<SocketBehaviour<UDP>> behaviour;

    using PendingWrites = std::vector<PendingIO<uv_udp_send_t>>;
    /// Writes sent before writing socket is read
    PendingWrites pending_writes;

    /// Host to bind the server
    std::string host;
    /// Port to bind the server
    std::string port;
    /// Listening name
    std::optional<std::string> listen_name = std::nullopt;

    /// Base address (head of linked list)
    addrinfo* addr_base = nullptr;
    /// Current address (node in the list that resolved first)
    addrinfo* addr_current = nullptr;

    [[nodiscard]] bool port_assigned() const
    {
      return port != "0";
    }

    [[nodiscard]] std::string get_address_name() const
    {
      const std::string port_suffix =
        port_assigned() ? fmt::format(":{}", port) : "";

      if (addr_current != nullptr && addr_current->ai_family == AF_INET6)
      {
        return fmt::format("[{}]{}", host, port_suffix);
      }

      return fmt::format("{}{}", host, port_suffix);
    }

    UDPImpl()
    {
      if (!init())
      {
        throw std::logic_error("uv UDP initialization failed");
      }

      uv_handle.data = this;
    }

    ~UDPImpl() override
    {
      {
        std::unique_lock<ccf::pal::Mutex> guard(pending_resolve_requests_mtx);
        for (const auto& req : pending_resolve_requests)
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
    }

  public:
    static void reset_read_quota()
    {
      remaining_read_quota = max_read_quota;
    }

    void set_behaviour(std::unique_ptr<SocketBehaviour<UDP>> b)
    {
      behaviour = std::move(b);
    }

    [[nodiscard]] std::string get_host() const
    {
      return host;
    }

    [[nodiscard]] std::string get_port() const
    {
      return port;
    }

    [[nodiscard]] std::optional<std::string> get_listen_name() const
    {
      return listen_name;
    }

    /// Listen to packets on host:port
    bool listen(
      const std::string& host_,
      const std::string& port_,
      const std::optional<std::string>& name = std::nullopt)
    {
      listen_name = name;
      auto name_str = name.has_value() ? name.value() : "";
      LOG_TRACE_FMT("UDP listen on {}:{} [{}]", host_, port_, name_str);
      return resolve(host_, port_, false);
    }

    /// Start the service via behaviour (register on ringbuffer, etc)
    void start(int64_t id)
    {
      behaviour->on_start(id);
    }

    bool connect(const std::string& /*host_*/, const std::string& /*port_*/)
    {
      LOG_TRACE_FMT("UDP dummy connect to {}:{}", host, port);
      return true;
    }

    bool write(size_t len, const uint8_t* data, sockaddr addr)
    {
      auto* req = new uv_udp_send_t; // NOLINT(cppcoreguidelines-owning-memory)
      auto* copy = new char[len]; // NOLINT(cppcoreguidelines-owning-memory)
      if (data != nullptr)
      {
        memcpy(copy, data, len);
      }
      req->data = copy;

      switch (status)
      {
        // Handles unbound or in unknown state
        case RESOLVING:
        case RESOLVING_FAILED:
        case READING_FAILED:
        case WRITING_FAILED:
        {
          pending_writes.emplace_back(req, len, addr, free_write);
          break;
        }

        // Both read and write handles have been bound here
        case READING:
        {
          auto [h, p] = addr_to_str(&addr);
          LOG_TRACE_FMT("UDP write addr: {}:{}", h, p);
          return send_write(req, len, &addr);
        }

        // This shouldn't happen, but the only state is FRESH
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
    /// Initializes both handles (recv/send)
    bool init()
    {
      assert_status(FRESH, FRESH);

      int rc = 0;
      LOG_TRACE_FMT("UDP init");
      if ((rc = uv_udp_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL_FMT("uv_udp_init failed on recv handle: {}", uv_strerror(rc));
        return false;
      }

      return true;
    }

    bool send_write(uv_udp_send_t* req, size_t len, const struct sockaddr* addr)
    {
      auto* copy = static_cast<char*>(req->data);

      uv_buf_t buf;
      buf.base = copy;
      buf.len = len;

      int rc = 0;

      auto [h, p] = addr_to_str(addr);
      LOG_TRACE_FMT("UDP send_write addr: {}:{}", h, p);
      std::string data(copy, len);
      LOG_TRACE_FMT("UDP send_write [{}]", data);
      if ((rc = uv_udp_send(req, &uv_handle, &buf, 1, addr, on_write)) < 0)
      {
        free_write(req);
        LOG_FAIL_FMT("uv_write failed: {}", uv_strerror(rc));
        status = WRITING_FAILED;
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
      LOG_TRACE_FMT("UDP update address to {}:{}", host, port);
    }

    void resolved()
    {
      int rc = 0;

      LOG_TRACE_FMT("UDP bind to {}:{}", host, port);
      while (addr_current != nullptr)
      {
        update_resolved_address(addr_current->ai_family, addr_current->ai_addr);

        if ((rc = uv_udp_bind(&uv_handle, addr_current->ai_addr, 0)) < 0)
        {
          addr_current = addr_current->ai_next;
          LOG_FAIL_FMT(
            "uv_udp_bind failed on {}: {}",
            get_address_name(),
            uv_strerror(rc));
          continue;
        }

        // If bound on port 0 (ie - asking the OS to assign a port), then we
        // need to call uv_udp_getsockname to retrieve the bound port
        // (addr_current will not contain it)
        if (!port_assigned())
        {
          sockaddr_storage sa_storage{};
          auto* const sa = reinterpret_cast<sockaddr*>(&sa_storage);
          int sa_len = sizeof(sa_storage);
          if ((rc = uv_udp_getsockname(&uv_handle, sa, &sa_len)) != 0)
          {
            LOG_FAIL_FMT("uv_udp_getsockname failed: {}", uv_strerror(rc));
          }
          update_resolved_address(addr_current->ai_family, sa);
        }

        LOG_TRACE_FMT("UDP to call on_listening");

        behaviour->on_listening(host, port);

        assert_status(RESOLVING, READING);
        read_start();
        return;
      }

      status = RESOLVING_FAILED;

      // This should show even when verbose logs are off
      LOG_INFO_FMT(
        "Unable to connect: all resolved addresses failed: {}:{}", host, port);
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
      const std::string& host_, const std::string& port_, bool async = true)
    {
      host = host_;
      port = port_;

      LOG_TRACE_FMT("UDP resolve {}:{}", host, port);
      if (addr_base != nullptr)
      {
        uv_freeaddrinfo(addr_base);
        addr_base = nullptr;
        addr_current = nullptr;
      }

      assert_status(FRESH, RESOLVING);

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

      LOG_TRACE_FMT("UDP on_resolve static");
      if (req->data != nullptr)
      {
        static_cast<UDPImpl*>(req->data)->on_resolved(req, rc);
      }
      else
      {
        // The UDPImpl that submitted the request has been destroyed, but we
        // need to clean up the request object.
        uv_freeaddrinfo(res);
        delete req; // NOLINT(cppcoreguidelines-owning-memory)
      }
    }

    void on_resolved(uv_getaddrinfo_t* req, int rc)
    {
      LOG_TRACE_FMT("UDP on_resolve dynamic");
      // It is possible that on_resolved is triggered after there has been a
      // request to close uv_handle. In this scenario, we should not try to
      // do anything with the handle and return immediately (otherwise,
      // uv_close cb will abort).
      if (uv_is_closing(reinterpret_cast<uv_handle_t*>(&uv_handle)) != 0)
      {
        LOG_DEBUG_FMT("on_resolved: closing");
        uv_freeaddrinfo(req->addrinfo);
        delete req; // NOLINT(cppcoreguidelines-owning-memory)
        return;
      }

      if (rc < 0)
      {
        status = RESOLVING_FAILED;
        LOG_DEBUG_FMT("UDP resolve failed: {}", uv_strerror(rc));
        behaviour->on_resolve_failed();
      }
      else
      {
        addr_base = req->addrinfo;
        addr_current = addr_base;

        LOG_TRACE_FMT("UDP to call resolved");
        resolved();
      }

      delete req; // NOLINT(cppcoreguidelines-owning-memory)
    }

    void push_pending_writes()
    {
      for (auto& w : pending_writes)
      {
        auto [h, p] = addr_to_str(&w.addr);
        LOG_TRACE_FMT("UDP pending_writes addr: {}:{}", h, p);
        send_write(w.req, w.len, &w.addr);
        w.req = nullptr;
      }

      PendingWrites().swap(pending_writes);
    }

    void read_start()
    {
      int rc = 0;

      LOG_TRACE_FMT("UDP read start");
      if ((rc = uv_udp_recv_start(&uv_handle, on_alloc, on_read)) < 0)
      {
        status = READING_FAILED;
        LOG_FAIL_FMT("uv_udp_read_start failed: {}", uv_strerror(rc));
        behaviour->on_disconnect();
      }
    }

    static void on_alloc(
      uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
    {
      static_cast<UDPImpl*>(handle->data)->on_alloc(suggested_size, buf);
    }

    void on_alloc(size_t suggested_size, uv_buf_t* buf)
    {
      auto alloc_size = std::min(suggested_size, max_read_size);

      alloc_size = std::min(alloc_size, remaining_read_quota);
      remaining_read_quota -= alloc_size;
      LOG_TRACE_FMT(
        "Allocating {} bytes for UDP read ({} of quota remaining)",
        alloc_size,
        remaining_read_quota);

      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      buf->base = new char[alloc_size];
      buf->len = alloc_size;
    }

    void on_free(const uv_buf_t* buf)
    {
      delete[] buf->base; // NOLINT(cppcoreguidelines-owning-memory)
    }

    static void on_read(
      uv_udp_t* handle,
      ssize_t sz,
      const uv_buf_t* buf,
      const struct sockaddr* addr,
      unsigned flags)
    {
      static_cast<UDPImpl*>(handle->data)->on_read(sz, buf, addr, flags);
    }

    void on_read(
      ssize_t sz,
      const uv_buf_t* buf,
      const struct sockaddr* addr,
      unsigned /*flags*/)
    {
      if (sz == 0)
      {
        on_free(buf);
        return;
      }

      if (sz == UV_ENOBUFS)
      {
        LOG_DEBUG_FMT("UDP on_read reached allocation quota");
        on_free(buf);
        return;
      }

      if (sz < 0)
      {
        on_free(buf);
        LOG_DEBUG_FMT("UDP on_read: {}", uv_strerror(static_cast<int>(sz)));
        behaviour->on_disconnect();
        return;
      }

      auto [h, p] = addr_to_str(addr);
      LOG_TRACE_FMT("UDP on_read addr: {}:{}", h, p);

      auto* b = reinterpret_cast<uint8_t*>(buf->base);
      std::string data(reinterpret_cast<char*>(b), sz);
      LOG_TRACE_FMT("UDP on_read [{}]", data);
      behaviour->on_read(static_cast<size_t>(sz), b, *addr);

      if (b != nullptr)
      {
        on_free(buf);
      }
    }

    static void on_write(uv_udp_send_t* req, int /*status*/)
    {
      free_write(req);
    }

    static void free_write(uv_udp_send_t* req)
    {
      if (req == nullptr)
      {
        return;
      }

      auto* copy = static_cast<char*>(req->data);
      delete[] copy; // NOLINT(cppcoreguidelines-owning-memory)
      delete req; // NOLINT(cppcoreguidelines-owning-memory)
    }
  };

  // NOLINTEND(cppcoreguidelines-virtual-class-destructor)

  class ResetUDPReadQuotaImpl
  {
  public:
    ResetUDPReadQuotaImpl() = default;

    void before_io()
    {
      UDPImpl::reset_read_quota();
    }
  };

  using ResetUDPReadQuota = proxy_ptr<BeforeIO<ResetUDPReadQuotaImpl>>;
}
