// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// A minimal UDP datagram server: it owns a SOCK_DGRAM socket polled by the
// host libuv loop and delivers each received datagram to a handler. It backs
// UDP interfaces, leaving protocol behaviour to its handler.
//
// ===========================================================================
// QUIC EXTENSION POINT
// ---------------------------------------------------------------------------
// This is deliberately the substrate a future OpenSSL-native QUIC server would
// build on. The UDP socket created and bound here is exactly the datagram
// socket OpenSSL QUIC operates on. The pieces that change for QUIC are marked
// "QUIC EXTENSION POINT" inline; socket creation, binding and lifecycle remain.
//
// To become a QUIC server (needs OpenSSL >= 3.5, which adds SSL_new_listener /
// SSL_accept_connection / OSSL_QUIC_server_method):
//   * wrap `sock` with BIO_new_dgram()/SSL_set_fd() on a QUIC listener SSL;
//   * poll the descriptor returned by SSL_get_rpoll_descriptor() and use an
//     SSL_get_event_timeout() timer;
//   * on readability/timeout call SSL_handle_events(), then
//     SSL_accept_connection()/SSL_accept_stream()/SSL_read_ex(), and reply with
//     SSL_write_ex().
// ===========================================================================

#include <arpa/inet.h>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <uv.h>

namespace asynchost
{
  class DatagramServer
  {
  public:
    using OnDatagram = std::function<void(
      const uint8_t* data,
      size_t len,
      const sockaddr_storage& peer,
      socklen_t peerlen)>;

  private:
    static constexpr size_t max_datagram = 65535;

    uv_loop_t* loop = nullptr;
    int sock = -1;
    uv_poll_t socket_poll{};
    uv_async_t stop_handle{};
    uint16_t bound_port = 0;
    OnDatagram on_datagram;

    std::mutex lifecycle_mutex;
    std::condition_variable stopped_cv;
    std::thread::id loop_thread_id;
    bool started = false;
    bool stopping = false;
    bool shutdown_started = false;
    bool stopped = false;
    size_t pending_uv_closes = 0;
    std::thread::id initialising_thread_id;
    bool loop_thread_seen = false;

    static bool set_nonblocking(int fd)
    {
      const int flags = fcntl(fd, F_GETFL, 0);
      if (flags < 0)
      {
        return false;
      }
      return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    void mark_loop_thread()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      loop_thread_id = std::this_thread::get_id();
      loop_thread_seen = true;
    }

    void drain()
    {
      for (;;)
      {
        uint8_t buf[max_datagram];
        sockaddr_storage peer{};
        socklen_t peerlen = sizeof(peer);
        const ssize_t n = ::recvfrom(
          sock,
          buf,
          sizeof(buf),
          0,
          reinterpret_cast<sockaddr*>(&peer),
          &peerlen);
        if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
          {
            break;
          }
          if (errno == EINTR)
          {
            continue;
          }
          break;
        }

        if (on_datagram)
        {
          // === QUIC EXTENSION POINT ===
          // A QUIC server would feed these bytes to SSL_handle_events().
          on_datagram(buf, static_cast<size_t>(n), peer, peerlen);
        }
      }
    }

    static void on_socket_poll(uv_poll_t* handle, int status, int events)
    {
      auto* self = static_cast<DatagramServer*>(handle->data);
      self->mark_loop_thread();
      if (status < 0)
      {
        self->stop_on_loop();
        return;
      }
      if ((events & UV_READABLE) != 0)
      {
        // === QUIC EXTENSION POINT ===
        // For QUIC this becomes SSL_handle_events() on the listener.
        self->drain();
      }
    }

    static void on_stop(uv_async_t* handle)
    {
      auto* self = static_cast<DatagramServer*>(handle->data);
      self->mark_loop_thread();
      self->stop_on_loop();
    }

    static void on_handle_closed(uv_handle_t* handle)
    {
      auto* self = static_cast<DatagramServer*>(handle->data);
      std::lock_guard<std::mutex> guard(self->lifecycle_mutex);
      --self->pending_uv_closes;
      if (self->pending_uv_closes == 0)
      {
        self->stopped = true;
        self->stopped_cv.notify_all();
      }
    }

    void stop_on_loop()
    {
      {
        std::lock_guard<std::mutex> guard(lifecycle_mutex);
        if (shutdown_started)
        {
          return;
        }
        stopping = true;
        shutdown_started = true;
        pending_uv_closes = 2;
      }

      (void)uv_poll_stop(&socket_poll);
      if (sock >= 0)
      {
        ::close(sock);
        sock = -1;
      }
      uv_close(reinterpret_cast<uv_handle_t*>(&socket_poll), on_handle_closed);
      uv_close(reinterpret_cast<uv_handle_t*>(&stop_handle), on_handle_closed);
    }

  public:
    DatagramServer(
      const std::string& host,
      uint16_t port,
      OnDatagram on_datagram_,
      uv_loop_t* loop_ = uv_default_loop()) :
      loop(loop_),
      on_datagram(std::move(on_datagram_))
    {
      addrinfo hints{};
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_flags = AI_PASSIVE;
      addrinfo* res = nullptr;
      const std::string port_str = std::to_string(port);
      if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0)
      {
        throw std::runtime_error("getaddrinfo (udp) failed for " + host);
      }

      const int one = 1;
      bool bound = false;
      for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next)
      {
        sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
        {
          continue;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
        {
          ::close(sock);
          sock = -1;
          continue;
        }
        if (::bind(sock, ai->ai_addr, ai->ai_addrlen) == 0)
        {
          bound = true;
          break;
        }
        ::close(sock);
        sock = -1;
      }
      freeaddrinfo(res);
      if (!bound)
      {
        cleanup();
        throw std::runtime_error("bind (udp) failed for " + host);
      }
      if (!set_nonblocking(sock))
      {
        cleanup();
        throw std::runtime_error("set_nonblocking (udp) failed");
      }

      sockaddr_storage bound_address{};
      socklen_t bound_address_len = sizeof(bound_address);
      if (
        getsockname(
          sock,
          reinterpret_cast<sockaddr*>(&bound_address),
          &bound_address_len) == 0)
      {
        bound_port = (bound_address.ss_family == AF_INET6) ?
          ntohs(reinterpret_cast<sockaddr_in6*>(&bound_address)->sin6_port) :
          ntohs(reinterpret_cast<sockaddr_in*>(&bound_address)->sin_port);
      }
    }

    DatagramServer(const DatagramServer&) = delete;
    DatagramServer& operator=(const DatagramServer&) = delete;
    DatagramServer(DatagramServer&&) = delete;
    DatagramServer& operator=(DatagramServer&&) = delete;

    ~DatagramServer()
    {
      stop();
      cleanup();
    }

    void start()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (started)
      {
        return;
      }
      int rc = uv_poll_init_socket(loop, &socket_poll, sock);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_poll_init_socket(udp) failed: ") + uv_strerror(rc));
      }
      socket_poll.data = this;
      rc = uv_async_init(loop, &stop_handle, on_stop);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_async_init(udp) failed: ") + uv_strerror(rc));
      }
      stop_handle.data = this;
      rc = uv_poll_start(&socket_poll, UV_READABLE, on_socket_poll);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_poll_start(udp) failed: ") + uv_strerror(rc));
      }
      started = true;
      stopping = false;
      shutdown_started = false;
      stopped = false;
      initialising_thread_id = std::this_thread::get_id();
      loop_thread_seen = false;
    }

    void stop()
    {
      std::unique_lock<std::mutex> lock(lifecycle_mutex);
      if (!started || stopped)
      {
        return;
      }
      if (!stopping)
      {
        stopping = true;
        (void)uv_async_send(&stop_handle);
      }
      const bool loop_not_started_here = !loop_thread_seen &&
        std::this_thread::get_id() == initialising_thread_id;
      if (loop_not_started_here)
      {
        lock.unlock();
        stop_on_loop();
        for (;;)
        {
          {
            std::lock_guard<std::mutex> guard(lifecycle_mutex);
            if (stopped)
            {
              return;
            }
          }
          (void)uv_run(loop, UV_RUN_NOWAIT);
        }
      }
      if (std::this_thread::get_id() == loop_thread_id)
      {
        lock.unlock();
        stop_on_loop();
        return;
      }
      stopped_cv.wait(lock, [this]() { return stopped; });
    }

    [[nodiscard]] uint16_t port() const
    {
      return bound_port;
    }

    [[nodiscard]] bool send_to(
      const sockaddr_storage& peer,
      socklen_t peerlen,
      const uint8_t* data,
      size_t len) const
    {
      const auto rc = ::sendto(
        sock, data, len, 0, reinterpret_cast<const sockaddr*>(&peer), peerlen);
      return rc >= 0;
    }

  private:
    void cleanup()
    {
      if (sock >= 0)
      {
        ::close(sock);
        sock = -1;
      }
    }
  };
}