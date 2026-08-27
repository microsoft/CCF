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

    // Whether anything is running the libuv loop when stop() is called. See
    // stop() for why this has to be stated rather than inferred.
    enum class LoopState : uint8_t
    {
      Running,
      NotRunning,
    };

  private:
    static constexpr size_t max_datagram = 65535;
    // Datagrams handled per readable event. The handler runs inline on the
    // loop thread, so an unbounded drain would let a UDP flood starve every
    // other handle on the loop. The socket stays level-triggered, so any
    // remainder is picked up on the next iteration. This replaces the read
    // quota the previous ringbuffer-based UDP transport applied.
    static constexpr size_t max_datagrams_per_event = 64;

    uv_loop_t* loop = nullptr;
    int sock = -1;
    // Heap-allocated and freed by their own close callbacks, so that this
    // server can be destroyed without waiting for the loop to run them. See
    // the equivalent note in host/tls/openssl_server.h.
    uv_poll_t* socket_poll = nullptr;
    uv_async_t* stop_handle = nullptr;
    uint16_t bound_port = 0;
    OnDatagram on_datagram;

    std::mutex lifecycle_mutex;
    std::condition_variable teardown_cv;
    bool started = false;
    bool stopping = false;
    bool torn_down = false;

    template <typename THandle>
    static void close_handle(THandle*& handle)
    {
      if (handle == nullptr)
      {
        return;
      }
      auto* as_handle = reinterpret_cast<uv_handle_t*>(handle);
      handle = nullptr;
      if (uv_is_closing(as_handle) != 0)
      {
        return;
      }
      uv_close(as_handle, [](uv_handle_t* h) {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        delete reinterpret_cast<THandle*>(h);
      });
    }

    static bool set_nonblocking(int fd)
    {
      const int flags = fcntl(fd, F_GETFL, 0);
      if (flags < 0)
      {
        return false;
      }
      return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    void drain()
    {
      size_t handled = 0;
      while (handled < max_datagrams_per_event)
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
            // Interrupted before receiving anything, so this does not count
            // against the quota.
            continue;
          }
          break;
        }

        ++handled;
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
      if (status < 0)
      {
        self->tear_down_on_loop();
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
      self->tear_down_on_loop();
    }

    // Close the socket and hand every handle to uv_close(). Must only run
    // where it cannot race the loop - see stop(). Does not wait for the
    // closes: the handles own themselves.
    void tear_down_on_loop()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (torn_down)
      {
        return;
      }
      stopping = true;

      if (socket_poll != nullptr)
      {
        (void)uv_poll_stop(socket_poll);
      }
      // Closed under the lock so that a concurrent send_to() cannot be left
      // holding a descriptor which has been closed (and possibly reused)
      // underneath it.
      if (sock >= 0)
      {
        ::close(sock);
        sock = -1;
      }

      close_handle(socket_poll);
      close_handle(stop_handle);

      torn_down = true;
      teardown_cv.notify_all();
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

      // Marked started before any handle is created, so that a failure part
      // way through still leaves a server whose destructor closes the handles
      // which were created (stop() is a no-op unless `started` is set).
      started = true;
      stopping = false;
      torn_down = false;

      socket_poll = new uv_poll_t{}; // NOLINT(cppcoreguidelines-owning-memory)
      socket_poll->data = this;
      int rc = uv_poll_init_socket(loop, socket_poll, sock);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_poll_init_socket(udp) failed: ") + uv_strerror(rc));
      }

      stop_handle = new uv_async_t{}; // NOLINT(cppcoreguidelines-owning-memory)
      stop_handle->data = this;
      rc = uv_async_init(loop, stop_handle, on_stop);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_async_init(udp) failed: ") + uv_strerror(rc));
      }

      rc = uv_poll_start(socket_poll, UV_READABLE, on_socket_poll);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_poll_start(udp) failed: ") + uv_strerror(rc));
      }
    }

    // Tear the server down. Idempotent, and safe to call from the destructor.
    // See OpenSSLServer::stop() for why `loop_state` is stated rather than
    // inferred.
    void stop(LoopState loop_state = LoopState::NotRunning)
    {
      std::unique_lock<std::mutex> lock(lifecycle_mutex);
      if (!started || torn_down)
      {
        return;
      }

      if (loop_state == LoopState::NotRunning)
      {
        lock.unlock();
        tear_down_on_loop();
        return;
      }

      if (!stopping)
      {
        stopping = true;
        if (stop_handle != nullptr)
        {
          (void)uv_async_send(stop_handle);
        }
      }
      teardown_cv.wait(lock, [this]() { return torn_down; });
    }

    [[nodiscard]] uint16_t port() const
    {
      return bound_port;
    }

    // Thread-safe: replies are sent from session workers, while the socket may
    // be closed concurrently by shutdown on the loop thread.
    [[nodiscard]] bool send_to(
      const sockaddr_storage& peer,
      socklen_t peerlen,
      const uint8_t* data,
      size_t len)
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (sock < 0)
      {
        return false;
      }
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