// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// A minimal UDP datagram server: it owns a SOCK_DGRAM socket in its own epoll
// loop and delivers each received datagram to a handler. It backs UDP
// interfaces, leaving protocol behaviour to its handler.
//
// ===========================================================================
// QUIC EXTENSION POINT
// ---------------------------------------------------------------------------
// This is deliberately the substrate a future OpenSSL-native QUIC server would
// build on. The UDP socket created and bound here is exactly the datagram
// socket OpenSSL QUIC operates on. The pieces that change for QUIC are marked
// "QUIC EXTENSION POINT" inline; the socket creation, binding, epoll loop and
// lifecycle below are unchanged by that switch.
//
// To become a QUIC server (needs OpenSSL >= 3.5, which adds SSL_new_listener /
// SSL_accept_connection / OSSL_QUIC_server_method - absent in the 3.3.x we
// build against today):
//   * wrap `sock` with BIO_new_dgram()/SSL_set_fd() on a QUIC listener SSL
//     (OSSL_QUIC_server_method + SSL_new_listener);
//   * epoll the descriptor returned by SSL_get_rpoll_descriptor() (it is this
//     same UDP fd) plus an SSL_get_event_timeout() timer, instead of `sock`
//     directly;
//   * on readability/timeout call SSL_handle_events(), then
//     SSL_accept_connection()/SSL_accept_stream()/SSL_read_ex(), and reply with
//     SSL_write_ex() on a stream rather than the raw sendto() below.
// The event-driven integration primitives (SSL_handle_events,
// SSL_get_rpoll_descriptor, SSL_get_event_timeout, BIO_new_dgram,
// SSL_set1_initial_peer_addr) already exist in 3.3.x - only the server-side
// listener/accept is missing.
// ===========================================================================

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace asynchost
{
  class DatagramServer
  {
  public:
    // Invoked on the loop thread for each received datagram.
    using OnDatagram = std::function<void(
      const uint8_t* data,
      size_t len,
      const sockaddr_storage& peer,
      socklen_t peerlen)>;

  private:
    // Max UDP payload (theoretical IPv4 limit); datagrams are read whole.
    static constexpr size_t max_datagram = 65535;

    int sock = -1;
    int epoll_fd = -1;
    int stop_fd = -1;
    uint16_t bound_port = 0;
    OnDatagram on_datagram;

    std::thread loop_thread;
    std::atomic<bool> running{false};

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
          // A QUIC server would feed the received bytes to OpenSSL
          // (SSL_handle_events). `peer` is the source address that
          // SSL_set1_initial_peer_addr() consumes.
          on_datagram(buf, static_cast<size_t>(n), peer, peerlen);
        }
      }
    }

    void run()
    {
      constexpr int max_events = 8;
      std::vector<epoll_event> events(max_events);
      while (running.load())
      {
        const int n = epoll_wait(epoll_fd, events.data(), max_events, -1);
        if (n < 0)
        {
          if (errno == EINTR)
          {
            continue;
          }
          break;
        }
        for (int i = 0; i < n; ++i)
        {
          const int fd = events[i].data.fd;
          if (fd == stop_fd)
          {
            running.store(false);
            break;
          }
          if (fd == sock)
          {
            // === QUIC EXTENSION POINT ===
            // For QUIC this becomes SSL_handle_events() on the listener.
            drain();
          }
        }
      }
    }

  public:
    DatagramServer(
      const std::string& host, uint16_t port, OnDatagram on_datagram_) :
      on_datagram(std::move(on_datagram_))
    {
      // Resolve + bind the datagram address (getaddrinfo supports hostnames and
      // IPv6, matching the TCP listener).
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
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
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

      // Read back the actual bound port (supports ephemeral port 0, v4 and v6).
      sockaddr_storage b{};
      socklen_t blen = sizeof(b);
      if (getsockname(sock, reinterpret_cast<sockaddr*>(&b), &blen) == 0)
      {
        bound_port = (b.ss_family == AF_INET6) ?
          ntohs(reinterpret_cast<sockaddr_in6*>(&b)->sin6_port) :
          ntohs(reinterpret_cast<sockaddr_in*>(&b)->sin_port);
      }

      epoll_fd = epoll_create1(0);
      if (epoll_fd < 0)
      {
        cleanup();
        throw std::runtime_error("epoll_create1 (udp) failed");
      }
      stop_fd = eventfd(0, EFD_NONBLOCK);
      if (stop_fd < 0)
      {
        cleanup();
        throw std::runtime_error("eventfd (udp) failed");
      }

      epoll_event ev{};
      ev.events = EPOLLIN;
      ev.data.fd = sock;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
      ev.data.fd = stop_fd;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stop_fd, &ev);
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
      running.store(true);
      loop_thread = std::thread([this]() { run(); });
    }

    void stop()
    {
      if (!running.exchange(false))
      {
        if (loop_thread.joinable())
        {
          loop_thread.join();
        }
        return;
      }
      if (stop_fd >= 0)
      {
        const uint64_t one = 1;
        [[maybe_unused]] auto w = ::write(stop_fd, &one, sizeof(one));
      }
      if (loop_thread.joinable())
      {
        loop_thread.join();
      }
    }

    uint16_t port() const
    {
      return bound_port;
    }

    void send_to(
      const sockaddr_storage& peer,
      socklen_t peerlen,
      const uint8_t* data,
      size_t len)
    {
      ::sendto(
        sock, data, len, 0, reinterpret_cast<const sockaddr*>(&peer), peerlen);
    }

  private:
    void cleanup()
    {
      if (stop_fd >= 0)
      {
        ::close(stop_fd);
        stop_fd = -1;
      }
      if (epoll_fd >= 0)
      {
        ::close(epoll_fd);
        epoll_fd = -1;
      }
      if (sock >= 0)
      {
        ::close(sock);
        sock = -1;
      }
    }
  };
}
