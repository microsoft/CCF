// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/startup_config.h"
#include "ds/internal_logger.h"
#include "tracing/spsc_queue.h"

#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <memory>
#include <netdb.h>
#include <poll.h>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace ccf::tracing
{
  // Configure and bind before producers start; stop producers before shutdown.
  class FluentdSink
  {
    static_assert(std::atomic<uint64_t>::is_always_lock_free);

  public:
    using Endpoint = ccf::CCFConfig::Observability::Fluentd;
    static constexpr size_t MAX_PRODUCERS = 65535;
    static constexpr uint64_t DROP_REPORT_INTERVAL = 65536;

    static size_t validate(const Endpoint& endpoint, size_t producers = 1)
    {
      const auto size = endpoint.queue_capacity;
      if (
        producers == 0 || producers > MAX_PRODUCERS || size == 0 ||
        size > SPSCQueue::MAX_CAPACITY)
      {
        throw std::invalid_argument(fmt::format(
          "Trace queue capacity must be between 1 and {} slots, with "
          "between 1 and {} producers",
          SPSCQueue::MAX_CAPACITY,
          MAX_PRODUCERS));
      }
      unsigned port = 0;
      const auto* end = endpoint.port.data() + endpoint.port.size();
      auto result = std::from_chars(endpoint.port.data(), end, port);
      if (
        endpoint.host.empty() ||
        endpoint.host.find('\0') != std::string::npos ||
        result.ec != std::errc{} || result.ptr != end || port == 0 ||
        port > 65535)
      {
        throw std::invalid_argument("Invalid Fluentd host or TCP port");
      }
      return size;
    }

  private:
    struct Transport
    {
      sockaddr_storage address = {};
      socklen_t address_size = 0;
      std::vector<std::unique_ptr<SPSCQueue>> queues;
      std::atomic<uint64_t> dropped = 0;
      std::atomic<bool> stopping = false;
      std::atomic<bool> connected = false;
      std::chrono::steady_clock::time_point deadline;
      std::chrono::steady_clock::time_point retry_after;
      uint64_t reported = 0;
      int fd = -1;
      std::thread consumer;

      Transport(const Endpoint& endpoint, size_t producers)
      {
        const auto size = validate(endpoint, producers);
        addrinfo hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;
        addrinfo* addresses = nullptr;
        const auto rc = getaddrinfo(
          endpoint.host.c_str(), endpoint.port.c_str(), &hints, &addresses);
        if (rc != 0)
        {
          throw std::invalid_argument(
            fmt::format("Cannot resolve Fluentd host: {}", gai_strerror(rc)));
        }
        std::memcpy(&address, addresses->ai_addr, addresses->ai_addrlen);
        address_size = addresses->ai_addrlen;
        freeaddrinfo(addresses);
        for (size_t i = 0; i < producers; ++i)
        {
          queues.push_back(std::make_unique<SPSCQueue>(size));
        }
        consumer = std::thread([this] { run(); });
      }

      [[nodiscard]] bool expired() const
      {
        return stopping.load(std::memory_order_acquire) &&
          std::chrono::steady_clock::now() >= deadline;
      }

      void report_drops()
      {
        const auto total = dropped.load(std::memory_order_relaxed);
        const auto crossings = total / DROP_REPORT_INTERVAL;
        while (reported < crossings)
        {
          ++reported;
          LOG_FAIL_FMT(
            "Dropped {} trace events (observed {})",
            reported * DROP_REPORT_INTERVAL,
            total);
        }
      }

      void disconnect()
      {
        connected.store(false, std::memory_order_release);
        if (fd >= 0)
        {
          ::close(fd);
          fd = -1;
        }
        retry_after =
          std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
      }

      bool wait_writable()
      {
        while (!expired())
        {
          report_drops();
          pollfd descriptor{fd, POLLOUT, 0};
          const auto rc = ::poll(&descriptor, 1, 50);
          if (rc > 0)
          {
            return (descriptor.revents & POLLOUT) != 0 &&
              (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
          }
          if (rc < 0 && errno != EINTR)
          {
            return false;
          }
        }
        return false;
      }

      bool connect()
      {
        if (std::chrono::steady_clock::now() < retry_after)
        {
          return false;
        }
        fd = ::socket(
          address.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
        {
          disconnect();
          return false;
        }
        if (
          ::connect(
            fd, reinterpret_cast<const sockaddr*>(&address), address_size) == 0)
        {
          connected.store(true, std::memory_order_release);
          return true;
        }
        if (errno == EINPROGRESS && wait_writable())
        {
          int error = 0;
          socklen_t size = sizeof(error);
          if (
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 &&
            error == 0)
          {
            connected.store(true, std::memory_order_release);
            return true;
          }
        }
        disconnect();
        return false;
      }

      void write(std::span<const uint8_t> bytes)
      {
        if (expired() || (fd < 0 && !connect()))
        {
          dropped.fetch_add(1, std::memory_order_relaxed);
          return;
        }
        while (!bytes.empty() && !expired())
        {
          report_drops();
          const auto sent =
            ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
          if (sent > 0)
          {
            bytes = bytes.subspan(static_cast<size_t>(sent));
          }
          else if (sent < 0 && errno == EINTR)
          {
            continue;
          }
          else if (
            sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            wait_writable())
          {
            continue;
          }
          else
          {
            break;
          }
        }
        if (!bytes.empty())
        {
          // Never append a new frame to a partially written frame.
          disconnect();
          dropped.fetch_add(1, std::memory_order_relaxed);
        }
      }

      void run()
      {
        while (!expired())
        {
          if (fd < 0 && !stopping.load(std::memory_order_acquire))
          {
            connect();
          }
          bool progress = false;
          for (auto& queue : queues)
          {
            if (expired())
            {
              break;
            }
            progress |= queue->read(64, [this](std::span<const uint8_t> bytes) {
              write(bytes);
            }) != 0;
          }
          if (!progress && stopping.load(std::memory_order_acquire))
          {
            break;
          }
          report_drops();
          if (!progress)
          {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
        }
        size_t pending = 0;
        for (const auto& queue : queues)
        {
          pending += queue->size();
        }
        dropped.fetch_add(pending, std::memory_order_relaxed);
        report_drops();
        disconnect();
      }

      void shutdown()
      {
        if (consumer.joinable())
        {
          deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
          stopping.store(true, std::memory_order_release);
          consumer.join();
        }
      }

      ~Transport()
      {
        shutdown();
      }
    };

    static std::unique_ptr<Transport>& transport()
    {
      static std::unique_ptr<Transport> instance;
      return instance;
    }

    static SPSCQueue*& bound_queue()
    {
      thread_local SPSCQueue* queue = nullptr;
      return queue;
    }

  public:
    static void configure(
      std::optional<Endpoint> endpoint, size_t producers = 1)
    {
      if (transport())
      {
        throw std::logic_error("Trace exporter already configured");
      }
      if (endpoint)
      {
        transport() = std::make_unique<Transport>(*endpoint, producers);
      }
    }

    static bool is_configured()
    {
      return transport() != nullptr;
    }

    // Startup only: a connection observed here does not guarantee delivery.
    static bool wait_for_connection(std::chrono::milliseconds timeout)
    {
      const auto* t = transport().get();
      if (t == nullptr)
      {
        return false;
      }
      const auto deadline = std::chrono::steady_clock::now() + timeout;
      while (!t->stopping.load(std::memory_order_acquire))
      {
        if (t->connected.load(std::memory_order_acquire))
        {
          return true;
        }
        if (std::chrono::steady_clock::now() >= deadline)
        {
          return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      return false;
    }

    static void bind_producer(size_t slot)
    {
      if (transport())
      {
        bound_queue() = transport()->queues.at(slot).get();
      }
    }

    static bool enqueue(std::span<const uint8_t> bytes)
    {
      auto* t = transport().get();
      if (t == nullptr)
      {
        return false;
      }
      auto* q = bound_queue();
      if (
        q == nullptr || t->stopping.load(std::memory_order_acquire) ||
        !q->push(bytes))
      {
        t->dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
      return true;
    }

    static uint64_t dropped_count()
    {
      return transport() ? transport()->dropped.load() : 0;
    }

    // Producers must stop enqueueing before shutdown begins.
    static void shutdown()
    {
      if (transport())
      {
        transport()->shutdown();
      }
    }

    struct Lifetime
    {
      ~Lifetime()
      {
        shutdown();
      }
    };
  };
}
