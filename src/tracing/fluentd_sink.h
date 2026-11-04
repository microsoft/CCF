// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/fluentd_config.h"
#include "ds/internal_logger.h"
#include "tracing/spsc_queue.h"

#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
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
    using Endpoint = ccf::FluentdConfig;
    static constexpr uint64_t DROP_REPORT_INTERVAL = 65536;

    static size_t validate(const Endpoint& endpoint, size_t producers = 1)
    {
      const auto size = endpoint.queue_capacity;
      if (producers == 0 || size == 0)
      {
        throw std::invalid_argument(
          "Trace queue capacity and producer count must be greater than zero");
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
      Endpoint::Delivery delivery;
      std::vector<std::unique_ptr<SPSCQueue>> queues;
      std::atomic<uint64_t> dropped = 0;
      std::mutex mutex;
      // Producers observe shutdown without taking the transport mutex.
      std::atomic<bool> stopping = false;
      bool connected = false;
      std::chrono::steady_clock::time_point deadline;
      std::chrono::steady_clock::time_point retry_after;
      uint64_t reported = 0;
      int fd = -1;
      std::unique_ptr<std::vector<uint8_t>> pending;
      size_t write_offset = 0;
      std::thread consumer;

      Transport(const Endpoint& endpoint, size_t producers) :
        delivery(endpoint.delivery)
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
        return stopping.load(std::memory_order_relaxed) &&
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
        connected = false;
        if (pending)
        {
          pending.reset();
          write_offset = 0;
          dropped.fetch_add(1, std::memory_order_relaxed);
        }
        if (fd >= 0)
        {
          // Do not retry close, even on EINTR: the descriptor may be reused.
          if (::close(fd) != 0)
          {
            const auto err = errno;
            LOG_FAIL_FMT(
              "Failed to close Fluentd socket {}: {}",
              fd,
              ccf::nonstd::strerror(err));
          }
          fd = -1;
        }
        retry_after =
          std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
      }

      void connect()
      {
        if (connected)
        {
          return;
        }
        if (fd < 0)
        {
          if (std::chrono::steady_clock::now() < retry_after)
          {
            return;
          }
          fd = ::socket(
            address.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
          if (fd < 0)
          {
            disconnect();
            return;
          }
          if (
            ::connect(
              fd, reinterpret_cast<const sockaddr*>(&address), address_size) ==
            0)
          {
            connected = true;
            return;
          }
          if (errno != EINPROGRESS)
          {
            disconnect();
            return;
          }
        }
        pollfd descriptor{fd, POLLOUT, 0};
        const auto rc = ::poll(&descriptor, 1, 0);
        if (rc == 0 || (rc < 0 && errno == EINTR))
        {
          return;
        }
        if (
          rc > 0 && (descriptor.revents & POLLOUT) != 0 &&
          (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0)
        {
          int error = 0;
          socklen_t size = sizeof(error);
          if (
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 &&
            error == 0)
          {
            connected = true;
            return;
          }
        }
        disconnect();
      }

      void write()
      {
        while (write_offset < pending->size() && !expired())
        {
          const auto sent = ::send(
            fd,
            pending->data() + write_offset,
            pending->size() - write_offset,
            MSG_NOSIGNAL | MSG_DONTWAIT);
          if (sent > 0)
          {
            write_offset += static_cast<size_t>(sent);
            continue;
          }
          if (sent < 0 && errno == EINTR)
          {
            continue;
          }
          if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
          {
            if (
              delivery == Endpoint::Delivery::UNBUFFERED_NON_BLOCKING &&
              write_offset == 0)
            {
              pending.reset();
              dropped.fetch_add(1, std::memory_order_relaxed);
            }
            return;
          }
          disconnect();
          return;
        }
        if (write_offset == pending->size())
        {
          pending.reset();
          write_offset = 0;
        }
      }

      void run()
      {
        size_t next_queue = 0;
        std::unique_lock lock(mutex);
        while (!expired())
        {
          connect();
          bool progress = false;
          if (connected && pending)
          {
            write();
          }
          for (size_t q = 0; q < queues.size() && !expired(); ++q)
          {
            if (
              delivery == Endpoint::Delivery::BUFFERED_BEST_EFFORT &&
              (!connected || pending))
            {
              break;
            }
            auto& queue = queues[next_queue];
            next_queue = (next_queue + 1) % queues.size();
            for (size_t i = 0; i < 64 && !expired(); ++i)
            {
              if (
                delivery == Endpoint::Delivery::BUFFERED_BEST_EFFORT &&
                (!connected || pending))
              {
                break;
              }
              auto record = queue->pop();
              if (!record)
              {
                break;
              }
              progress = true;
              if (!connected || pending)
              {
                dropped.fetch_add(1, std::memory_order_relaxed);
                continue;
              }
              pending = std::move(record);
              write();
            }
          }
          if (!progress && stopping.load(std::memory_order_relaxed))
          {
            bool empty = !pending;
            for (const auto& queue : queues)
            {
              empty &= queue->size() == 0;
            }
            if (empty)
            {
              break;
            }
          }
          lock.unlock();
          report_drops();
          if (!progress)
          {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
          lock.lock();
        }
        size_t remaining = 0;
        for (const auto& queue : queues)
        {
          remaining += queue->size();
        }
        dropped.fetch_add(remaining, std::memory_order_relaxed);
        disconnect();
        lock.unlock();
        report_drops();
      }

      void stop(std::chrono::steady_clock::time_point shutdown_deadline)
      {
        std::lock_guard lock(mutex);
        if (!stopping.load(std::memory_order_relaxed))
        {
          deadline = shutdown_deadline;
          stopping.store(true, std::memory_order_relaxed);
        }
      }

      void shutdown()
      {
        if (consumer.joinable())
        {
          stop(std::chrono::steady_clock::now() + std::chrono::seconds(2));
          consumer.join();
          LOG_INFO_FMT(
            "Fluentd exporter shutdown: {} dropped events", dropped.load());
        }
      }

      ~Transport()
      {
        shutdown();
      }
    };

    static std::vector<std::unique_ptr<Transport>>& transports()
    {
      static std::vector<std::unique_ptr<Transport>> instances;
      return instances;
    }

    static size_t& bound_slot()
    {
      thread_local size_t slot = std::numeric_limits<size_t>::max();
      return slot;
    }

  public:
    static void configure(
      const std::vector<Endpoint>& endpoints, size_t producers = 1)
    {
      if (is_configured())
      {
        throw std::logic_error("Trace exporter already configured");
      }
      std::vector<std::unique_ptr<Transport>> instances;
      instances.reserve(endpoints.size());
      for (const auto& endpoint : endpoints)
      {
        instances.push_back(std::make_unique<Transport>(endpoint, producers));
      }
      transports() = std::move(instances);
    }

    static void configure(
      std::optional<Endpoint> endpoint, size_t producers = 1)
    {
      configure(
        endpoint ? std::vector{*endpoint} : std::vector<Endpoint>{}, producers);
    }

    static bool is_configured()
    {
      return !transports().empty();
    }

    // Startup only: a connection observed here does not guarantee delivery.
    static bool wait_for_connection(std::chrono::milliseconds timeout)
    {
      if (!is_configured())
      {
        return false;
      }
      const auto deadline = std::chrono::steady_clock::now() + timeout;
      while (true)
      {
        bool connected = true;
        for (const auto& t : transports())
        {
          std::lock_guard lock(t->mutex);
          if (t->stopping.load(std::memory_order_relaxed))
          {
            return false;
          }
          connected &= t->connected;
        }
        if (connected)
        {
          return true;
        }
        if (std::chrono::steady_clock::now() >= deadline)
        {
          return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }

    static void bind_producer(size_t slot)
    {
      if (is_configured())
      {
        std::ignore = transports().front()->queues.at(slot);
        bound_slot() = slot;
      }
    }

    // False may mean partial acceptance: other sinks still receive the record.
    static bool enqueue(std::span<const uint8_t> bytes)
    {
      bool enqueued = is_configured();
      const auto slot = bound_slot();
      for (const auto& t : transports())
      {
        if (
          slot >= t->queues.size() ||
          t->stopping.load(std::memory_order_relaxed) ||
          !t->queues[slot]->push(bytes))
        {
          t->dropped.fetch_add(1, std::memory_order_relaxed);
          enqueued = false;
        }
      }
      return enqueued;
    }

    static void record_drop()
    {
      for (const auto& t : transports())
      {
        t->dropped.fetch_add(1, std::memory_order_relaxed);
      }
    }

    static uint64_t dropped_count()
    {
      uint64_t total = 0;
      for (const auto& t : transports())
      {
        total += t->dropped.load();
      }
      return total;
    }

    // Producers must stop enqueueing before shutdown begins.
    static void shutdown()
    {
      const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
      for (const auto& t : transports())
      {
        t->stop(deadline);
      }
      for (const auto& t : transports())
      {
        t->shutdown();
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
