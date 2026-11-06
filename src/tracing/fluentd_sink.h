// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/locking.h"
#include "ccf/ds/nonstd.h"
#include "ccf/fluentd_config.h"
#include "ds/internal_logger.h"
#include "tracing/spsc_queue.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <netdb.h>
#include <poll.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
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
      static constexpr size_t TURN_BUDGET = 256;

      class QueueReader
      {
        static constexpr size_t QUEUE_QUOTA = 64;

        const std::vector<std::unique_ptr<SPSCQueue>>& queues;
        size_t next_queue = 0;
        size_t queue_records = 0;

      public:
        explicit QueueReader(
          const std::vector<std::unique_ptr<SPSCQueue>>& queues) :
          queues(queues)
        {}

        std::unique_ptr<std::vector<uint8_t>> next()
        {
          for (size_t q = 0; q < queues.size(); ++q)
          {
            if (queue_records == QUEUE_QUOTA)
            {
              next_queue = (next_queue + 1) % queues.size();
              queue_records = 0;
            }
            auto record = queues[next_queue]->pop();
            if (record)
            {
              ++queue_records;
              return record;
            }
            next_queue = (next_queue + 1) % queues.size();
            queue_records = 0;
          }
          return nullptr;
        }
      };

      const std::vector<std::string> tag_prefix_allow_list;
      sockaddr_storage address = {};
      socklen_t address_size = 0;
      Endpoint::Delivery delivery;
      std::vector<std::unique_ptr<SPSCQueue>> queues;
      std::atomic<uint64_t> dropped = 0;
      ccf::ds::Mutex mutex;
      // Producers observe shutdown without taking the transport mutex.
      std::atomic<bool> stopping = false;
      bool connected CCF_GUARDED_BY(mutex) = false;
      std::chrono::steady_clock::time_point deadline CCF_GUARDED_BY(mutex);
      std::chrono::steady_clock::time_point retry_after CCF_GUARDED_BY(mutex);
      uint64_t reported = 0;
      int fd CCF_GUARDED_BY(mutex) = -1;
      std::unique_ptr<std::vector<uint8_t>> pending CCF_GUARDED_BY(mutex);
      size_t write_offset CCF_GUARDED_BY(mutex) = 0;
      QueueReader reader CCF_GUARDED_BY(mutex);
      bool finished CCF_GUARDED_BY(mutex) = false;

      Transport(const Endpoint& endpoint, size_t producers) :
        tag_prefix_allow_list(endpoint.tag_prefix_allow_list),
        delivery(endpoint.delivery),
        reader(queues)
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
      }

      [[nodiscard]] bool accepts(std::string_view tag) const
      {
        return std::any_of(
          tag_prefix_allow_list.begin(),
          tag_prefix_allow_list.end(),
          [tag](const auto& prefix) { return tag.starts_with(prefix); });
      }

      [[nodiscard]] bool expired() const CCF_REQUIRES(mutex)
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

      void disconnect() CCF_REQUIRES(mutex)
      {
        connected = false;
        write_offset = 0;
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

      void connect() CCF_REQUIRES(mutex)
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

      struct SendResult
      {
        bool progress = false;
        bool blocked = false;
      };

      SendResult send_turn() CCF_REQUIRES(mutex)
      {
        SendResult result{.blocked = !connected};
        // Bound syscalls as well as messages so a busy sink cannot monopolise
        // the shared worker, including when writes are short or interrupted.
        for (size_t i = 0; i < TURN_BUDGET && connected && !expired(); ++i)
        {
          if (!pending)
          {
            pending = reader.next();
            if (!pending)
            {
              break;
            }
            result.progress = true;
          }
          if (write_offset == pending->size())
          {
            pending.reset();
            continue;
          }
          const auto sent = ::send(
            fd,
            pending->data() + write_offset,
            pending->size() - write_offset,
            MSG_NOSIGNAL | MSG_DONTWAIT);
          if (sent > 0)
          {
            result.progress = true;
            write_offset += static_cast<size_t>(sent);
            if (write_offset == pending->size())
            {
              pending.reset();
              write_offset = 0;
            }
            continue;
          }
          if (sent < 0 && errno == EINTR)
          {
            continue;
          }
          if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
          {
            result.blocked = true;
            break;
          }
          disconnect();
          result.blocked = true;
          break;
        }
        return result;
      }

      bool discard_queued() CCF_REQUIRES(mutex)
      {
        size_t discarded = 0;
        for (const auto& queue : queues)
        {
          const auto count = queue->size();
          for (size_t i = 0; i < count; ++i)
          {
            std::ignore = queue->pop();
          }
          discarded += count;
        }
        dropped.fetch_add(discarded, std::memory_order_relaxed);
        return discarded != 0;
      }

      void finish_if_done() CCF_REQUIRES(mutex)
      {
        if (!stopping.load(std::memory_order_relaxed))
        {
          return;
        }
        size_t remaining = pending ? 1 : 0;
        for (const auto& queue : queues)
        {
          remaining += queue->size();
        }
        if (expired() || remaining == 0)
        {
          dropped.fetch_add(remaining, std::memory_order_relaxed);
          pending.reset();
          disconnect();
          finished = true;
        }
      }

      bool step() CCF_REQUIRES(mutex)
      {
        if (finished)
        {
          return false;
        }
        bool progress = false;
        if (!expired())
        {
          connect();
          const auto sent = send_turn();
          progress = sent.progress;
          if (
            delivery == Endpoint::Delivery::UNBUFFERED_NON_BLOCKING &&
            sent.blocked)
          {
            progress |= discard_queued();
          }
        }
        finish_if_done();
        return progress;
      }

      void stop(std::chrono::steady_clock::time_point shutdown_deadline)
      {
        ccf::ds::MutexGuard lock(mutex);
        if (!stopping.load(std::memory_order_relaxed))
        {
          deadline = shutdown_deadline;
          stopping.store(true, std::memory_order_relaxed);
        }
      }

      ~Transport()
      {
        ccf::ds::MutexGuard lock(mutex);
        disconnect();
      }
    };

    struct Worker
    {
      std::vector<std::unique_ptr<Transport>> transports;
      std::thread consumer;

      explicit Worker(std::vector<std::unique_ptr<Transport>> instances) :
        transports(std::move(instances)),
        consumer([this] { run(); })
      {}

      void run()
      {
        while (true)
        {
          bool progress = false;
          bool finished = true;
          for (const auto& t : transports)
          {
            {
              ccf::ds::MutexGuard lock(t->mutex);
              progress |= t->step();
              finished &= t->finished;
            }
            t->report_drops();
          }
          if (finished)
          {
            break;
          }
          if (!progress)
          {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
        }
      }

      void shutdown()
      {
        if (consumer.joinable())
        {
          const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(2);
          for (const auto& t : transports)
          {
            t->stop(deadline);
          }
          consumer.join();
          for (const auto& t : transports)
          {
            LOG_INFO_FMT(
              "Fluentd exporter shutdown: {} dropped events",
              t->dropped.load());
          }
        }
      }

      ~Worker()
      {
        shutdown();
      }
    };

    static std::unique_ptr<Worker>& worker()
    {
      static std::unique_ptr<Worker> instance;
      return instance;
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
      if (!instances.empty())
      {
        worker() = std::make_unique<Worker>(std::move(instances));
      }
    }

    static void configure(
      std::optional<Endpoint> endpoint, size_t producers = 1)
    {
      configure(
        endpoint ? std::vector{*endpoint} : std::vector<Endpoint>{}, producers);
    }

    static bool is_configured()
    {
      return worker() != nullptr;
    }

    static bool is_producer_active()
    {
      return is_configured() &&
        bound_slot() < worker()->transports.front()->queues.size() &&
        !worker()->transports.front()->stopping.load(std::memory_order_relaxed);
    }

    static bool accepts(std::string_view tag)
    {
      if (!is_configured())
      {
        return false;
      }
      for (const auto& t : worker()->transports)
      {
        if (t->accepts(tag))
        {
          return true;
        }
      }
      return false;
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
        for (const auto& t : worker()->transports)
        {
          ccf::ds::MutexGuard lock(t->mutex);
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
        std::ignore = worker()->transports.front()->queues.at(slot);
        bound_slot() = slot;
      }
    }

    // False may mean partial acceptance: other sinks still receive the record.
    static bool enqueue(std::string_view tag, std::span<const uint8_t> bytes)
    {
      if (!is_configured())
      {
        return false;
      }
      bool enqueued = true;
      const auto slot = bound_slot();
      for (const auto& t : worker()->transports)
      {
        if (!t->accepts(tag))
        {
          continue;
        }
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

    static void record_drop(std::string_view tag)
    {
      if (!is_configured())
      {
        return;
      }
      for (const auto& t : worker()->transports)
      {
        if (t->accepts(tag))
        {
          t->dropped.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }

    static uint64_t dropped_count()
    {
      if (!is_configured())
      {
        return 0;
      }
      uint64_t total = 0;
      for (const auto& t : worker()->transports)
      {
        total += t->dropped.load();
      }
      return total;
    }

    // Producers must stop enqueueing before shutdown begins.
    static void shutdown()
    {
      if (is_configured())
      {
        worker()->shutdown();
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
