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
  // Configure before producers start; stop producers before shutdown.
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
      // Set while the consumer sleeps and this transport can drain, so
      // producers must wake it. Like io_uring's IORING_SQ_NEED_WAKEUP.
      std::atomic<bool> needs_wakeup = false;
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
        // Unbound producers share one queue, serialised before enqueueing.
        queues.push_back(std::make_unique<SPSCQueue>(size));
      }

      [[nodiscard]] bool accepts(std::string_view tag) const
      {
        return std::any_of(
          tag_prefix_allow_list.begin(),
          tag_prefix_allow_list.end(),
          [tag](const auto& prefix) { return tag.starts_with(prefix); });
      }

      // The next step would send a new record or, when unbuffered, discard
      // it. Must be false whenever queued records would stay queued, or the
      // consumer would spin.
      [[nodiscard]] bool can_drain() const CCF_REQUIRES(mutex)
      {
        return !stopping.load(std::memory_order_relaxed) &&
          ((connected && !pending) ||
           delivery == Endpoint::Delivery::UNBUFFERED_NON_BLOCKING);
      }

      // Waiting to connect, for a blocked send, or to finish shutting down.
      // Nothing signals when these can progress, so the consumer polls them.
      [[nodiscard]] bool needs_polling() const CCF_REQUIRES(mutex)
      {
        return !finished &&
          (!connected || pending || stopping.load(std::memory_order_relaxed));
      }

      [[nodiscard]] bool has_queued_records() const
      {
        return std::any_of(queues.begin(), queues.end(), [](const auto& queue) {
          return queue->size() != 0;
        });
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

    // The consumer sleeps like io_uring's SQPOLL thread: when out of work, it
    // sets needs_wakeup on each transport that can drain, rechecks their
    // queues, then sleeps. Producers check needs_wakeup after pushing, so they
    // only pay for a wake-up when the consumer sleeps. Unlike SQPOLL, the
    // consumer sleeps rather than spins through its idle period (LINGER), and
    // its sleep times out to poll stalled transports and report drops.
    struct Worker
    {
      // Longest wait between passes, which bounds how long drop reports can be
      // delayed.
      static constexpr auto MAX_IDLE_WAIT = std::chrono::milliseconds(100);
      // An idle consumer checks once more after this delay before blocking, so
      // records closer together than this never make producers wake it.
      static constexpr auto LINGER = std::chrono::milliseconds(1);
      // Polls wait 2 ms, doubling to at most 2^6 = 64 ms.
      static constexpr size_t MAX_POLL_BACKOFF_SHIFT = 6;

      std::vector<std::unique_ptr<Transport>> transports;
      ccf::ds::Mutex unbound_producer_mutex;
      ccf::ds::Mutex wake_mutex;
      ccf::ds::ConditionVariable wake_condition;
      bool wake_pending CCF_GUARDED_BY(wake_mutex) = false;
      std::thread consumer;

      explicit Worker(std::vector<std::unique_ptr<Transport>> instances) :
        transports(std::move(instances)),
        consumer([this] { run(); })
      {}

      void run()
      {
        size_t idle_passes = 0;
        while (true)
        {
          bool progress = false;
          bool finished = true;
          bool poll = false;
          for (const auto& t : transports)
          {
            {
              ccf::ds::MutexGuard lock(t->mutex);
              progress |= t->step();
              finished &= t->finished;
              poll |= t->needs_polling();
            }
            t->report_drops();
          }
          if (finished)
          {
            break;
          }
          if (progress)
          {
            idle_passes = 0;
            continue;
          }
          ++idle_passes;
          if (idle_passes == 1)
          {
            wait(LINGER, false);
            continue;
          }
          const auto poll_wait = std::chrono::milliseconds(
            int64_t{1} << std::min(idle_passes - 1, MAX_POLL_BACKOFF_SHIFT));
          wait(poll ? poll_wait : MAX_IDLE_WAIT, true);
        }
      }

      // Returns on timeout, on wake(), or, if wake_on_records, when a producer
      // pushes a record that a transport can drain.
      void wait(std::chrono::milliseconds timeout, bool wake_on_records)
      {
        bool queued = false;
        if (wake_on_records)
        {
          for (const auto& t : transports)
          {
            {
              ccf::ds::MutexGuard lock(t->mutex);
              if (!t->can_drain())
              {
                continue;
              }
            }
            t->needs_wakeup.store(true, std::memory_order_relaxed);
            // Pairs with the fence in enqueue_at_slot(): either the producer
            // observes needs_wakeup, or this observes the producer's record.
            std::atomic_thread_fence(std::memory_order_seq_cst);
            if (t->has_queued_records())
            {
              queued = true;
              break;
            }
          }
        }
        {
          ccf::ds::MutexGuard lock(wake_mutex);
          if (!queued)
          {
            wake_condition.wait_for(
              lock, timeout, [this]() CCF_REQUIRES(wake_mutex) {
                return wake_pending;
              });
          }
          wake_pending = false;
        }
        for (const auto& t : transports)
        {
          t->needs_wakeup.store(false, std::memory_order_relaxed);
        }
      }

      void wake()
      {
        {
          ccf::ds::MutexGuard lock(wake_mutex);
          wake_pending = true;
        }
        wake_condition.notify_one();
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
          wake();
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

    static bool is_running()
    {
      return is_configured() &&
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
        if (slot >= worker()->transports.front()->queues.size() - 1)
        {
          throw std::out_of_range("Trace producer slot out of range");
        }
        bound_slot() = slot;
      }
    }

  private:
    static bool enqueue_at_slot(
      std::string_view tag, std::span<const uint8_t> bytes, size_t slot)
    {
      bool enqueued = true;
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
          continue;
        }
        // Pairs with the fence in Worker::wait().
        std::atomic_thread_fence(std::memory_order_seq_cst);
        if (t->needs_wakeup.load(std::memory_order_relaxed))
        {
          worker()->wake();
        }
      }
      return enqueued;
    }

  public:
    // False may mean partial acceptance: other sinks still receive the record.
    static bool enqueue(std::string_view tag, std::span<const uint8_t> bytes)
    {
      if (!is_configured())
      {
        return false;
      }
      const auto slot = bound_slot();
      if (slot == std::numeric_limits<size_t>::max())
      {
        ccf::ds::MutexGuard lock(worker()->unbound_producer_mutex);
        return enqueue_at_slot(
          tag, bytes, worker()->transports.front()->queues.size() - 1);
      }
      return enqueue_at_slot(tag, bytes, slot);
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
