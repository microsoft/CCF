// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Task-local instrumentation. Signals gate collection to the warm workload;
// no request contents or cryptographic material are recorded.

#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <unistd.h>

namespace ccf::queue_probe
{
  enum Stage
  {
    RX_QUEUE,
    RX_WORK,
    COMMIT_WAIT,
    SEND_QUEUE,
    SEND_WORK,
    TLS_RX_QUEUE,
    TLS_TX_QUEUE,
    TLS_WORK,
    OUT_LOOP_WAIT,
    COMPLETION_LOOP_WAIT,
    LOOP_DRAIN_WORK,
    COUNT
  };

  inline constexpr const char* NAMES[COUNT] = {
    "rx_queue",
    "rx_work",
    "commit_wait",
    "send_queue",
    "send_work",
    "tls_rx_queue",
    "tls_tx_queue",
    "tls_work",
    "out_loop_wait",
    "completion_loop_wait",
    "loop_drain_work"};

  using Clock = std::chrono::steady_clock;
  using Stamp = Clock::time_point;
  inline std::atomic<bool> enabled{false};
  static_assert(std::atomic<bool>::is_always_lock_free);
  static_assert(std::atomic<uint64_t>::is_always_lock_free);

  struct Histogram
  {
    std::atomic<uint64_t> count{0};
    std::atomic<uint64_t> total_ns{0};
    std::atomic<uint64_t> max_ns{0};
    std::array<std::atomic<uint64_t>, 64> bins{};
  };

  inline std::array<Histogram, COUNT> histograms;
  inline std::atomic<uint64_t> errors{0};

  inline void ensure_reporter();

  inline Stamp stamp()
  {
    ensure_reporter();
    return enabled.load(std::memory_order_relaxed) ? Clock::now() : Stamp{};
  }

  inline void record(Stage stage, Stamp start)
  {
    if (start == Stamp{} || !enabled.load(std::memory_order_relaxed))
    {
      return;
    }
    const auto elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start)
        .count();
    if (elapsed < 0)
    {
      errors.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    const auto ns = static_cast<uint64_t>(elapsed);
    auto& histogram = histograms[stage];
    histogram.count.fetch_add(1, std::memory_order_relaxed);
    histogram.total_ns.fetch_add(ns, std::memory_order_relaxed);
    size_t bucket = std::bit_width(ns);
    if (bucket >= histogram.bins.size())
    {
      bucket = histogram.bins.size() - 1;
    }
    histogram.bins[bucket].fetch_add(1, std::memory_order_relaxed);
    auto previous = histogram.max_ns.load(std::memory_order_relaxed);
    while (previous < ns &&
           !histogram.max_ns.compare_exchange_weak(
             previous, ns, std::memory_order_relaxed))
    {
    }
  }

  struct Scope
  {
    Stage stage;
    Stamp start = stamp();
    explicit Scope(Stage stage_) : stage(stage_) {}
    ~Scope()
    {
      record(stage, start);
    }
  };

  inline void enable_handler(int)
  {
    enabled.store(true, std::memory_order_relaxed);
  }

  inline void disable_handler(int)
  {
    enabled.store(false, std::memory_order_relaxed);
  }

  struct Reporter
  {
    const char* prefix = std::getenv("CCF_QUEUE_PROBE_OUT");

    Reporter()
    {
      if (prefix == nullptr)
      {
        return;
      }
      struct sigaction action
      {};
      sigemptyset(&action.sa_mask);
      action.sa_flags = SA_RESTART;
      action.sa_handler = enable_handler;
      if (sigaction(SIGRTMIN + 6, &action, nullptr) != 0)
      {
        std::perror("queue probe enable signal");
        std::abort();
      }
      action.sa_handler = disable_handler;
      if (sigaction(SIGRTMIN + 7, &action, nullptr) != 0)
      {
        std::perror("queue probe disable signal");
        std::abort();
      }
    }

    ~Reporter()
    {
      if (prefix == nullptr)
      {
        return;
      }
      enabled.store(false, std::memory_order_relaxed);
      char path[4096];
      const auto length =
        std::snprintf(path, sizeof(path), "%s.%d.json", prefix, getpid());
      if (length < 0 || static_cast<size_t>(length) >= sizeof(path))
      {
        std::fprintf(stderr, "queue probe output path is too long\n");
        return;
      }
      FILE* file = std::fopen(path, "w");
      if (file == nullptr)
      {
        std::perror("queue probe output");
        return;
      }
      std::fprintf(
        file,
        "{\"errors\":%llu,\"stages\":{",
        static_cast<unsigned long long>(errors.load()));
      for (size_t stage = 0; stage < COUNT; ++stage)
      {
        const auto& h = histograms[stage];
        std::fprintf(
          file,
          "%s\"%s\":{\"count\":%llu,\"total_ns\":%llu,\"max_ns\":%llu,\"bins\":"
          "[",
          stage == 0 ? "" : ",",
          NAMES[stage],
          static_cast<unsigned long long>(h.count.load()),
          static_cast<unsigned long long>(h.total_ns.load()),
          static_cast<unsigned long long>(h.max_ns.load()));
        for (size_t bucket = 0; bucket < h.bins.size(); ++bucket)
        {
          std::fprintf(
            file,
            "%s%llu",
            bucket == 0 ? "" : ",",
            static_cast<unsigned long long>(h.bins[bucket].load()));
        }
        std::fprintf(file, "]}");
      }
      std::fprintf(file, "}}\n");
      if (std::fclose(file) != 0)
      {
        std::perror("queue probe close");
      }
    }
  };

  inline void ensure_reporter()
  {
    static Reporter reporter;
    (void)reporter;
  }
}
