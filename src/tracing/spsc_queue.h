// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ccf::tracing
{
  // One producer and one consumer. Stop both before destruction.
  class SPSCQueue
  {
    using Record = std::vector<uint8_t>;
    static constexpr size_t CACHE_LINE_SIZE = 64;

    std::vector<std::unique_ptr<Record>> slots;
    const uint64_t max_bytes;

    // Written by the consumer only. popped_bytes is a monotonic total, so a
    // stale read by the producer only overestimates the queued bytes.
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> head = 0;
    std::atomic<uint64_t> popped_bytes = 0;
    // Separate indices also support non-power-of-two capacities when counters
    // wrap around.
    size_t read_index = 0;

    // Written by the producer only. The producer works from its last view of
    // the consumer's counters, and reads the consumer's cache line again only
    // when that view says the queue is full.
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> tail = 0;
    size_t write_index = 0;
    uint64_t pushed_bytes = 0;
    size_t cached_head = 0;
    uint64_t cached_popped_bytes = 0;

    static_assert(std::atomic<size_t>::is_always_lock_free);
    static_assert(std::atomic<uint64_t>::is_always_lock_free);

    [[nodiscard]] bool is_full(size_t end) const
    {
      // Unsigned differences stay correct when the totals wrap around.
      return end - cached_head >= slots.size() ||
        pushed_bytes - cached_popped_bytes >= max_bytes;
    }

  public:
    static constexpr size_t MAX_RECORD_SIZE = size_t{1024} * 1024;
    static constexpr uint64_t UNLIMITED_BYTES =
      std::numeric_limits<uint64_t>::max();

    // A record is admitted while fewer than max_bytes are queued, so the
    // queue holds less than max_bytes + MAX_RECORD_SIZE payload bytes.
    explicit SPSCQueue(
      size_t capacity = 4096, uint64_t max_bytes = UNLIMITED_BYTES) :
      max_bytes(max_bytes)
    {
      if (capacity == 0 || max_bytes == 0)
      {
        throw std::invalid_argument(
          "Trace queue capacity must be greater than zero");
      }
      slots.resize(capacity);
    }

    bool push(std::span<const uint8_t> bytes)
    {
      const auto end = tail.load(std::memory_order_relaxed);
      if (bytes.size() > MAX_RECORD_SIZE)
      {
        return false;
      }
      if (is_full(end))
      {
        // Acquire: the consumer has emptied every slot before this head.
        cached_head = head.load(std::memory_order_acquire);
        cached_popped_bytes = popped_bytes.load(std::memory_order_relaxed);
        if (is_full(end))
        {
          return false;
        }
      }
      try
      {
        slots[write_index] =
          std::make_unique<Record>(bytes.begin(), bytes.end());
      }
      catch (const std::bad_alloc&)
      {
        return false;
      }
      write_index = (write_index + 1) % slots.size();
      tail.store(end + 1, std::memory_order_release);
      pushed_bytes += bytes.size();
      return true;
    }

    // Consumer-only observation; exact once the producer has stopped.
    // Counts queued records only, not records already popped by the consumer.
    [[nodiscard]] size_t size() const
    {
      return tail.load(std::memory_order_acquire) -
        head.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::unique_ptr<Record> pop()
    {
      const auto begin = head.load(std::memory_order_relaxed);
      if (begin == tail.load(std::memory_order_acquire))
      {
        return nullptr;
      }
      auto record = std::move(slots[read_index]);
      read_index = (read_index + 1) % slots.size();
      // Single writer, so no atomic read-modify-write is needed.
      popped_bytes.store(
        popped_bytes.load(std::memory_order_relaxed) + record->size(),
        std::memory_order_relaxed);
      head.store(begin + 1, std::memory_order_release);
      return record;
    }
  };
}
