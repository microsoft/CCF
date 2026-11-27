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
  // Cache-line padding separates consumer and producer state.
  class SPSCQueue // NOLINT(clang-analyzer-optin.performance.Padding)
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
    static constexpr uint64_t UNLIMITED_BYTES =
      std::numeric_limits<uint64_t>::max();

    // The record count is a hard limit. The byte limit is soft across records
    // and caps each record: a record up to max_bytes is admitted while fewer
    // than max_bytes are queued, and charged once enqueued, so a queue stays
    // under 2 * max_bytes while letting a producer test for space before sizing
    // a record.
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

    // Producer-only. Once true, it stays true until this producer pushes: the
    // consumer only frees space.
    [[nodiscard]] bool has_space()
    {
      const auto end = tail.load(std::memory_order_relaxed);
      if (is_full(end))
      {
        // Acquire: the consumer has emptied every slot before this head.
        cached_head = head.load(std::memory_order_acquire);
        cached_popped_bytes = popped_bytes.load(std::memory_order_relaxed);
        return !is_full(end);
      }
      return true;
    }

    // Throws std::bad_alloc, leaving the queue unchanged, if the record
    // cannot be allocated.
    bool push(std::span<const uint8_t> bytes)
    {
      if (bytes.size() > max_bytes || !has_space())
      {
        return false;
      }
      slots[write_index] = std::make_unique<Record>(bytes.begin(), bytes.end());
      write_index = (write_index + 1) % slots.size();
      tail.store(
        tail.load(std::memory_order_relaxed) + 1, std::memory_order_release);
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
