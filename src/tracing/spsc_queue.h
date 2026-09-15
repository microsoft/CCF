// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

namespace ccf::tracing
{
  // One producer and one consumer. Stop both before destruction.
  class SPSCQueue
  {
    using Record = std::vector<uint8_t>;
    std::vector<std::unique_ptr<Record>> slots;
    std::atomic<size_t> head = 0;
    std::atomic<size_t> tail = 0;
    // Separate indices also support non-power-of-two capacities when counters
    // wrap around.
    size_t read_index = 0;
    size_t write_index = 0;

    static_assert(std::atomic<size_t>::is_always_lock_free);

  public:
    static constexpr size_t MAX_CAPACITY = 1024 * 1024;
    static constexpr size_t MAX_RECORD_SIZE = 1024 * 1024;

    explicit SPSCQueue(size_t capacity = 4096)
    {
      if (capacity == 0 || capacity > MAX_CAPACITY)
      {
        throw std::invalid_argument(
          "Trace queue capacity must be between 1 and 1048576 slots");
      }
      slots.resize(capacity);
    }

    bool push(std::span<const uint8_t> bytes)
    {
      const auto end = tail.load(std::memory_order_relaxed);
      if (
        bytes.size() > MAX_RECORD_SIZE ||
        end - head.load(std::memory_order_acquire) >= slots.size())
      {
        return false;
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
      return true;
    }

    template <typename F>
    size_t read(size_t limit, F&& callback)
    {
      size_t count = 0;
      while (count < limit)
      {
        const auto begin = head.load(std::memory_order_relaxed);
        if (begin == tail.load(std::memory_order_acquire))
        {
          break;
        }
        auto& record = slots[read_index];
        callback(std::span<const uint8_t>(*record));
        record.reset();
        read_index = (read_index + 1) % slots.size();
        head.store(begin + 1, std::memory_order_release);
        ++count;
      }
      return count;
    }
  };
}
