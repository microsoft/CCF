// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <doctest/doctest.h>
#define FMT_HEADER_ONLY
#include <deque>
#include <fmt/format.h>
#include <functional>
#include <random>
#include <set>
#include <thread>

template <typename T>
class FunQueue
{
protected:
  std::mutex mutex;
  std::deque<T> queue;
  bool active;

public:
  bool push(T&& t)
  {
    std::lock_guard<std::mutex> lock(mutex);
    const bool ret = queue.empty() && !active;
    queue.emplace_back(std::forward<T>(t));
    return ret;
  }

  using Visitor = std::function<void(T&&)>;
  bool pop_and_visit(Visitor&& visitor)
  {
    std::deque<T> local;
    {
      std::lock_guard<std::mutex> lock(mutex);
      // assert(!active);
      active = true;

      std::swap(local, queue);
    }

    for (auto&& entry : local)
    {
      visitor(std::forward<T>(entry));
    }

    {
      std::lock_guard<std::mutex> lock(mutex);
      // assert(active);
      active = false;

      return !queue.empty();
    }
  }
};

TEST_CASE("FunQueue")
{
  FunQueue<size_t> fq;

  // push returns true iff queue was previously empty and inactive
  REQUIRE(fq.push(1));
  REQUIRE_FALSE(fq.push(2));
  REQUIRE_FALSE(fq.push(3));
  REQUIRE_FALSE(fq.push(4));

  // pop returns true iff queue is non-empty when it completes
  REQUIRE_FALSE(fq.pop_and_visit([](size_t&& n) { fmt::print("{}\n", n); }));

  // Visits an empty queue, leaves an empty queue
  REQUIRE_FALSE(fq.pop_and_visit([](size_t&& n) { fmt::print("{}\n", n); }));

  // Not the first push, but the first on an empty queue, so gets a true
  // response
  REQUIRE(fq.push(5));

  // If the visitor (or anything concurrent with it) pushes a new element, then
  // the pop returns true to indicate that queue is now non-empty
  REQUIRE(fq.pop_and_visit([&](size_t&& n) {
    fmt::print("{}\n", n);

    // While popping/visiting, the queue is active
    REQUIRE_FALSE(fq.push(6));
  }));

  REQUIRE(fq.pop_and_visit([&](size_t&& n) {
    fmt::print("{}\n", n);
    REQUIRE_FALSE(fq.push(7));
    REQUIRE_FALSE(fq.push(8));
    REQUIRE_FALSE(fq.push(9));
  }));

  REQUIRE_FALSE(fq.pop_and_visit([&](size_t&& n) { fmt::print("{}\n", n); }));
}