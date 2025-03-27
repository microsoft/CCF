// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "../work_beacon.h"

#include "ccf/ds/logger.h"

#include <doctest/doctest.h>
#include <functional>
#include <iostream>
#include <optional>
#include <queue>
#include <thread>

using WorkItem = std::function<bool()>;

struct WorkQueue
{
  std::mutex mutex;
  std::queue<WorkItem> work;

  void add_work(WorkItem&& item)
  {
    std::unique_lock<std::mutex> lock(mutex);
    work.push(std::move(item));
  }

  std::optional<WorkItem> get_work()
  {
    std::unique_lock<std::mutex> lock(mutex);

    std::optional<WorkItem> result = std::nullopt;
    if (!work.empty())
    {
      result = work.front();
      work.pop();
    }

    return result;
  }
};

// Do nothing, so that callers simply spin-loop
struct NopBeacon
{
  void wait_for_work() {}
  void notify_work_available() {}
};

// Simulate what should generally be done in production. Always wait with a
// timeout, rather than indefinitely, to handle senders who forget/fail to
// notify.
struct WaitBeacon
{
  ccf::ds::WorkBeacon internal;

  void wait_for_work()
  {
    internal.wait_for_work_with_timeout(std::chrono::milliseconds(100));
  }

  void notify_work_available()
  {
    // Sometimes, just forget to notify the receivers
    if (rand() % 4 != 0)
    {
      internal.notify_work_available();
    }
    else
    {
      // Instead, waste so much time that the receivers wake up
      std::this_thread::sleep_for(std::chrono::milliseconds(110));
    }
  }
};

// Run a simple task simulation, with some sender and receiver threads passing
// work items around. Return how often the receivers checked the work queue and
// found it empty.
template <typename TBeacon>
size_t run_jobs(size_t n_senders, size_t n_receivers)
{
  std::vector<std::thread> senders;
  std::vector<std::thread> receivers;

  WorkQueue work_queue;
  TBeacon beacon;

  std::atomic<size_t> workless_wakes = 0;

  for (auto i = 0; i < n_senders; ++i)
  {
    senders.push_back(std::thread(
      [&](size_t sender_idx) {
        for (auto x = 0; x < 10; ++x)
        {
          work_queue.add_work([=]() {
            std::this_thread::sleep_for(std::chrono::nanoseconds(x * x));
            return false;
          });
          beacon.notify_work_available();
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        // Add tasks that tells the receiving worker to terminate. Each sender
        // is responsible for sending some fraction of terminate tasks, such
        // that each receiver receives exactly one.
        size_t quota = n_receivers / n_senders;
        if (sender_idx == 0)
        {
          quota += n_receivers % n_senders;
        }
        for (auto j = 0; j < quota; ++j)
        {
          work_queue.add_work([&]() { return true; });
          beacon.notify_work_available();
        }
      },
      i));
  }

  for (auto i = 0; i < n_receivers; ++i)
  {
    receivers.push_back(std::thread([&]() {
      while (true)
      {
        beacon.wait_for_work();

        auto task = work_queue.get_work();
        if (!task.has_value())
        {
          ++workless_wakes;
        }
        else
        {
          const auto task_ret = task.value()();
          if (task_ret == true)
          {
            return;
          }
        }
      }
    }));
  }

  for (auto& sender : senders)
  {
    sender.join();
  }

  for (auto& receiver : receivers)
  {
    receiver.join();
  }

  return workless_wakes;
}

TEST_CASE("WorkBeacon" * doctest::test_suite("workbeacon"))
{
  std::vector<size_t> test_vals{1, 5};
  for (auto n_senders : test_vals)
  {
    for (auto n_receivers : test_vals)
    {
      {
        LOG_INFO_FMT(
          "Testing {} senders and {} receivers", n_senders, n_receivers);
        // Allow test to be repeated multiple times locally to improve
        // confidence in the given bounds
        static constexpr auto n_repeats = 1;
        for (size_t i = 0; i < n_repeats; ++i)
        {
          const auto wakes_with_spinloop =
            run_jobs<NopBeacon>(n_senders, n_receivers);
          const auto wakes_with_waits =
            run_jobs<WaitBeacon>(n_senders, n_receivers);
          const auto wakes_with_beacon =
            run_jobs<ccf::ds::WorkBeacon>(n_senders, n_receivers);

          LOG_INFO_FMT(
            "  {} vs {} vs {}",
            wakes_with_beacon,
            wakes_with_waits,
            wakes_with_spinloop);

          // Spin loop should have hundreds of thousands of idle wake-ups.
          // Beacon should have 0 idle wake-ups.
          // Beacon with timer should have a handful of idle wake-ups, roughly
          // proportional to the ratio of receivers / senders, and the total
          // test run-time, and the various ad-hoc random parameters in this
          // test. But crucially, drastically fewer than the spin-loop

          // First assert the order
          REQUIRE(wakes_with_beacon == 0);
          REQUIRE(wakes_with_beacon <= wakes_with_waits);

          // In occasional runs on some build configurations, we see 0 wakes
          // when using the spinloop. This is surprising, but not impossible. In
          // this instance we obviously don't see any improvement in the waiting
          // scheme, so skip the following assertions
          if (wakes_with_spinloop > 0)
          {
            REQUIRE(wakes_with_waits < wakes_with_spinloop);

            // Then try to be a little more precise, allowing head-room for
            // different build configs and cosmic rays
            REQUIRE(wakes_with_waits * 10 < wakes_with_spinloop);
          }
        }
      }
    }
  }
}
